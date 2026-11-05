package com.adshield.pro.engine.storage

import com.adshield.pro.domain.model.CloudObject
import okhttp3.Credentials
import okhttp3.FormBody
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okio.BufferedSink
import okio.source
import org.w3c.dom.Element
import java.io.InputStream
import java.io.OutputStream
import java.net.URI
import java.net.URLDecoder
import java.security.MessageDigest
import java.time.Instant
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.TimeUnit
import javax.xml.parsers.DocumentBuilderFactory

object WebDavPath {
    fun normalize(raw: String): String {
        val value = raw.trim().trim('/')
        if (value.isEmpty()) return ""
        require(!value.contains('\\') && !value.any { it.isISOControl() }) { "Invalid storage path" }
        val segments = value.split('/')
        require(segments.all { it.isNotBlank() && it != "." && it != ".." }) { "Path traversal is not allowed" }
        require(value.length <= 4096) { "Storage path is too long" }
        return segments.joinToString("/")
    }

    fun child(parent: String, name: String): String {
        val child = normalize(name)
        require(!child.contains('/')) { "A name cannot contain a path separator" }
        val base = normalize(parent)
        return if (base.isEmpty()) child else "$base/$child"
    }

    fun parent(path: String): String = normalize(path).substringBeforeLast('/', "")
}

data class WebDavQuota(
    val totalBytes: Long?,
    val availableBytes: Long?,
    val usedBytes: Long?
)

data class WebDavListing(
    val objects: List<CloudObject>,
    val quota: WebDavQuota
)

data class WebDavDownloadResult(
    val bytesWritten: Long,
    val sha256: String,
    val etag: String?
)

/** A real RFC 4918 client. It supports Nextcloud and generic HTTPS WebDAV endpoints. */
class WebDavClient(
    private val providerId: String,
    private val baseUrl: HttpUrl,
    private val username: String,
    private val password: String,
    private val isNextcloud: Boolean,
    private val client: OkHttpClient = defaultClient()
) {
    fun list(path: String = ""): WebDavListing {
        val normalized = WebDavPath.normalize(path)
        val url = urlFor(normalized, directory = true)
        val body = """
            <?xml version="1.0" encoding="utf-8" ?>
            <d:propfind xmlns:d="DAV:">
              <d:prop>
                <d:displayname/><d:getcontentlength/><d:getlastmodified/>
                <d:resourcetype/><d:getetag/>
                <d:quota-available-bytes/><d:quota-used-bytes/>
              </d:prop>
            </d:propfind>
        """.trimIndent()
        val response = execute(
            request(url, "PROPFIND")
                .header("Depth", "1")
                .method("PROPFIND", body.toRequestBody("application/xml; charset=utf-8"))
                .build()
        )
        response.use {
            val xml = it.body?.byteStream() ?: error("WebDAV returned an empty response")
            return WebDavXml.parseListing(xml, providerId, url)
        }
    }

    fun createFolder(parentPath: String, name: String) {
        val path = WebDavPath.child(parentPath, name)
        execute(request(urlFor(path, directory = true), "MKCOL").method("MKCOL", null).build()).close()
    }

    fun delete(path: String, isDirectory: Boolean) {
        val normalized = WebDavPath.normalize(path)
        require(normalized.isNotEmpty()) { "Refusing to delete the provider root" }
        execute(request(urlFor(normalized, isDirectory), "DELETE").delete().build()).close()
    }

    fun rename(path: String, isDirectory: Boolean, newName: String) {
        val normalized = WebDavPath.normalize(path)
        require(normalized.isNotEmpty()) { "Rename the provider root is not supported" }
        val destination = WebDavPath.child(WebDavPath.parent(normalized), newName)
        execute(
            request(urlFor(normalized, isDirectory), "MOVE")
                .header("Destination", urlFor(destination, isDirectory).toString())
                .header("Overwrite", "F")
                .method("MOVE", null)
                .build()
        ).close()
    }

    fun upload(
        parentPath: String,
        name: String,
        mimeType: String,
        contentLength: Long,
        input: InputStream,
        onProgress: (Long) -> Unit = {}
    ): String? {
        val path = WebDavPath.child(parentPath, name)
        val requestBody = object : RequestBody() {
            override fun contentType() = mimeType.toMediaType()
            override fun contentLength() = contentLength
            override fun writeTo(sink: BufferedSink) {
                input.use { stream ->
                    val source = stream.source()
                    val buffer = ByteArray(128 * 1024)
                    var written = 0L
                    while (true) {
                        val read = stream.read(buffer)
                        if (read < 0) break
                        sink.write(buffer, 0, read)
                        written += read
                        onProgress(written)
                    }
                    source.close()
                }
            }
        }
        val response = execute(request(urlFor(path), "PUT").put(requestBody).build())
        return response.use { it.header("ETag") }
    }

    fun download(
        path: String,
        output: OutputStream,
        onProgress: (Long) -> Unit = {}
    ): WebDavDownloadResult {
        val normalized = WebDavPath.normalize(path)
        require(normalized.isNotEmpty()) { "Choose a file, not the provider root" }
        val response = execute(request(urlFor(normalized), "GET").get().build())
        response.use {
            val source = it.body?.byteStream() ?: error("WebDAV returned an empty file response")
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(128 * 1024)
            var written = 0L
            source.use { input ->
                output.use { destination ->
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        destination.write(buffer, 0, read)
                        digest.update(buffer, 0, read)
                        written += read
                        onProgress(written)
                    }
                }
            }
            return WebDavDownloadResult(
                bytesWritten = written,
                sha256 = digest.digest().joinToString("") { byte -> "%02x".format(byte) },
                etag = it.header("ETag")
            )
        }
    }

    /** Creates a Nextcloud public link using OCS Share API v1; generic WebDAV has no standard share API. */
    fun createNextcloudPublicLink(path: String): String {
        require(isNextcloud) { "Public sharing requires the Nextcloud OCS API" }
        val normalized = WebDavPath.normalize(path)
        require(normalized.isNotEmpty()) { "Choose a file or folder to share" }
        val marker = "/remote.php/dav/files/"
        val rootText = baseUrl.toString().substringBefore(marker, "")
        require(rootText.isNotEmpty()) {
            "Use the full Nextcloud Files WebDAV URL: https://server/remote.php/dav/files/USERNAME/"
        }
        val shareEndpoint = rootText.trimEnd('/') + "/ocs/v2.php/apps/files_sharing/api/v1/shares"
        val form = FormBody.Builder()
            .add("shareType", "3")
            .add("path", "/$normalized")
            .build()
        val response = execute(
            request(shareEndpoint.toHttpUrl(), "OCS Share")
                .header("OCS-APIRequest", "true")
                .header("Accept", "application/xml")
                .post(form)
                .build()
        )
        response.use {
            val xml = it.body?.byteStream() ?: error("Nextcloud returned an empty share response")
            return WebDavXml.parseShareUrl(xml)
        }
    }

    private fun request(url: HttpUrl, operation: String): Request.Builder {
        val builder = Request.Builder().url(url).header("User-Agent", "OmniShieldX-Infinity/1.0")
        if (username.isNotEmpty() || password.isNotEmpty()) {
            builder.header("Authorization", Credentials.basic(username, password))
        }
        builder.header("X-OmniShield-Operation", operation)
        return builder
    }

    private fun execute(request: Request): Response {
        val response = client.newCall(request).execute()
        if (!response.isSuccessful && response.code != 207) {
            val code = response.code
            response.close()
            when (code) {
                401, 403 -> error("${operationMessage(request)} failed: authentication/permission denied (HTTP $code)")
                404 -> error("${operationMessage(request)} failed: remote path not found (HTTP 404)")
                409 -> error("${operationMessage(request)} failed: parent folder is missing or the path conflicts (HTTP 409)")
                507 -> error("${operationMessage(request)} failed: server storage is full (HTTP 507)")
                else -> error("${operationMessage(request)} failed with HTTP $code")
            }
        }
        return response
    }

    private fun operationMessage(request: Request): String = request.header("X-OmniShield-Operation") ?: "WebDAV request"

    private fun urlFor(path: String, directory: Boolean = false): HttpUrl {
        val normalized = WebDavPath.normalize(path)
        val builder = baseUrl.newBuilder().encodedPath(baseUrl.encodedPath.trimEnd('/') + "/")
        if (normalized.isNotEmpty()) normalized.split('/').forEach { builder.addPathSegment(it) }
        if (directory) builder.addPathSegment("")
        return builder.build()
    }

    companion object {
        fun endpoint(raw: String): HttpUrl {
            val value = raw.trim()
            require(value.startsWith("https://", ignoreCase = true)) {
                "HTTPS is required; cleartext credentials and files are refused"
            }
            val url = runCatching { value.toHttpUrl() }.getOrElse { error("Invalid WebDAV URL") }
            require(url.host.isNotBlank() && url.username.isEmpty() && url.password.isEmpty()) {
                "Use the username/password fields; credentials are not accepted in the URL"
            }
            require(url.query == null && url.fragment == null) { "The WebDAV root cannot contain a query or fragment" }
            return url
        }

        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(20, TimeUnit.SECONDS)
            .readTimeout(90, TimeUnit.SECONDS)
            .writeTimeout(90, TimeUnit.SECONDS)
            .followRedirects(true)
            .followSslRedirects(false) // Never follow an HTTPS-to-HTTP downgrade with credentials.
            .build()
    }
}

private fun String.toRequestBody(mediaType: String): RequestBody =
    RequestBody.create(mediaType.toMediaType(), this)

object WebDavXml {
    private val factory: DocumentBuilderFactory = DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = true
        runCatching { setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) }
        runCatching { setFeature("http://xml.org/sax/features/external-general-entities", false) }
        runCatching { setFeature("http://xml.org/sax/features/external-parameter-entities", false) }
        runCatching { setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "") }
        runCatching { setAttribute("http://javax.xml.XMLConstants/property/accessExternalSchema", "") }
    }

    @Synchronized
    private fun parse(input: InputStream) = factory.newDocumentBuilder().parse(input)

    fun parseListing(input: InputStream, providerId: String, requestUrl: HttpUrl): WebDavListing {
        val document = parse(input)
        val responses = document.getElementsByTagNameNS("DAV:", "response")
        val requestPath = requestUrl.encodedPath.trimEnd('/')
        val objects = ArrayList<CloudObject>()
        var available: Long? = null
        var used: Long? = null
        for (index in 0 until responses.length) {
            val response = responses.item(index) as Element
            val href = directChildText(response, "href") ?: continue
            val rawPath = runCatching { URI(href).rawPath }.getOrNull() ?: continue
            val decodedHref = URLDecoder.decode(rawPath, Charsets.UTF_8.name())
            if (decodedHref.trimEnd('/') == URLDecoder.decode(requestPath, Charsets.UTF_8.name()).trimEnd('/')) {
                available = textInDescendants(response, "quota-available-bytes")?.toLongOrNull()?.takeIf { it >= 0 } ?: available
                used = textInDescendants(response, "quota-used-bytes")?.toLongOrNull()?.takeIf { it >= 0 } ?: used
                continue
            }
            val basePath = URLDecoder.decode(requestPath, Charsets.UTF_8.name()).trimEnd('/') + "/"
            if (!decodedHref.startsWith(basePath)) continue
            val relative = decodedHref.removePrefix(basePath).trim('/')
            if (relative.isBlank() || relative.split('/').any { it == ".." }) continue
            val normalized = runCatching { WebDavPath.normalize(relative) }.getOrNull() ?: continue
            val isDirectory = descendants(response, "collection").any()
            val displayName = textInDescendants(response, "displayname")?.takeIf { it.isNotBlank() }
            objects += CloudObject(
                providerId = providerId,
                path = normalized,
                name = displayName ?: normalized.substringAfterLast('/'),
                isDirectory = isDirectory,
                sizeBytes = if (isDirectory) 0L else textInDescendants(response, "getcontentlength")?.toLongOrNull()?.coerceAtLeast(0L) ?: 0L,
                lastModifiedEpochMs = textInDescendants(response, "getlastmodified")?.let(::parseWebDavDate),
                etag = textInDescendants(response, "getetag")?.trim('"')
            )
        }
        if (available == null || used == null) {
            for (index in 0 until responses.length) {
                val response = responses.item(index) as Element
                available = available ?: textInDescendants(response, "quota-available-bytes")?.toLongOrNull()?.takeIf { it >= 0 }
                used = used ?: textInDescendants(response, "quota-used-bytes")?.toLongOrNull()?.takeIf { it >= 0 }
            }
        }
        return WebDavListing(
            objects = objects.sortedWith(compareByDescending<CloudObject> { it.isDirectory }.thenBy { it.name.lowercase() }),
            quota = WebDavQuota(
                totalBytes = if (available != null && used != null) available + used else null,
                availableBytes = available,
                usedBytes = used
            )
        )
    }

    fun parseShareUrl(input: InputStream): String {
        val document = parse(input)
        val nodes = document.getElementsByTagName("url")
        val value = if (nodes.length > 0) nodes.item(0).textContent.trim() else ""
        require(value.startsWith("https://")) { "Nextcloud did not return an HTTPS public share URL" }
        return value
    }

    private fun directChildText(element: Element, localName: String): String? {
        val children = element.childNodes
        for (index in 0 until children.length) {
            val child = children.item(index)
            if (child is Element && child.localName == localName) return child.textContent?.trim()
        }
        return null
    }

    private fun descendants(element: Element, localName: String): List<Element> {
        val result = ArrayList<Element>()
        fun visit(node: Element) {
            val children = node.childNodes
            for (index in 0 until children.length) {
                val child = children.item(index)
                if (child is Element) {
                    if (child.localName == localName) result += child
                    visit(child)
                }
            }
        }
        visit(element)
        return result
    }

    private fun textInDescendants(element: Element, localName: String): String? =
        descendants(element, localName).firstOrNull()?.textContent?.trim()

    private fun parseWebDavDate(value: String): Long? =
        runCatching { ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli() }
            .recoverCatching { Instant.parse(value).toEpochMilli() }
            .getOrNull()
}
