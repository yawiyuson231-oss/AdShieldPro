package com.adshield.pro.engine.security

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.content.ContentResolver
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import java.io.InputStream
import java.util.EnumMap

/**
 * On-device QR/barcode decoding.
 *
 * Why a local decoder: a QR code is a URL you cannot see before you open it, which is exactly the
 * shape of a payment-scam payload. Decoding locally means the image never leaves the phone, no
 * Google Play Services library is required, and the result can be handed to the existing
 * deterministic URL analyser before anything is opened.
 *
 * Limits, stated plainly:
 *  - the user must pick an image (system file picker); nothing scans the screen or the gallery;
 *  - a decoded payload is analysed as text, never executed or opened automatically;
 *  - decoding can fail on blurry or stylised codes, and a failure is reported as "no code found",
 *    not as "safe".
 */
object QrImageDecoder {

    /** Refuse absurd images before allocating a bitmap, so a hostile file cannot exhaust memory. */
    const val MAX_PIXELS = 12_000_000
    const val MAX_FILE_BYTES = 16L * 1024L * 1024L

    data class Decoded(val text: String, val format: String)

    /**
     * Pure decoding entry point: ARGB pixels in, payload out. No Android types, so it is testable
     * on the JVM (the test encodes a QR with ZXing and decodes it again).
     */
    fun decodeArgb(width: Int, height: Int, pixels: IntArray): Decoded? {
        if (width <= 0 || height <= 0) return null
        if (width.toLong() * height.toLong() > MAX_PIXELS) return null
        if (pixels.size < width * height) return null
        val source = runCatching { RGBLuminanceSource(width, height, pixels) }.getOrNull() ?: return null
        val bitmap = runCatching { BinaryBitmap(HybridBinarizer(source)) }.getOrNull() ?: return null
        val hints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
            put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE, BarcodeFormat.DATA_MATRIX))
            put(DecodeHintType.TRY_HARDER, true)
            put(DecodeHintType.CHARACTER_SET, "UTF-8")
        }
        val result = runCatching { MultiFormatReader().decode(bitmap, hints) }.getOrNull() ?: return null
        val text = result.text?.trim().orEmpty()
        if (text.isEmpty() || text.length > 4_096) return null
        return Decoded(text, result.barcodeFormat?.name ?: "QR_CODE")
    }

    /** Decodes a user-selected image, bounded by size and pixel count. */
    fun decodeUri(resolver: ContentResolver, uri: Uri): Result<Decoded> {
        val bytes = runCatching {
            resolver.openInputStream(uri)?.use(::readBounded)
        }.getOrNull() ?: return Result.failure(IllegalArgumentException("The image could not be read"))
        if (bytes.isEmpty()) return Result.failure(IllegalArgumentException("The image is empty or larger than 16 MB"))
        val options = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)
        if (options.outWidth <= 0 || options.outHeight <= 0) {
            return Result.failure(IllegalArgumentException("The file is not a decodable image"))
        }
        if (options.outWidth.toLong() * options.outHeight.toLong() > MAX_PIXELS) {
            return Result.failure(IllegalArgumentException("The image is larger than 12 megapixels"))
        }
        val bitmap: Bitmap = runCatching {
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
        }.getOrNull() ?: return Result.failure(IllegalArgumentException("The image could not be decoded"))
        return try {
            val width = bitmap.width
            val height = bitmap.height
            val pixels = IntArray(width * height)
            bitmap.getPixels(pixels, 0, width, 0, 0, width, height)
            val decoded = decodeArgb(width, height, pixels)
            if (decoded == null) {
                Result.failure(IllegalStateException("No QR or Data Matrix code was found in this image"))
            } else {
                Result.success(decoded)
            }
        } finally {
            bitmap.recycle()
        }
    }

    /**
     * Generates a QR code and decodes it again. Used by the runtime probe as a real self-test of
     * the decoder, so a green status is only shown when encoding and decoding actually agree.
     */
    fun selfTest(payload: String = "https://example.com/qr-selftest"): Result<Decoded> {
        val matrix = runCatching {
            QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, 240, 240)
        }.getOrNull() ?: return Result.failure(IllegalStateException("QR encoder unavailable"))
        val width = matrix.width
        val height = matrix.height
        val pixels = IntArray(width * height)
        for (y in 0 until height) {
            for (x in 0 until width) {
                pixels[y * width + x] = if (matrix.get(x, y)) 0xFF000000.toInt() else 0xFFFFFFFF.toInt()
            }
        }
        val decoded = decodeArgb(width, height, pixels)
            ?: return Result.failure(IllegalStateException("QR decoder could not read its own code"))
        return if (decoded.text == payload) {
            Result.success(decoded)
        } else {
            Result.failure(IllegalStateException("QR round-trip mismatch"))
        }
    }

    private fun readBounded(stream: InputStream): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(16 * 1024)
        var total = 0L
        while (true) {
            val read = stream.read(buffer)
            if (read <= 0) break
            total += read
            if (total > MAX_FILE_BYTES) return ByteArray(0)
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }
}
