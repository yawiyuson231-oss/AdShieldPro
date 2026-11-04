# AdShield Pro / OMNISHIELD X INFINITY — Privacy Policy & Google Play Data Safety Disclosure

**Effective Date:** November 4, 2026

**Application:** AdShield Pro (`com.adshield.pro`)

---

## 1. Core Privacy Commitment

AdShield Pro is engineered from the ground up as a local, on-device privacy and ad-blocking firewall for Android.
- **No Root Required:** AdShield Pro operates exclusively in standard Android user space.
- **No Developer Analytics or Data Sale:** The app includes no developer analytics, advertising, crash-tracking SDK, or developer-operated collection endpoint, and we do not sell personal data. External providers you deliberately use (DNS, search, cloud, and media hosts) receive the requests needed to provide their service and have their own privacy policies.
- **No HTTPS Interception or Root Certificates:** AdShield Pro never installs a trusted root Certificate Authority (CA) and never decrypts, inspects, or modifies encrypted TLS/HTTPS application payloads.

---

## 2. How Android `VpnService` Is Used

AdShield Pro uses the Android `android.net.VpnService` API strictly to establish a **local on-device virtual DNS interface** (`10.215.173.1/30` and `fd00:ad5:1e1d::1/126`):
1. **DNS-Only Routing:** Only traffic destined for the virtual DNS addresses (`10.215.173.2/32` and `fd00:ad5:1e1d::2/128`) is routed into the local TUN interface. All non-DNS TCP, UDP, and QUIC application traffic flows directly over your physical Wi-Fi or mobile data interface without passing through a remote VPN server.
2. **Local Rule Evaluation:** Each DNS query is evaluated locally in memory against your enabled blocklists and custom rules.
   - **Blocked Domains:** Immediately answered on-device with `NXDOMAIN` or `0.0.0.0` / `::` sinkhole in `< 1 ms`.
   - **Allowed Domains:** Forwarded using the protocol you select: encrypted **DNS-over-HTTPS (DoH, RFC 8484)** or **DNS-over-TLS (DoT, RFC 7858)**, or unencrypted UDP/TCP port 53. If DoH or DoT is unavailable, the app returns DNS `SERVFAIL` instead of silently downgrading that query to plaintext.
3. **Resilience Controls (Local):** Per-app DNS policies, per-network (Wi-Fi / mobile data / Ethernet / other) policies, an emergency allowlist-only mode, optional failover between providers **you** select, and DNSSEC evidence reporting are all evaluated on-device from local settings. These settings never leave the device, are stored only in on-device DataStore, and are included in the local configuration backup you export yourself. Enabling failover means additional providers you selected may receive queries when the primary fails; an encrypted protocol never falls back to plaintext.
4. **Local File Scanning:** The YARA-compatible scanner subset runs entirely on-device over files you choose; no file content, hash or verdict is uploaded.

---

## 3. Upstream Encrypted DNS Providers

When a DNS query is allowed by your local filtering rules, it is resolved by your selected upstream DNS provider:
- **Cloudflare (`1.1.1.1`)** — Subject to the [Cloudflare 1.1.1.1 Privacy Commitment](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/).
- **Quad9 (`9.9.9.9`)** — Subject to the [Quad9 Privacy Policy](https://www.quad9.net/privacy/policy/).
- **AdGuard DNS** — Subject to the [AdGuard DNS Privacy Notice](https://adguard-dns.io/en/privacy.html).
- **Google Public DNS (`8.8.8.8`)** — Subject to the [Google Public DNS Privacy Notice](https://developers.google.com/speed/public-dns/privacy).
- **Custom DNS Resolver** — Subject to the privacy policy of the operator you configure.

---

## 4. Local Activity Logging & User Deletion Controls

- **Optional Local Logging:** Per-domain DNS query logs (`dns_logs` SQLite table) are stored **exclusively on your device** and can be toggled off at any time in the **Activity** tab.
- **Automatic Retention Pruning:** Local DNS logs are automatically purged after your selected retention window (1–90 days).
- **One-Tap Data Deletion:** Tapping **Clear History** in the **Activity** tab permanently deletes all local DNS logs and historical statistics from your device. Security → History has a separate control for persisted scan reports.
- **Platform Backups:** App-private data is excluded from Android cloud backup and device transfer. The manual JSON configuration export does not include DNS query history, security reports, storage-provider passwords, search history, or download history.

### 4A. Private search and Browser data

- DuckDuckGo is the default search provider; Google can be selected. Search text is sent over HTTPS to the selected external provider, which can also observe normal connection metadata such as IP address and user agent.
- Search suggestions are **off by default**. Enabling them sends typed search text to the selected provider before you submit the search.
- Search history stores search text, provider, and timestamp locally in DataStore, not every visited page. You can disable it, clear it, enable automatic deletion when leaving Browser, or use private mode to suppress new search history.
- Private mode disables WebView cookies, DOM storage and cache and clears WebView session data on exit. It does not make searches anonymous and does not prevent websites/providers from observing their own requests.

### 4B. SAF files, security reports and duplicates

- Files and folder trees are accessed only after you grant an Android Storage Access Framework URI. The app does not request all-files access and cannot read other apps’ sandbox-private files.
- Security scans, duplicate detection and hashes run locally. Scan reports can include document names, user-granted URIs, findings, timestamps and risk scores and are stored locally in Room until you clear them or delete the app data.
- File preview/share sends a user-selected document or URI grant to the Android app you choose. Cloud preview/download writes to the destination you select.

### 4C. Nextcloud/WebDAV and Infinity providers

- No storage provider is connected by default. When you register one, its display name, type, HTTPS URL, username, health and quota metadata are stored locally in Room. Passwords/app passwords are encrypted with an Android-Keystore-backed AES-GCM key; only ciphertext is stored in app-private preferences.
- Upload/list/share/rename/delete operations send the relevant file content, paths and credentials to the authorized server you configured. Nextcloud public links can make shared content accessible to anyone with the link, subject to server policy.
- The app itself does not operate those servers, provide free capacity, or receive a copy of provider credentials/files. Server logs, retention, versions, trash, backups and sharing are controlled by the server operator.

### 4D. Direct-media downloads

- Inspecting or downloading a direct media URL sends that URL and normal connection metadata to its host. The app supports only direct permitted HTTPS media and does not bypass authentication, DRM or site restrictions.
- Local download history includes source/final file metadata, destination URI, status, sizes, errors and integrity results. It remains in Room until you remove the history entry or clear app data. Removing history does not delete the downloaded document.

---

## 5. Google Play Data Safety Section Summary

| Data Category | Collected Off-Device? | Shared with Third Parties? | Purpose |
| :--- | :---: | :---: | :--- |
| Web Browsing / DNS Queries | **No developer collection** (processed locally; allowed queries go to the user-selected DNS resolver) | **Only user-selected infrastructure** | Local filtering and resolution |
| Search text / suggestions | **No developer collection** (sent only when using search; suggestions are opt-in) | **Selected Google or DuckDuckGo provider** | User-requested search |
| Files, filenames and security hashes | **No developer collection** (local by default; cloud transfer only on user action) | **User-authorized WebDAV/Nextcloud or preview/share app** | File management, security and storage |
| Cloud account / password | **No developer collection** (username/URL local; password encrypted locally; sent to configured server for authentication) | **User-authorized storage provider** | User-requested cloud connection |
| Direct media URL / download metadata | **No developer collection** (history stored locally; URL sent to media host on user action) | **User-selected media host** | User-requested download |
| Installed App List (`QUERY_ALL_PACKAGES`) | **No** (Never leaves device) | **No** | Per-app VPN controls and local security audit |
| Diagnostics / Crash Tracking SDKs | **None Included** | **No** | Zero third-party tracking SDKs |
