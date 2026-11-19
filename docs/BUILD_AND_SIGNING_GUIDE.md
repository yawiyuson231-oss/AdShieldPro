# AdShield Pro — APK, signing recovery, and AAB build guide

## 1. Environment Prerequisites

- **JDK:** Java 17 or Java 21 (AGP 9.4 requires JDK 17+)
- **Android SDK:** API 37 (`compileSdk = 37`, `targetSdk = 36`, `minSdk = 29`); install with `sdkmanager "platforms;android-37"` if missing.
- **Gradle:** Gradle 9.7.1 Wrapper (`.\gradlew.bat`), AGP 9.4.1, Kotlin 2.4.21

---

## 2. Building Debug & Release APKs (Deliverable 15)

Run from the repository root (where `gradlew.bat` and `settings.gradle.kts` live):

### Build Debug APK
```powershell
.\gradlew.bat assembleDebug
```
**Output APK Path:**
`app\build\outputs\apk\debug\app-debug.apk`

### Build Optimized & Minified Release APK
```powershell
.\gradlew.bat assembleRelease
```
**Output APK Path:**
`app\build\outputs\apk\release\app-release.apk`

---

## 3. Building a Signed Release Android App Bundle (`.aab`) for Google Play (Deliverable 16)

### Step 1: Use the Existing Production Signing Keystore

Use a trusted private signing key for the intended distribution channel. Android requires a compatible signing certificate or supported signing lineage for in-place updates. The historical GitHub APK key was publicly exposed: do not use it for production or import it as a Play upload key. GitHub APK publication remains blocked pending signing recovery (see [Publishing a release](../README.md#publishing-a-release)). If using Google Play App Signing, manage the upload key separately in Play Console.

### Step 2: Set Signing Environment Variables and Build `.aab`
`app/build.gradle.kts` reads release credentials from environment variables or Gradle user properties (never hardcoded in source control). On Windows, you can keep them in `%USERPROFILE%\.gradle\gradle.properties`, outside this project:

```properties
adshieldKeystorePath=C:/path/to/signing.keystore
adshieldKeystorePassword=your_keystore_password
adshieldKeyAlias=your_key_alias
adshieldKeyPassword=your_key_password
```

Keep this file private and never commit or share it. The equivalent environment variable names are shown below:

```powershell
$env:ADSHIELD_KEYSTORE_PATH = "C:\path\to\adshield-upload-key.jks"
$env:ADSHIELD_KEYSTORE_PASSWORD = "your_keystore_password"
$env:ADSHIELD_KEY_ALIAS = "adshield_upload"
$env:ADSHIELD_KEY_PASSWORD = "your_key_password"
.\gradlew.bat bundleRelease
```

**Output Signed AAB Path:**
`app\build\outputs\bundle\release\app-release.aab`

---

## Production signing recovery

The [public certificate audit](https://github.com/yawiyuson231-oss/AdShieldPro/actions/runs/44484928398)
verified the signatures on the actual v2.10.9 and v2.11.0 APKs. They use the same signing
certificate. Because the private key was published in v2.10.9, a new password or a new Actions
secret for that key cannot make an in-place production update trustworthy. Do not use that key
again or disable the continuity check. Removing an exposed key asset does not undo exposure.

**For current users:** keep the existing app installed while deciding how to migrate. In the old
app, open **Settings → Configuration Backup & Privacy Disclosures → Backup / Restore** and save
the displayed JSON privately. It backs up supported configuration such as custom rules, protection
mode, DNS settings, and exclusions. It is not a full device backup: it does not transfer scan
history, account credentials, API keys, or Android VPN consent.

**Replacement:** the production build now installs separately as **AdShield Pro Secure**
(`com.adshield.pro.secure`). Keep the old app until you have imported and checked your settings in
Secure. Only one app can run the VPN at a time; stop the old VPN before enabling the replacement.
Account sign-in and VPN consent must be set up again. The AI Agent does not require an API key. Do not uninstall the old app
until you have verified what migrated.

**Before publishing (repo maintainer):**

1. Create a new private Android signing keystore locally and back it up securely. Use a new key
   pair, not a new password on a legacy key. `keytool -genkeypair` can prompt for passwords at your
   terminal; do not put passwords on the command line or in the repository.
2. Create the GitHub Actions environment **`android-secure-release`**. Restrict deployments to
   reviewed `main` and configure required reviewers where available.
3. In that environment set **`ADSHIELD_SECURE_APK_CERT_SHA256`** to the 64-hex SHA-256 of the signed
   key's public certificate (`keytool -exportcert ... | sha256sum`). Add environment secrets
   **`ADSHIELD_SECURE_KEYSTORE_BASE64`** (base64 of the new key file), **`ADSHIELD_SECURE_STORE_PASSWORD`**,
   and optionally **`ADSHIELD_SECURE_KEY_ALIAS`** (default `adshield`) and
   **`ADSHIELD_SECURE_KEY_PASSWORD`** (defaults to the store password). The private key material
   belongs in the protected environment only.
4. Once the reviewed changes are on `main`, run **Test APK (pre-release)**, test the export/restore
   and VPN switch on a phone, then run **Release APK** after approving the signed candidate. The
   real release uses `secure-v<version>`, never overwrites a tag, and must leave legacy Latest
   unchanged. A `test-secure-` tag is not offered as an update.

**For testing only:** the opt-in GitHub **Android build & test** public preview uses the separate
`com.adshield.pro.debug` package and a CI debug signer. It does not use the exposed key or replace
production. A normal Actions debug artifact requires GitHub sign-in; a public preview is a direct
APK with no account required.

---

## 4. Running Automated Unit & Regression Tests

### Android Engine & Database Migration Unit Tests
```powershell
.\gradlew.bat testDebugUnitTest
```

