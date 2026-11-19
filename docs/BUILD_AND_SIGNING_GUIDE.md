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

**For maintainers:** plan a separate application ID and a fresh private production signer rather
than silently replacing the old app. A separate install lets users confirm their backup and restore
before removing the old application. A clean reinstall under the original ID would require
uninstalling the existing app first, which deletes its local data. Do not publish either migration
until the package identity, separate update channel, signing custody, and recovery instructions are
reviewed. Never upload a private keystore to a release or provide it in chat.

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

