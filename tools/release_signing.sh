#!/usr/bin/env bash
# Only the two GitHub APK publication workflows use this policy. CI debug builds
# and throwaway-key R8 checks do not need a production signing key.
set -euo pipefail

fail() {
    echo "::error::$*" >&2
    exit 1
}

trusted=${ADSHIELD_TRUSTED_APK_CERT_SHA256:-}
[[ "$trusted" =~ ^[0-9A-Fa-f]{64}$ ]] || fail \
    'APK publication is blocked until signing recovery is reviewed and ADSHIELD_TRUSTED_APK_CERT_SHA256 is configured.'
trusted=${trusted,,}
apksigner="${ANDROID_HOME:?}/build-tools/36.0.0/apksigner"

certificate_sha256() {
    local report digest
    report=$("$apksigner" verify --print-certs "$1") || fail 'APK signature verification failed.'
    digest=$(sed -nE 's/^Signer #[0-9]+ certificate SHA-256 digest: ([0-9A-Fa-f]{64})$/\1/p' <<< "$report")
    [[ "$digest" =~ ^[0-9A-Fa-f]{64}$ ]] || fail 'Expected exactly one APK signing certificate.'
    printf '%s\n' "${digest,,}"
}

case "${1:-}" in
    build)
        [[ -n "${KEYSTORE_B64:-}" && -n "${ADSHIELD_STORE_PASSWORD:-}" ]] || fail \
            'Set the private release keystore and store password in GitHub Actions secrets.'
        umask 077
        work=$(mktemp -d "${RUNNER_TEMP:?}/adshield-signing.XXXXXXXX")
        trap 'rm -rf -- "$work"' EXIT

        # v2.10.9's release notes confirm its signing private key was published.
        # Read the public certificate from the signed APK, never the keystore asset.
        exposed_apk=AdShieldPro-2.10.9-release.apk
        gh release download v2.10.9 --pattern "$exposed_apk" --dir "$work" || fail \
            'Cannot verify the historically exposed signing certificate; refusing to sign.'
        exposed=$(certificate_sha256 "$work/$exposed_apk")
        [[ "$trusted" != "$exposed" ]] || fail \
            'The configured signing certificate was exposed. A new password or secret does not change the key.'

        latest=$(gh release view --json tagName --jq .tagName) || fail 'Cannot resolve the current production release.'
        [[ "$latest" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Cannot identify the current production APK.'
        previous_apk="AdShieldPro-${latest#v}-release.apk"
        if [[ ! -s "$work/$previous_apk" ]]; then
            gh release download "$latest" --pattern "$previous_apk" --dir "$work" || fail \
                'Cannot verify the current production APK; refusing to sign.'
        fi
        [[ "$trusted" == "$(certificate_sha256 "$work/$previous_apk")" ]] || fail \
            'The trusted signer does not match the current production APK. Resolve the Android migration before publishing.'

        keystore="$work/release.jks"
        printf '%s' "$KEYSTORE_B64" | base64 --decode > "$keystore" || fail 'Invalid release keystore encoding.'
        digest=$(keytool -exportcert -keystore "$keystore" -alias "${ADSHIELD_KEY_ALIAS:-adshield}" \
            -storepass:env ADSHIELD_STORE_PASSWORD | sha256sum | cut -d ' ' -f 1) || fail \
            'Cannot read the certificate from the private signing configuration.'
        [[ "$trusted" == "$digest" ]] || fail 'Private keystore does not match the approved certificate.'
        unset KEYSTORE_B64
        export ADSHIELD_KEYSTORE_PATH="$keystore"
        export ADSHIELD_KEYSTORE_PASSWORD="$ADSHIELD_STORE_PASSWORD"
        export ADSHIELD_KEY_ALIAS="${ADSHIELD_KEY_ALIAS:-adshield}"
        export ADSHIELD_KEY_PASSWORD="${ADSHIELD_KEY_PASSWORD:-$ADSHIELD_STORE_PASSWORD}"
        ./gradlew :app:assembleRelease --no-daemon --console=plain
        ;;
    verify)
        built=$(certificate_sha256 "${2:?pass the built release APK}")
        [[ "$trusted" == "$built" ]] || fail 'The built APK does not match the approved signing certificate.'
        echo "Verified APK signing certificate: $trusted"
        ;;
    *) fail 'Usage: release_signing.sh build | verify <apk>' ;;
esac
