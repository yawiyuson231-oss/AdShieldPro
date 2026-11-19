#!/usr/bin/env bash
# Shared signer verification for GitHub APK publication and read-only audits.
# Debug builds and the public-signer audit do not need a production signing key.
set -euo pipefail

fail() {
    echo "::error::$*" >&2
    exit 1
}

approved_certificate() {
    local trusted=${ADSHIELD_TRUSTED_APK_CERT_SHA256:-}
    [[ "$trusted" =~ ^[0-9A-Fa-f]{64}$ ]] || fail \
        'APK publication is blocked until signing recovery is reviewed and ADSHIELD_TRUSTED_APK_CERT_SHA256 is configured.'
    printf '%s\n' "${trusted,,}"
}

certificate_sha256() {
    local report digest
    local apksigner="${ANDROID_HOME:?}/build-tools/36.0.0/apksigner"
    report=$("$apksigner" verify --print-certs "$1") || fail 'APK signature verification failed.'
    digest=$(sed -nE 's/^Signer #[0-9]+ certificate SHA-256 digest: ([0-9A-Fa-f]{64})$/\1/p' <<< "$report")
    [[ "$digest" =~ ^[0-9A-Fa-f]{64}$ ]] || fail 'Expected exactly one APK signing certificate.'
    printf '%s\n' "${digest,,}"
}

prepare_workspace() {
    umask 077
    work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/adshield-signing.XXXXXXXX")
    trap 'rm -rf -- "$work"' EXIT
}

read_public_signers() {
    # v2.10.9 published the private signing key. Fetch only the exact public APK,
    # never the keystore or the full set of assets.
    local exposed_apk=AdShieldPro-2.10.9-release.apk
    gh release download v2.10.9 --pattern "$exposed_apk" --dir "$work" || fail \
        'Cannot download the historically exposed release APK for signer verification.'
    exposed=$(certificate_sha256 "$work/$exposed_apk")

    latest=$(gh release view --json tagName --jq .tagName) || fail 'Cannot resolve the current production release.'
    [[ "$latest" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Cannot identify the current production APK.'
    local previous_apk="AdShieldPro-${latest#v}-release.apk"
    if [[ ! -s "$work/$previous_apk" ]]; then
        gh release download "$latest" --pattern "$previous_apk" --dir "$work" || fail \
            'Cannot download the current production APK for signer verification.'
    fi
    published=$(certificate_sha256 "$work/$previous_apk")
}

case "${1:-}" in
    audit)
        prepare_workspace
        read_public_signers
        echo "v2.10.9 signer SHA-256: $exposed"
        echo "$latest signer SHA-256: $published"
        if [[ "$exposed" == "$published" ]]; then
            summary="Latest $latest uses the exposed v2.10.9 signing certificate. Do not sign another update with this key. A separate install or reviewed migration is required."
            echo "::warning title=Exposed production signing certificate::$summary"
        else
            summary="Latest $latest uses a different signing certificate than v2.10.9. In-place updates need the matching trusted private key; the APK does not prove the key is privately held."
            echo "::notice title=Production signing certificate differs::$summary"
        fi
        if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
            printf '## Public APK signing audit\n\n%s\n\n- v2.10.9: `%s`\n- %s: `%s`\n' \
                "$summary" "$exposed" "$latest" "$published" >> "$GITHUB_STEP_SUMMARY"
        fi
        ;;
    build)
        trusted=$(approved_certificate)
        [[ -n "${KEYSTORE_B64:-}" && -n "${ADSHIELD_STORE_PASSWORD:-}" ]] || fail \
            'Set the private release keystore and store password in GitHub Actions secrets.'
        prepare_workspace
        read_public_signers
        [[ "$trusted" != "$exposed" ]] || fail \
            'The configured signing certificate was exposed. A new password or secret does not change the key.'
        [[ "$trusted" == "$published" ]] || fail \
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
        trusted=$(approved_certificate)
        built=$(certificate_sha256 "${2:?pass the built release APK}")
        [[ "$trusted" == "$built" ]] || fail 'The built APK does not match the approved signing certificate.'
        echo "Verified APK signing certificate: $trusted"
        ;;
    *) fail 'Usage: release_signing.sh audit | build | verify <apk>' ;;
esac
