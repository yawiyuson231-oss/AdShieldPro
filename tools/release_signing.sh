#!/usr/bin/env bash
# Shared signer verification for GitHub APK publication and read-only audits.
# Debug builds and the public-signer audit do not need a production signing key.
set -euo pipefail

fail() {
    echo "::error::$*" >&2
    exit 1
}

approved_certificate() {
    local trusted=${ADSHIELD_SECURE_APK_CERT_SHA256:-}
    [[ "$trusted" =~ ^[0-9A-Fa-f]{64}$ ]] || fail \
        'Secure APK publication requires the approved ADSHIELD_SECURE_APK_CERT_SHA256 variable.'
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

verify_secure_continuity() {
    local tags predecessor apk attrs
    local next="secure-v${SECURE_VERSION_NAME:?}"
    local tag_pattern='^secure-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]?)\.(0|[1-9][0-9]?)$'
    [[ "$next" =~ $tag_pattern ]] || fail 'Invalid Secure release version.'
    tags=$(gh api --paginate "repos/${GITHUB_REPOSITORY:?}/releases?per_page=100" \
        --jq '.[] | select(.draft == false) | .tag_name') || fail 'Cannot inspect existing Secure releases.'
    predecessor=$(printf '%s\n' "$tags" | { grep -E "$tag_pattern" || true; } | sort -V | tail -n 1)
    if [[ -z "$predecessor" ]]; then
        echo 'No prior Secure APK; verifying the first independent installation signer.'
        return
    fi
    [[ "$predecessor" != "$next" && "$(printf '%s\n%s\n' "$predecessor" "$next" | sort -V | tail -n 1)" == "$next" ]] ||
        fail 'Secure version must be newer than the published Secure channel.'
    apk="AdShieldPro-Secure-${predecessor#secure-v}-release.apk"
    gh release download "$predecessor" --pattern "$apk" --dir "$work" || fail 'Cannot download the prior Secure APK.'
    [[ "$(certificate_sha256 "$work/$apk")" == "$trusted" ]] || fail 'The prior Secure APK uses another signer.'
    attrs=$("$ANDROID_HOME/build-tools/36.0.0/aapt2" dump badging "$work/$apk") || fail 'Cannot validate the prior Secure APK identity.'
    grep -q "^package: name='com\.adshield\.pro\.secure' " <<< "$attrs" || fail 'The prior Secure APK has another package identity.'
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
    build-secure)
        trusted=$(approved_certificate)
        [[ -n "${KEYSTORE_B64:-}" && -n "${ADSHIELD_STORE_PASSWORD:-}" ]] || fail \
            'Set the private Secure keystore and store password in the release environment.'
        prepare_workspace
        read_public_signers
        [[ "$trusted" != "$exposed" && "$trusted" != "$published" ]] || fail \
            'Secure must use a fresh signer. The exposed and legacy APK certificates cannot be reused.'
        verify_secure_continuity

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
        export GITHUB_UPDATE_REPOSITORY="$GITHUB_REPOSITORY"
        ./gradlew :app:assembleRelease --no-daemon --console=plain
        ;;
    verify-secure)
        trusted=$(approved_certificate)
        built=$(certificate_sha256 "${2:?pass the built release APK}")
        [[ "$trusted" == "$built" ]] || fail 'The built APK does not match the approved signing certificate.'
        echo "Verified APK signing certificate: $trusted"
        ;;
    *) fail 'Usage: release_signing.sh audit | build-secure | verify-secure <apk>; legacy publication is retired' ;;
esac
