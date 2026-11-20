# GitHub Releases evolution-data channel

## Current state

GitHub Releases is the selected host. The repository is public, so app downloads do not need a GitHub token. The endpoint contract is:

`https://github.com/yawiyuson231-oss/AdShieldPro/releases/download/evolution-data/reputation.evo`

This URL is configured in code as the dedicated channel contract, **not evidence that an asset is already published**. No release, production signing key, secret, environment or app configuration was created by this change. A subsequent protected-environment provisioning attempt on 2026-11-20 was denied with HTTP 403 `Resource not accessible by integration`; admin environment/secret permissions need to be granted or an administrator must provision the environment through GitHub. No weaker repository-secret fallback was used. The updater remains default-off. These changes have not yet passed Android CI or runtime transport tests.

## Validation of this addition

- 18 isolated Kotlin/JVM updater test methods passed using the documented local JUnit-compatible assertion shim, including redirect allowlist, HTTPS/port/credential restrictions and redirect limits. This is not Android instrumentation or an HTTP transport integration test.
- 77 Python evolution tests passed, including seven new publisher tests using ephemeral test-only RSA keys.
- A separately executed interoperability check signed a harmless package with the Python publisher and verified its signature, sequence and indicator schema with the Kotlin verifier. The temporary private test key was removed; only ignored test output remains under `.cache/`.
- The 109 original boundary hashes remain pinned; only the exact disclosed additive consent-card insertion is normalized out, with all other bytes unchanged. No publisher workflow has been executed and no live CDN transfer, production signing or Android runtime claim follows from these checks.

## Channel isolation

The dedicated `evolution-data` prerelease is marked `--latest=false`. It must never replace the app's latest APK release. Its `reputation.evo` asset is a mutable channel head; each publication must have a strictly increasing signed sequence. Existing devices also enforce their stored sequence. The tag identifies the channel, not necessarily the source commit of each overwritten asset; retain source/review records separately.

The app manually follows at most three HTTPS redirects, only from the exact pinned GitHub channel to `release-assets.githubusercontent.com` or `objects.githubusercontent.com`, or between these exact CDN hosts. Credentials in URLs, fragments, alternate ports, HTTP downgrades, lookalike hosts and other GitHub repositories/paths are rejected. Custom HTTPS publishers still cannot redirect. Signed CDN query parameters are accepted but must not be recorded in telemetry. Normal platform TLS validation and mandatory publisher signature checks remain in force. If GitHub changes its hosting domains, the download fails closed pending a reviewed app change.

## Secure provisioning (repository owner)

1. Create the `evolution-publisher` GitHub environment. **Configure required independent reviewers and main-only deployment restrictions before enabling the workflow.** YAML's `environment` field alone does not establish these protections; GitHub plan/repository capabilities must support them. If appropriate environment protections are unavailable, do not enable automated signing.
2. Provision a 2048–4096-bit RSA publisher key using a trusted administrator machine or managed signing process. This is a different key from the Android APK signer. Keep private material out of source control, chat, logs and artifacts.
3. Set environment secret `EVOLUTION_PUBLISHER_PRIVATE_KEY_PEM` through GitHub's secure secret settings, and independently verify/set environment variable `EVOLUTION_PUBLISHER_PUBLIC_KEY_PEM`. Do not paste either private credentials or private-key content into this conversation.
4. Prepare `evolution/publisher/reviewed-reputation.json` in a reviewed PR. Its exact fields are `keyId`, `sequence`, `issuedAt`, `expiresAt`, `minAppVersion`, `maxAppVersion`, `indicators`. Indicator fields are `sha256` and `category` (`malware`, `phishing`, `unwanted`). Only independently reviewed real indicators belong in the publication input. Do not publish test hashes or fabricate detection evidence.
5. Preserve the source/license/label/evaluation review separately and make it part of the environment approval. The signing script validates format, times, signature/key matching and monotonic publication, **not indicator truth or the existing evolution holdout approval report**. The workflow must not be represented as an independent detection-quality gate.
6. Review and merge the publisher workflow through the normal process. It deliberately refuses signing from a working branch. No main merge is performed here.

## Publishing

Run `Publish reviewed evolution data` manually from main after the review above. The first publication requires the explicit `bootstrap` input. It creates the dedicated prerelease and fails if it already exists. Later runs must leave bootstrap false; they download the existing asset and cryptographically verify its signature/sequence using the configured public key before signing a higher sequence. Failure to obtain/verify the prior asset aborts publication rather than resetting history. Key rotation is not automatic and needs a migration plan.

The workflow signs in a private runner-temporary directory, verifies with the independently configured public key, publishes only `reputation.evo`, retains **only public** app configuration as an Actions artifact and removes the temporary private-key file in an always-run cleanup step. Runner isolation and GitHub secret custody remain trust boundaries. Cleanup is not a guarantee of physical secure erasure. Workflow concurrency serializes its own runs; manual uploads or other workflows can bypass it and must be prohibited operationally. A failed first run may leave an empty channel release needing explicit operator recovery; there is no silent reset/recreation.

An offline signing alternative is:

```sh
python3 -m tools.evolution.publisher \
  --manifest /secure/reviewed-reputation.json \
  --private-key /secure/publisher-private.pem \
  --public-key /secure/independently-verified-public.pem \
  --previous /secure/current-reputation.evo \
  --output /secure/output/reputation.evo \
  --public-config-output /secure/output/evolution-publisher.properties
```

Omit `--previous` only for an independently approved first publication. This tool does not upload anything. Its output configuration contains the public key, key ID and dedicated endpoint, not private signing material.

## Shipping app integration

Review the public configuration artifact against the independently trusted publisher key, then package it at `app/src/main/assets/evolution-publisher.properties` in an authorized app build. Never download and trust this configuration at runtime. The explicit consent UI, advisory-only scanner integration and atomic activation/rollback are now implemented. Complete Android build/instrumentation and real transport tests before enabling live use. Neither a published feed nor a staged download updates an already-installed app's executable code.

The signed validity window is at most seven days. Publish renewed, reviewed data with a higher sequence before expiry; an expired feed is not used as current evidence. Service outages and unmatched hashes are not evidence that files are safe. Data freshness, trusted time, key compromise, rollback after reinstall and holdout quality still require operational planning.
