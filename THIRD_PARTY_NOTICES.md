# Third-Party Notices — TitanShield Max

TitanShield Max bundles the following third-party data assets inside `app/src/main/assets/`:

## HaGeZi DNS Blocklists

- **Files:** `core_max_ads.txt` (HaGeZi Multi Pro — ADS build), `core_max_threats.txt` (HaGeZi Threat Intelligence Feeds — mini build), `core_lite_ads.txt` (HaGeZi Light build).
- **Source:** https://github.com/hagezi/dns-blocklists
- **Author:** HaGeZi's Diversion and the HaGeZi community contributors.
- **License:** GNU General Public License v3.0 (verified from the repository `LICENSE` file, SPDX `GPL-3.0`).
- **Modifications:** The bundled files are the official builds plus a clearly-marked block of baseline additions at the end of `core_max_ads.txt` (5 bare infrastructural ad/tracker registrable domains, each verified by the CI compatibility gate `DnsFirewallCompatibilityTest`). Category header lines may be re-annotated by the parser in memory. Per GPLv3 the modified files and their source remain available.
- **Source availability:** The original list files are publicly downloadable from the source repository above. Per GPLv3, the bundled copies and their source are provided free of charge and this entire project is distributed under a GPLv3-compatible license with full source availability.

## Other remote filter sources (downloaded on demand, not bundled)

- AdGuard DNS Filter — https://github.com/AdguardTeam/AdGuardSDNSFilter (Creative Commons CC BY-SA / unless stated otherwise in that repository)
- OISD Small — https://oisd.nl (custom free license, see oisd.nl)
- URLHaus Malicious URL Blocklist — https://urlhaus.abuse.ch/blocklist/ (CC0 1.0)
- StevenBlack Unified Hosts — https://github.com/StevenBlack/hosts (MIT, data in the public domain where noted)

These lists are fetched at runtime only if the user enables their sources in Settings → Filter Sources; they are never redistributed by this app.

## Libraries

Jetpack Compose, Material 3, AndroidX (Room, DataStore, WorkManager, WebKit, Lifecycle), Dagger Hilt, OkHttp, Kotlin Coroutines, Kotlin Serialization — all under the Apache License 2.0.
