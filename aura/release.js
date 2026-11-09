/**
 * Aura AI Assistant — release manifest.
 *
 * One place that describes where the Android build comes from, so the download
 * UI, the assistant's download answers and the verification checks in
 * `scripts/verify.mjs` all read the same values. Nothing here is decorative:
 * every field is either shown to the visitor or asserted by a test.
 *
 * Deliberately absent: byte size and SHA-256. MediaFire does not expose a
 * publisher-issued hash for this upload, and printing a checksum we did not
 * receive from the publisher would be worse than printing none — a wrong hash
 * looks exactly like a right one to someone who is not checking.
 */

/** Hosts the download card is ever allowed to link to. */
export const ALLOWED_DOWNLOAD_HOSTS = ['www.mediafire.com', 'mediafire.com'];

export const AURA_RELEASE = {
  product: 'Aura AI Assistant',
  channel: 'MediaFire',
  version: '1.0.582',
  fileName: 'aura-1.0.582.apk',
  platform: 'Android',
  publishedAt: '2026-11-06',
  /** Landing page for the upload — a human opens this, not a script. */
  pageUrl: 'https://www.mediafire.com/file/vqu39py830k1gkl/aura-1.0.582.apk/file',
  /** Not published by the uploader; the UI states this rather than guessing. */
  bytes: null,
  sha256: null,
  requirements: [
    'An Android phone or tablet that can install apps from outside the Play Store',
    '"Install unknown apps" permission for the browser or file manager that opens the APK',
    'Enough free storage for the download plus the installed app'
  ],
  steps: [
    'Choose “Download on MediaFire” below to open the official upload page.',
    'On the MediaFire page, confirm the file name is aura-1.0.582.apk, then download it.',
    'Open the downloaded file. If Android asks, allow "install unknown apps" for the app doing the install — then revoke that permission once the install finishes.',
    'Review the install prompt (permissions and version), then confirm.',
    'Open Aura and complete its introduction before granting anything optional.'
  ],
  notes: [
    'Sideloaded builds are not delivered by an app store, so the store\'s scanning does not apply — verify the file yourself before installing.',
    'No SHA-256 is published for this build. The card says so instead of showing an unverifiable value.',
    'Only use the link on this page; copies posted elsewhere may not be the same file.'
  ]
};

/**
 * True when a URL is an https link to an approved download host.
 * The UI runs every outbound download link through this before rendering it, and
 * the verification script asserts the manifest still passes.
 *
 * @param {string} url
 * @param {string[]} [hosts]
 * @returns {boolean}
 */
export function isAllowedDownloadUrl(url, hosts = ALLOWED_DOWNLOAD_HOSTS) {
  try {
    const parsed = new URL(String(url));
    return parsed.protocol === 'https:' && hosts.includes(parsed.hostname);
  } catch {
    return false;
  }
}

/**
 * Human-readable release line, e.g. `aura-1.0.582.apk · Android`.
 * @param {typeof AURA_RELEASE} [release]
 */
export function releaseLine(release = AURA_RELEASE) {
  return `${release.fileName} · ${release.platform}`;
}

/**
 * Integrity statement for the UI. Always says what is *not* known.
 * @param {typeof AURA_RELEASE} [release]
 */
export function integritySummary(release = AURA_RELEASE) {
  const parts = [];
  parts.push(release.sha256 ? `SHA-256 ${release.sha256}` : 'SHA-256 not published for this build');
  parts.push(release.bytes ? `${release.bytes} bytes` : 'size not published');
  return parts.join(' · ');
}
