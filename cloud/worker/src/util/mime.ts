/**
 * File type validation policy.
 *
 * The API accepts a deliberately bounded set of types so the bucket can never be used as a
 * general file host for executable payloads. Unknown types are still storable (people back
 * up arbitrary documents) but are marked non-previewable and are always run through the
 * content scanner before they can be downloaded.
 */
export interface TypePolicy {
  /** canonical mime used when the client supplies nothing trustworthy */
  mime: string;
  previewable: boolean;
  /** inline rendering allowed from the share viewer */
  inlineSafe: boolean;
  category: 'image' | 'video' | 'audio' | 'document' | 'archive' | 'other';
}

const EXTENSION_TABLE: Record<string, TypePolicy> = {
  // images
  jpg: { mime: 'image/jpeg', previewable: true, inlineSafe: true, category: 'image' },
  jpeg: { mime: 'image/jpeg', previewable: true, inlineSafe: true, category: 'image' },
  png: { mime: 'image/png', previewable: true, inlineSafe: true, category: 'image' },
  webp: { mime: 'image/webp', previewable: true, inlineSafe: true, category: 'image' },
  gif: { mime: 'image/gif', previewable: true, inlineSafe: true, category: 'image' },
  heic: { mime: 'image/heic', previewable: true, inlineSafe: false, category: 'image' },
  heif: { mime: 'image/heif', previewable: true, inlineSafe: false, category: 'image' },
  bmp: { mime: 'image/bmp', previewable: true, inlineSafe: true, category: 'image' },
  svg: { mime: 'image/svg+xml', previewable: false, inlineSafe: false, category: 'image' }, // scriptable
  // video
  mp4: { mime: 'video/mp4', previewable: true, inlineSafe: true, category: 'video' },
  m4v: { mime: 'video/x-m4v', previewable: true, inlineSafe: true, category: 'video' },
  mov: { mime: 'video/quicktime', previewable: true, inlineSafe: false, category: 'video' },
  webm: { mime: 'video/webm', previewable: true, inlineSafe: true, category: 'video' },
  mkv: { mime: 'video/x-matroska', previewable: false, inlineSafe: false, category: 'video' },
  '3gp': { mime: 'video/3gpp', previewable: true, inlineSafe: false, category: 'video' },
  // audio
  mp3: { mime: 'audio/mpeg', previewable: true, inlineSafe: true, category: 'audio' },
  m4a: { mime: 'audio/mp4', previewable: true, inlineSafe: true, category: 'audio' },
  aac: { mime: 'audio/aac', previewable: true, inlineSafe: true, category: 'audio' },
  wav: { mime: 'audio/wav', previewable: true, inlineSafe: true, category: 'audio' },
  flac: { mime: 'audio/flac', previewable: true, inlineSafe: true, category: 'audio' },
  ogg: { mime: 'audio/ogg', previewable: true, inlineSafe: true, category: 'audio' },
  opus: { mime: 'audio/opus', previewable: true, inlineSafe: true, category: 'audio' },
  // documents
  pdf: { mime: 'application/pdf', previewable: true, inlineSafe: false, category: 'document' },
  txt: { mime: 'text/plain', previewable: true, inlineSafe: true, category: 'document' },
  md: { mime: 'text/markdown', previewable: true, inlineSafe: true, category: 'document' },
  csv: { mime: 'text/csv', previewable: true, inlineSafe: true, category: 'document' },
  rtf: { mime: 'application/rtf', previewable: false, inlineSafe: false, category: 'document' },
  doc: { mime: 'application/msword', previewable: false, inlineSafe: false, category: 'document' },
  docx: { mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', previewable: false, inlineSafe: false, category: 'document' },
  xls: { mime: 'application/vnd.ms-excel', previewable: false, inlineSafe: false, category: 'document' },
  xlsx: { mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', previewable: false, inlineSafe: false, category: 'document' },
  ppt: { mime: 'application/vnd.ms-powerpoint', previewable: false, inlineSafe: false, category: 'document' },
  pptx: { mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', previewable: false, inlineSafe: false, category: 'document' },
  odt: { mime: 'application/vnd.oasis.opendocument.text', previewable: false, inlineSafe: false, category: 'document' },
  ods: { mime: 'application/vnd.oasis.opendocument.spreadsheet', previewable: false, inlineSafe: false, category: 'document' },
  json: { mime: 'application/json', previewable: true, inlineSafe: false, category: 'document' },
  xml: { mime: 'application/xml', previewable: true, inlineSafe: false, category: 'document' },
  // archives (stored, never previewed)
  zip: { mime: 'application/zip', previewable: false, inlineSafe: false, category: 'archive' },
  '7z': { mime: 'application/x-7z-compressed', previewable: false, inlineSafe: false, category: 'archive' },
  tar: { mime: 'application/x-tar', previewable: false, inlineSafe: false, category: 'archive' },
  gz: { mime: 'application/gzip', previewable: false, inlineSafe: false, category: 'archive' },
  // encrypted AdShield backup bundle
  cshield: { mime: 'application/x-adshield-backup', previewable: false, inlineSafe: false, category: 'other' },
  // fallback
  bin: { mime: 'application/octet-stream', previewable: false, inlineSafe: false, category: 'other' },
};

const GENERIC: TypePolicy = { mime: 'application/octet-stream', previewable: false, inlineSafe: false, category: 'other' };

export function policyFor(name: string, clientMime?: string): TypePolicy {
  const ext = name.includes('.') ? name.slice(name.lastIndexOf('.') + 1).toLowerCase() : '';
  const byExtension = EXTENSION_TABLE[ext];
  if (byExtension) return byExtension;
  if (clientMime && /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(clientMime)) {
    const lower = clientMime.toLowerCase();
    if (lower.startsWith('image/')) return { ...GENERIC, mime: lower, previewable: true, category: 'image' };
    if (lower.startsWith('video/')) return { ...GENERIC, mime: lower, previewable: true, category: 'video' };
    if (lower.startsWith('audio/')) return { ...GENERIC, mime: lower, previewable: true, category: 'audio' };
    if (lower.startsWith('text/')) return { ...GENERIC, mime: lower, previewable: true, category: 'document' };
    return { ...GENERIC, mime: lower };
  }
  return GENERIC;
}

/** Extensions that are refused outright — they are only ever malware vectors here. */
const BLOCKED_EXTENSIONS = new Set([
  'exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'msi', 'msp', 'bat', 'cmd', 'vbs', 'vbe',
  'js', 'jse', 'wsf', 'wsh', 'ps1', 'psm1', 'sh', 'bash', 'zsh', 'hta', 'reg', 'lnk',
  'inf', 'gadget', 'elf', 'so', 'dylib',
]);

/**
 * Storable, but they are executable/archive payloads: they are always scanned and, when the
 * verdict is anything but clean, quarantined until the owner releases them explicitly.
 */
const QUARANTINE_EXTENSIONS = new Set(['apk', 'aab', 'jar', 'dex', 'zip', '7z', 'tar', 'gz', 'iso', 'dmg', 'xapk']);

export function assertAllowedUpload(name: string, clientMime?: string): TypePolicy & { requiresScan: boolean } {
  const ext = name.includes('.') ? name.slice(name.lastIndexOf('.') + 1).toLowerCase() : '';
  if (BLOCKED_EXTENSIONS.has(ext)) {
    const error = new Error(
      `Files with the ".${ext}" extension cannot be stored. AdShield Cloud never hosts executable or script payloads.`
    );
    (error as Error & { code?: string; status?: number }).code = 'unsupported_file_type';
    (error as Error & { code?: string; status?: number }).status = 415;
    throw error;
  }
  const policy = policyFor(name, clientMime);
  return { ...policy, requiresScan: QUARANTINE_EXTENSIONS.has(ext) };
}

export function categoryMatches(a: string, b: string): boolean {
  return a === b;
}
