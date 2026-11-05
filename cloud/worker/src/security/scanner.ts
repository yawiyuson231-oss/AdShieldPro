/**
 * Content safety scanner.
 *
 * Runs entirely inside the worker so it costs nothing and needs no third-party service:
 *   1. magic-byte vs declared-type mismatch detection (renamed executables)
 *   2. EICAR antivirus test-string detection
 *   3. executable / script signatures inside "media" uploads
 *   4. dangerous-extension policy
 *   5. optional external ClamAV-compatible scanner (SCANNER_URL) for real signature scanning
 *
 * Files that are not clean are quarantined: metadata is kept, download links are refused
 * until the owner explicitly releases them from Cloud Security.
 */
export type ScanVerdict = 'clean' | 'suspicious' | 'infected' | 'error';

export interface ScanFinding {
  code: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
}

export interface ScanResult {
  verdict: ScanVerdict;
  score: number;
  findings: ScanFinding[];
  engine: string;
}

/** Category of a MIME type, used to compare declared type against actual bytes. */
export function mimeCategory(mime: string, name: string): 'image' | 'video' | 'audio' | 'document' | 'archive' | 'executable' | 'text' | 'other' {
  const lower = mime.toLowerCase();
  const ext = name.includes('.') ? name.slice(name.lastIndexOf('.') + 1).toLowerCase() : '';
  if (lower.startsWith('image/')) return 'image';
  if (lower.startsWith('video/')) return 'video';
  if (lower.startsWith('audio/')) return 'audio';
  if (lower.startsWith('text/') || lower.includes('json') || lower.includes('xml')) return 'text';
  if (['zip', 'rar', '7z', 'tar', 'gz', 'apk', 'aab', 'jar', 'xapk'].includes(ext)) return 'archive';
  if (['exe', 'dll', 'bat', 'cmd', 'sh', 'ps1', 'msi', 'scr', 'com', 'vbs', 'js', 'jar'].includes(ext)) return 'executable';
  if (lower.includes('pdf') || lower.includes('word') || lower.includes('sheet') || lower.includes('presentation')
    || lower.includes('officedocument') || lower.includes('opendocument') || ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'txt', 'md', 'csv', 'rtf'].includes(ext)) {
    return 'document';
  }
  return 'other';
}

interface Signature {
  code: string;
  bytes: number[];
  atOffset: number;
  category: ScanFinding['severity'];
  message: string;
}

const SIGNATURES: Signature[] = [
  { code: 'pe-executable', bytes: [0x4d, 0x5a], atOffset: 0, category: 'critical', message: 'Windows PE executable header' },
  { code: 'elf-binary', bytes: [0x7f, 0x45, 0x4c, 0x46], atOffset: 0, category: 'critical', message: 'Linux ELF executable header' },
  { code: 'macho-binary', bytes: [0xcf, 0xfa, 0xed, 0xfe], atOffset: 0, category: 'critical', message: 'Mach-O executable header' },
  { code: 'dex-bytecode', bytes: [0x64, 0x65, 0x78, 0x0a], atOffset: 0, category: 'high', message: 'Android DEX bytecode' },
  { code: 'zip-archive', bytes: [0x50, 0x4b, 0x03, 0x04], atOffset: 0, category: 'low', message: 'ZIP container' },
  { code: 'pdf-header', bytes: [0x25, 0x50, 0x44, 0x46], atOffset: 0, category: 'low', message: 'PDF document' },
  { code: 'png-header', bytes: [0x89, 0x50, 0x4e, 0x47], atOffset: 0, category: 'low', message: 'PNG image' },
  { code: 'jpeg-header', bytes: [0xff, 0xd8, 0xff], atOffset: 0, category: 'low', message: 'JPEG image' },
  { code: 'gif-header', bytes: [0x47, 0x49, 0x46, 0x38], atOffset: 0, category: 'low', message: 'GIF image' },
  { code: 'riff-header', bytes: [0x52, 0x49, 0x46, 0x46], atOffset: 0, category: 'low', message: 'RIFF container (WAV/AVI/WEBP)' },
  { code: 'ftyp-header', bytes: [0x66, 0x74, 0x79, 0x70], atOffset: 4, category: 'low', message: 'ISO-BMFF container (MP4/MOV/HEIC)' },
  { code: 'ogg-header', bytes: [0x4f, 0x67, 0x67, 0x53], atOffset: 0, category: 'low', message: 'Ogg container' },
  { code: 'id3-header', bytes: [0x49, 0x44, 0x33], atOffset: 0, category: 'low', message: 'MP3 audio with ID3 tag' },
  { code: 'shell-script', bytes: [0x23, 0x21], atOffset: 0, category: 'medium', message: 'Script with shebang interpreter directive' },
];

function matchesAt(bytes: Uint8Array, signature: Signature): boolean {
  if (bytes.length < signature.atOffset + signature.bytes.length) return false;
  return signature.bytes.every((value, index) => bytes[signature.atOffset + index] === value);
}

function detectText(bytes: Uint8Array): string | null {
  const decoder = new TextDecoder('utf-8');
  return decoder.decode(bytes.subarray(0, Math.min(bytes.length, 4096)));
}

/** Scans the first N bytes of a file plus its metadata. */
export function scanBytes(
  head: Uint8Array,
  options: { name: string; mime: string; size: number; expectedSha256?: string }
): ScanResult {
  const findings: ScanFinding[] = [];
  const category = mimeCategory(options.mime, options.name);

  // Known-bad test string (proves the pipeline works end-to-end).
  const text = detectText(head);
  if (text && text.includes('EICAR-STANDARD-ANTIVIRUS-TEST-FILE')) {
    findings.push({ code: 'eicar-test-file', severity: 'critical', message: 'EICAR antivirus test pattern detected' });
  }

  const detected = SIGNATURES.filter((sig) => matchesAt(head, sig));
  const hasExecutableHeader = detected.some((sig) => ['pe-executable', 'elf-binary', 'macho-binary', 'dex-bytecode'].includes(sig.code));

  if (hasExecutableHeader && category !== 'executable' && category !== 'archive') {
    findings.push({
      code: 'type-mismatch-executable',
      severity: 'critical',
      message: `File is named and typed as ${category} but contains executable code`,
    });
  }

  if (category === 'image' && detected.length === 0) {
    findings.push({ code: 'image-signature-missing', severity: 'medium', message: 'Declared image has no recognised image header' });
  }

  const lowerName = options.name.toLowerCase();
  const doubleExtension = /\.(jpg|jpeg|png|gif|pdf|docx?|xlsx?|mp4|mp3|txt)\.(exe|scr|bat|cmd|js|vbs|jar|apk|ps1)$/.test(lowerName);
  if (doubleExtension) {
    findings.push({ code: 'double-extension', severity: 'high', message: 'Double file extension hides an executable' });
  }

  if (text && /<script[\s>]/i.test(text) && category === 'image') {
    findings.push({ code: 'script-in-image', severity: 'high', message: 'Script markup found inside an image payload' });
  }

  if (options.size === 0) {
    findings.push({ code: 'empty-file', severity: 'low', message: 'File is empty' });
  }

  const score = findings.reduce((total, finding) => {
    const weight = { low: 1, medium: 3, high: 6, critical: 10 }[finding.severity];
    return total + weight;
  }, 0);

  let verdict: ScanVerdict = 'clean';
  if (findings.some((f) => f.severity === 'critical')) verdict = 'infected';
  else if (findings.some((f) => f.severity === 'high')) verdict = 'suspicious';
  else if (score >= 3) verdict = 'suspicious';

  return { verdict, score, findings, engine: 'cybershield-heuristic-v1' };
}

/** Optional external scanner (e.g. a free self-hosted ClamAV REST shim). */
export async function scanWithExternalEngine(
  scannerUrl: string | undefined,
  bytes: Uint8Array,
  name: string
): Promise<ScanResult | null> {
  if (!scannerUrl) return null;
  try {
    const response = await fetch(`${scannerUrl.replace(/\/$/, '')}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': encodeURIComponent(name) },
      body: bytes as unknown as BodyInit,
    });
    if (!response.ok) return null;
    const body = (await response.json()) as { verdict?: string; findings?: ScanFinding[]; engine?: string };
    const verdict = (body.verdict ?? 'error') as ScanVerdict;
    if (!['clean', 'suspicious', 'infected', 'error'].includes(verdict)) return null;
    return { verdict, score: 0, findings: body.findings ?? [], engine: body.engine ?? 'external' };
  } catch {
    return null;
  }
}
