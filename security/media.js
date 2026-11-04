/**
 * OmniShield X — universal media downloader.
 *
 * What this module does for real:
 *   - parses a pasted URL, names the platform and the media id
 *   - fetches genuine metadata from each platform's public oEmbed endpoint
 *     (title, author, thumbnail, declared formats) when that endpoint allows
 *     cross-origin reads
 *   - downloads URLs whose server permits it (direct media files and any URL that
 *     answers a ranged GET) with a resumable, pausable, cancellable queue
 *
 * What it deliberately does not do: strip DRM, bypass a paywall, or "extract"
 * streams from YouTube/Spotify/Instagram. Those platforms' terms forbid it, the
 * media is usually DRM-protected or served through signed manifests, and a browser
 * cannot legally or technically do it. For those URLs the module returns a
 * `blocked` result that names the reason and the supported alternative — it never
 * pretends a download started.
 */
import { createFileSink } from './vault.js';
import { sha256Hex } from './sha256.js';
import { MAX_FILE_BYTES } from './storage.js';

/** Platform registry. `directDownload` reflects what the operator permits. */
export const PLATFORMS = [
  {
    id: 'youtube', name: 'YouTube', hosts: ['youtube.com', 'youtu.be', 'm.youtube.com', 'music.youtube.com'],
    oembed: 'https://www.youtube.com/oembed?format=json&url=',
    directDownload: false,
    reason: 'YouTube serves media through signed adaptive manifests and its Terms of Service prohibit downloading outside the app.',
    alternative: 'Use YouTube Premium/offline, or the official download for your own uploads in YouTube Studio.'
  },
  {
    id: 'vimeo', name: 'Vimeo', hosts: ['vimeo.com', 'player.vimeo.com'],
    oembed: 'https://vimeo.com/api/oembed.json?url=',
    directDownload: true,
    reason: 'Vimeo exposes a per-video download link only when the uploader enabled it and the request is authorised.',
    alternative: 'The uploader can enable downloads in the video settings; the link then appears on the video page.'
  },
  {
    id: 'soundcloud', name: 'SoundCloud', hosts: ['soundcloud.com', 'm.soundcloud.com'],
    oembed: 'https://soundcloud.com/oembed?format=json&url=',
    directDownload: true,
    reason: 'SoundCloud tracks can be downloaded only when the artist enables the download button.',
    alternative: 'Use the artist-enabled download button on the track page.'
  },
  {
    id: 'dailymotion', name: 'Dailymotion', hosts: ['dailymotion.com', 'dai.ly'],
    oembed: 'https://www.dailymotion.com/services/oembed?format=json&url=',
    directDownload: false,
    reason: 'Dailymotion does not permit third-party downloading of its streams.',
    alternative: 'Use the platform\'s own offline feature where it is offered.'
  },
  {
    id: 'tiktok', name: 'TikTok', hosts: ['tiktok.com', 'vm.tiktok.com'],
    oembed: 'https://www.tiktok.com/oembed?url=',
    directDownload: false,
    reason: 'TikTok permits saving your own posts in the app; third-party extraction is not permitted.',
    alternative: 'Use "Save video" inside TikTok for content you own.'
  },
  {
    id: 'instagram', name: 'Instagram', hosts: ['instagram.com'],
    oembed: null, // Meta requires an app token for oEmbed; the request would always fail.
    directDownload: false,
    reason: 'Instagram requires an authenticated Meta Graph token for oEmbed and prohibits automated downloading.',
    alternative: 'Use Instagram\'s own download for your own posts.'
  },
  {
    id: 'spotify', name: 'Spotify', hosts: ['spotify.com', 'open.spotify.com'],
    oembed: 'https://open.spotify.com/oembed?url=',
    directDownload: false,
    reason: 'Spotify streams are Widevine DRM protected; no browser can download them, by design.',
    alternative: 'Use Spotify offline downloads with a Premium account.'
  },
  {
    id: 'direct', name: 'Direct media file', hosts: [], oembed: null, directDownload: true,
    reason: null, alternative: null
  }
];

const MEDIA_EXTENSIONS = {
  video: ['mp4', 'webm', 'mkv', 'mov', 'm4v', 'ogv', 'avi', 'ts', 'm3u8'],
  audio: ['mp3', 'm4a', 'aac', 'ogg', 'opus', 'wav', 'flac', 'weba'],
  image: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'svg', 'bmp', 'heic'],
  document: ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'txt', 'md', 'rtf', 'csv', 'json', 'xml']
};

/** Declared format ladders — what the *platform* publishes, not what we can fetch. */
const FORMAT_LADDERS = {
  video: [
    { id: 'mp4-2160', container: 'mp4', resolution: '2160p', height: 2160 },
    { id: 'mp4-1440', container: 'mp4', resolution: '1440p', height: 1440 },
    { id: 'mp4-1080', container: 'mp4', resolution: '1080p', height: 1080 },
    { id: 'mp4-720', container: 'mp4', resolution: '720p', height: 720 },
    { id: 'mp4-480', container: 'mp4', resolution: '480p', height: 480 },
    { id: 'webm-1080', container: 'webm', resolution: '1080p', height: 1080 }
  ],
  audio: [
    { id: 'm4a-256', container: 'm4a', bitrateKbps: 256 },
    { id: 'mp3-320', container: 'mp3', bitrateKbps: 320 },
    { id: 'mp3-192', container: 'mp3', bitrateKbps: 192 },
    { id: 'opus-128', container: 'opus', bitrateKbps: 128 }
  ]
};

const DEFAULT_MAX_BYTES = MAX_FILE_BYTES;

/** Extension of a URL path, lower-cased, without the query string. */
export function extensionOf(url) {
  try {
    const path = new URL(url).pathname;
    const match = /\.([A-Za-z0-9]{1,8})$/.exec(path);
    return match ? match[1].toLowerCase() : '';
  } catch {
    return '';
  }
}

/** Which media family an extension belongs to, or null. */
export function mediaKind(extension) {
  const ext = String(extension || '').toLowerCase();
  for (const [kind, list] of Object.entries(MEDIA_EXTENSIONS)) if (list.includes(ext)) return kind;
  return null;
}

/**
 * Classifies a pasted URL.
 * @returns {{ok:true, platform:object, id:string|null, canonical:string, kind:string|null, direct:boolean}
 *         | {ok:false, error:string}}
 */
export function parseMediaUrl(input) {
  const raw = String(input || '').trim();
  if (!raw) return { ok: false, error: 'Paste a video, audio or direct media URL first.' };
  let url;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
  } catch {
    return { ok: false, error: 'That is not a valid URL.' };
  }
  if (!/^https?:$/.test(url.protocol)) return { ok: false, error: 'Only http and https URLs are supported.' };

  const host = url.hostname.toLowerCase().replace(/^www\./, '');
  const platform = PLATFORMS.find((p) => p.hosts.some((h) => host === h || host.endsWith(`.${h}`)));
  const ext = extensionOf(url.href);
  const kind = mediaKind(ext);

  if (!platform) {
    if (kind) {
      return { ok: true, platform: PLATFORMS.find((p) => p.id === 'direct'), id: url.pathname.split('/').pop(), canonical: url.href, kind, direct: true };
    }
    return { ok: false, error: `${host} is not a recognised media platform, and the path has no media extension.` };
  }

  let id = null;
  if (platform.id === 'youtube') {
    id = url.searchParams.get('v') || (/^\/(?:shorts|embed|live)\/([\w-]{6,})/.exec(url.pathname)?.[1]) || (/^\/youtu\.be\//.test(`/${host}${url.pathname}`) ? url.pathname.slice(1) : null) || (host === 'youtu.be' ? url.pathname.slice(1) : null);
  } else if (platform.id === 'vimeo') {
    id = /\/(\d+)/.exec(url.pathname)?.[1] || null;
  } else if (platform.id === 'dailymotion') {
    id = /\/(?:video|embed\/video)\/([\w]+)/.exec(url.pathname)?.[1] || (host === 'dai.ly' ? url.pathname.slice(1) : null);
  } else if (platform.id === 'soundcloud') {
    id = url.pathname.replace(/^\//, '') || null;
  } else {
    id = url.pathname.replace(/^\/|\.mp4$/g, '') || null;
  }

  return { ok: true, platform, id, canonical: url.href, kind: kind || 'video', direct: !!platform.directDownload && !!kind };
}

/** The format ladder this platform publishes for the given media kind. */
export function availableFormats(kind) {
  if (kind === 'audio') return FORMAT_LADDERS.audio.map((f) => ({ ...f }));
  if (kind === 'video') return FORMAT_LADDERS.video.map((f) => ({ ...f }));
  return [];
}

/**
 * Fetches real metadata for a parsed URL from the platform's public oEmbed
 * endpoint. A CORS failure is reported as a CORS failure — never as "unknown
 * video", and never as success.
 */
export async function probeMedia(parsed, options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch?.bind(globalThis);
  const entry = parsed?.platform;
  if (!parsed?.ok) return { ok: false, error: parsed?.error || 'Unsupported URL.' };
  if (!entry?.oembed) {
    return {
      ok: false,
      code: 'NO_METADATA_ENDPOINT',
      error: `${entry.name} does not expose a public oEmbed endpoint a browser can read without credentials.`,
      formats: availableFormats(parsed.kind),
      direct: parsed.direct
    };
  }
  if (typeof fetchImpl !== 'function') return { ok: false, code: 'NO_FETCH', error: 'This browser has no fetch() implementation.' };

  const endpoint = entry.oembed + encodeURIComponent(parsed.canonical);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 12_000);
  try {
    const response = await fetchImpl(endpoint, { signal: controller.signal, credentials: 'omit', cache: 'no-store' });
    if (!response.ok) {
      return { ok: false, code: `HTTP_${response.status}`, error: `${entry.name} answered HTTP ${response.status} for its metadata endpoint.`, formats: availableFormats(parsed.kind), direct: parsed.direct };
    }
    const data = await response.json();
    return {
      ok: true,
      platform: entry.id,
      title: typeof data.title === 'string' ? data.title : null,
      author: typeof data.author_name === 'string' ? data.author_name : null,
      thumbnail: typeof data.thumbnail_url === 'string' ? data.thumbnail_url : null,
      durationSeconds: Number.isFinite(data.duration) ? data.duration : null,
      source: endpoint,
      formats: availableFormats(parsed.kind),
      direct: parsed.direct
    };
  } catch (error) {
    const blocked = error?.name === 'AbortError'
      ? 'the request timed out after 12 s'
      : 'the browser blocked the cross-origin read (CORS) or the network is offline';
    return { ok: false, code: 'NETWORK', error: `Metadata request failed: ${blocked}.`, detail: String(error?.message || error), formats: availableFormats(parsed.kind), direct: parsed.direct };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Pre-flight a URL with a HEAD request: does the server allow a download, does it
 * support ranges (needed for resume), what is the size and type?
 */
export async function inspectRemote(url, options = {}) {
  const fetchImpl = options.fetchImpl || globalThis.fetch?.bind(globalThis);
  if (typeof fetchImpl !== 'function') return { ok: false, error: 'fetch() unavailable.' };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 12_000);
  try {
    const response = await fetchImpl(url, { method: 'HEAD', signal: controller.signal, credentials: 'omit', redirect: 'follow', cache: 'no-store' });
    if (!response.ok) return { ok: false, error: `Server answered HTTP ${response.status} for a HEAD request.`, status: response.status };
    const length = Number(response.headers.get('content-length'));
    return {
      ok: true,
      status: response.status,
      size: Number.isFinite(length) && length > 0 ? length : null,
      type: response.headers.get('content-type') || null,
      resumable: /bytes/i.test(response.headers.get('accept-ranges') || ''),
      rangeHeader: response.headers.get('accept-ranges') || null,
      finalUrl: response.url || url
    };
  } catch (error) {
    return { ok: false, error: `Pre-flight failed: ${error?.name === 'AbortError' ? 'timeout' : error?.message || error}` };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * A resumable download queue.
 *
 * Tasks are plain objects persisted by the caller (metadata only — never bytes).
 * `start` streams a ranged GET into a file sink, reports real progress, and can be
 * paused (abort + remember bytes), resumed (ranged GET from the saved offset) or
 * cancelled (abort + delete the partial file).
 */
export class DownloadQueue {
  /**
   * @param {{fetchImpl?:Function, createSink?:Function, maxBytes?:number, onUpdate?:Function, clock?:()=>number}} [options]
   */
  constructor(options = {}) {
    this.fetchImpl = options.fetchImpl || globalThis.fetch?.bind(globalThis);
    this.createSink = options.createSink || createFileSink;
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
    this.onUpdate = options.onUpdate || (() => {});
    this.clock = options.clock || (() => Date.now());
    /** @type {Map<string, object>} */
    this.tasks = new Map();
    this._sequence = 0;
    this._controllers = new Map();
  }

  _emit(task) {
    try { this.onUpdate({ ...task }); } catch { /* a listener must not break a transfer */ }
  }

  /** Adds a task. Returns the stored object (never a copy). */
  add({ url, name, format = null, kind = null, resumable = null, size = null, destination = null, platform = null }) {
    const id = `dl-${this.clock()}-${this._sequence++}`;
    const task = {
      id, url, name: name || decodeURIComponent(url.split('/').pop() || 'download'),
      format, kind, platform, destination,
      status: 'queued', size: size ?? null, received: 0,
      resumable: resumable ?? null, startedAt: null, finishedAt: null,
      error: null, sha256: null, sinkPath: null, updatedAt: this.clock()
    };
    this.tasks.set(id, task);
    this._emit(task);
    return task;
  }

  list() { return [...this.tasks.values()].sort((a, b) => b.updatedAt - a.updatedAt); }

  get(id) { return this.tasks.get(id) || null; }

  stats() {
    const tasks = [...this.tasks.values()];
    const done = tasks.filter((t) => t.status === 'done');
    return {
      total: tasks.length,
      active: tasks.filter((t) => t.status === 'downloading').length,
      queued: tasks.filter((t) => t.status === 'queued').length,
      paused: tasks.filter((t) => t.status === 'paused').length,
      failed: tasks.filter((t) => t.status === 'failed').length,
      done: done.length,
      bytes: done.reduce((sum, t) => sum + (t.received || 0), 0)
    };
  }

  remove(id) {
    const task = this.tasks.get(id);
    if (!task) return false;
    if (task.status === 'downloading') this.cancel(id);
    this.tasks.delete(id);
    return true;
  }

  cancel(id) {
    const task = this.tasks.get(id);
    if (!task) return false;
    const controller = this._controllers.get(id);
    if (controller) controller.abort(new Error('cancelled by user'));
    task.status = 'cancelled';
    task.updatedAt = this.clock();
    this._emit(task);
    return true;
  }

  /**
   * Runs (or resumes) one task to completion.
   * @returns {Promise<object>} the final task state
   */
  async start(id, { sinkFactory } = {}) {
    const task = this.tasks.get(id);
    if (!task) throw new Error(`unknown download ${id}`);
    if (task.status === 'downloading') return task;
    if (typeof this.fetchImpl !== 'function') {
      task.status = 'failed';
      task.error = 'fetch() is unavailable in this context.';
      this._emit(task);
      return task;
    }

    const controller = new AbortController();
    this._controllers.set(id, controller);
    task.status = 'downloading';
    task.startedAt = task.startedAt || this.clock();
    task.error = null;
    this._emit(task);

    let sink = null;
    try {
      const resumeFrom = task.received;
      const headers = {};
      if (resumeFrom > 0 && task.resumable) headers.Range = `bytes=${resumeFrom}-`;
      const response = await this.fetchImpl(task.url, { signal: controller.signal, headers, credentials: 'omit', redirect: 'follow' });

      if (resumeFrom > 0 && response.status !== 206 && response.status !== 200) {
        throw new Error(`server answered HTTP ${response.status} to the ranged request`);
      }
      if (!response.ok) throw new Error(`server answered HTTP ${response.status}`);
      if (resumeFrom > 0 && response.status === 200) {
        // Server ignored our Range: start over rather than corrupt the file.
        task.received = 0;
      }

      const declared = Number(response.headers?.get?.('content-length'));
      if (Number.isFinite(declared) && declared > 0) {
        task.size = response.status === 206 ? task.size : declared;
        const total = (response.status === 206 ? (task.size || 0) : declared);
        if (total > this.maxBytes) throw new Error(`file is larger than the ${Math.round(this.maxBytes / 1024 / 1024)} MB per-file limit — set a smaller range or download it directly`);
      }

      const factory = sinkFactory || this.createSink;
      sink = await factory({ name: task.name, resumeFrom: task.received });
      task.sinkPath = sink.path || task.name;

      const reader = response.body?.getReader?.();
      if (!reader) {
        // No streaming in this environment: read once, write once, still honest.
        const buffer = new Uint8Array(await response.arrayBuffer());
        if (buffer.byteLength > this.maxBytes) throw new Error('file exceeds the size limit');
        await sink.write(buffer);
        task.received += buffer.byteLength;
        this._emit(task);
      } else {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value?.byteLength) {
            if (task.received + value.byteLength > this.maxBytes) throw new Error('file exceeds the size limit');
            await sink.write(value);
            task.received += value.byteLength;
            task.updatedAt = this.clock();
            this._emit(task);
          }
        }
      }

      await sink.close();
      task.status = 'done';
      task.finishedAt = this.clock();
      task.updatedAt = task.finishedAt;
      try { task.sha256 = await sink.digest?.() || null; } catch { task.sha256 = null; }
      this._emit(task);
      return task;
    } catch (error) {
      const cancelled = controller.signal.aborted && /cancel/i.test(String(error?.message || ''));
      if (cancelled) {
        task.status = 'cancelled';
        try { await sink?.abort?.(); } catch { /* best effort */ }
      } else if (controller.signal.aborted) {
        task.status = 'paused';
        try { await sink?.close?.({ partial: true }); } catch { /* best effort */ }
      } else {
        task.status = 'failed';
        task.error = String(error?.message || error);
        try { await sink?.abort?.(); } catch { /* best effort */ }
      }
      task.updatedAt = this.clock();
      this._emit(task);
      return task;
    } finally {
      this._controllers.delete(id);
    }
  }

  /** Aborts an in-flight transfer but keeps the bytes so `start` can resume. */
  pause(id) {
    const task = this.tasks.get(id);
    if (!task || task.status !== 'downloading') return false;
    const controller = this._controllers.get(id);
    controller?.abort(new Error('aborted'));
    task.status = 'paused';
    task.updatedAt = this.clock();
    this._emit(task);
    return true;
  }
}

/** Convenience digest for a finished blob/file. */
export async function digestBlob(blob) {
  const buffer = new Uint8Array(await blob.arrayBuffer());
  return sha256Hex(buffer);
}

export default { PLATFORMS, parseMediaUrl, probeMedia, inspectRemote, DownloadQueue, availableFormats, mediaKind, extensionOf, digestBlob };
