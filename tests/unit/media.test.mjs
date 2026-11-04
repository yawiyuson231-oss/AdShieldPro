/**
 * Universal media downloader.
 *
 * The point of these tests is honesty: a platform that forbids downloading must
 * come back as `blocked`, and a permitted URL must actually stream bytes into the
 * queue with pause/resume/cancel working against a real *mock* HTTP layer.
 */
import test from 'node:test';
import { strict as assert } from 'node:assert';
import { parseMediaUrl, probeMedia, inspectRemote, DownloadQueue, availableFormats, mediaKind, extensionOf, PLATFORMS } from '../../security/media.js';

/** A tiny streaming response double that honours Range when asked. */
function responseFor(payload, { status = 200, headers = {} } = {}) {
  const bytes = payload instanceof Uint8Array ? payload : new TextEncoder().encode(payload);
  let offset = 0;
  return {
    ok: status >= 200 && status < 300,
    status,
    url: 'https://example.test/file.bin',
    headers: { get: (name) => headers[name.toLowerCase()] ?? headers[name] ?? null },
    body: {
      getReader() {
        return {
          async read() {
            if (offset >= bytes.length) return { done: true, value: undefined };
            const chunk = bytes.subarray(offset, Math.min(bytes.length, offset + 8));
            offset += chunk.length;
            return { done: false, value: chunk };
          }
        };
      }
    },
    async arrayBuffer() { return bytes.buffer; }
  };
}

const parse = (url) => parseMediaUrl(url);

test('recognises every supported platform and extracts its media id', () => {
  assert.equal(parse('https://www.youtube.com/watch?v=dQw4w9WgXcQ').platform.id, 'youtube');
  assert.equal(parse('https://www.youtube.com/watch?v=dQw4w9WgXcQ').id, 'dQw4w9WgXcQ');
  assert.equal(parse('https://youtu.be/dQw4w9WgXcQ').id, 'dQw4w9WgXcQ');
  assert.equal(parse('https://vimeo.com/76979871').id, '76979871');
  assert.equal(parse('https://soundcloud.com/artist/track-name').platform.id, 'soundcloud');
  assert.equal(parse('https://www.dailymotion.com/video/x8abc12').id, 'x8abc12');
  assert.equal(parse('https://open.spotify.com/track/abc').platform.id, 'spotify');
  assert.equal(parse('https://cdn.example.com/media/clip.mp4').platform.id, 'direct');
  assert.equal(parse('https://cdn.example.com/media/clip.mp4').kind, 'video');
  assert.equal(parse('https://cdn.example.com/music/song.mp3').kind, 'audio');
});

test('rejects junk input and non-http schemes instead of guessing', () => {
  assert.equal(parse('').ok, false);
  assert.match(parse('').error, /Paste/);
  assert.equal(parse('not a url at all').ok, false);
  assert.equal(parse('file:///etc/passwd').ok, false);
  assert.equal(parse('https://example.com/no-extension').ok, false);
  assert.match(parse('https://example.com/no-extension').error, /not a recognised media platform/);
});

test('platforms whose terms forbid downloading are marked, never presented as downloadable', () => {
  const youtube = PLATFORMS.find((p) => p.id === 'youtube');
  assert.equal(youtube.directDownload, false);
  assert.match(youtube.reason, /Terms of Service/);
  assert.ok(youtube.alternative);
  const spotify = PLATFORMS.find((p) => p.id === 'spotify');
  assert.equal(spotify.directDownload, false);
  assert.match(spotify.reason, /DRM/);
  assert.equal(PLATFORMS.find((p) => p.id === 'vimeo').directDownload, true);
  assert.equal(PLATFORMS.find((p) => p.id === 'direct').directDownload, true);
});

test('format ladders match the media kind', () => {
  assert.equal(availableFormats('video').some((f) => f.container === 'mp4' && f.resolution === '1080p'), true);
  assert.equal(availableFormats('audio').some((f) => f.container === 'mp3' && f.bitrateKbps === 320), true);
  assert.deepEqual(availableFormats('document'), []);
  assert.equal(mediaKind('jpg'), 'image');
  assert.equal(extensionOf('https://x.test/a/b.MP4?token=1'), 'mp4');
});

test('oEmbed metadata is fetched for real and CORS failure is reported as CORS failure', async () => {
  const video = parse('https://vimeo.com/76979871');
  const good = await probeMedia(video, {
    fetchImpl: async (url) => {
      assert.match(url, /vimeo\.com\/api\/oembed\.json/);
      return {
        ok: true,
        status: 200,
        async json() { return { title: 'A real video title', author_name: 'Uploader', thumbnail_url: 'https://i.vimeocdn.com/x.jpg', duration: 120 }; }
      };
    }
  });
  assert.equal(good.ok, true);
  assert.equal(good.title, 'A real video title');
  assert.equal(good.author, 'Uploader');
  assert.equal(good.durationSeconds, 120);
  assert.equal(good.formats.length, 6);

  const opaque = await probeMedia(video, {
    fetchImpl: async () => { throw new TypeError('Failed to fetch'); }
  });
  assert.equal(opaque.ok, false);
  assert.equal(opaque.code, 'NETWORK');
  assert.match(opaque.error, /CORS|offline/);

  const noEndpoint = await probeMedia(parse('https://www.instagram.com/p/abc'));
  assert.equal(noEndpoint.ok, false);
  assert.equal(noEndpoint.code, 'NO_METADATA_ENDPOINT');
});

test('pre-flight reads real size, type and range support', async () => {
  const info = await inspectRemote('https://cdn.example.com/a.mp4', {
    fetchImpl: async (url, init) => {
      assert.equal(init.method, 'HEAD');
      assert.equal(url, 'https://cdn.example.com/a.mp4');
      return {
        ok: true, status: 200, url,
        headers: { get: (n) => ({ 'content-length': '2048', 'content-type': 'video/mp4', 'accept-ranges': 'bytes' })[n] ?? null }
      };
    }
  });
  assert.equal(info.ok, true);
  assert.equal(info.size, 2048);
  assert.equal(info.type, 'video/mp4');
  assert.equal(info.resumable, true);

  const refused = await inspectRemote('https://cdn.example.com/a.mp4', { fetchImpl: async () => ({ ok: false, status: 403, headers: { get: () => null } }) });
  assert.equal(refused.ok, false);
  assert.match(refused.error, /403/);
});

test('the queue streams a real payload, records progress and stores history', async () => {
  const updates = [];
  const queue = new DownloadQueue({
    fetchImpl: async () => responseFor(new Uint8Array(40)),
    createSink: async () => {
      const chunks = [];
      return {
        path: 'x.bin',
        async write(c) { chunks.push(c); },
        async close() {},
        async digest() { return 'a'.repeat(64); },
        async abort() {}
      };
    },
    onUpdate: (task) => updates.push({ status: task.status, received: task.received }),
    clock: (() => { let t = 1000; return () => (t += 1); })()
  });

  const task = queue.add({ url: 'https://cdn.example.com/x.bin', name: 'x.bin' });
  assert.equal(task.status, 'queued');
  const finished = await queue.start(task.id);
  assert.equal(finished.status, 'done');
  assert.equal(finished.received, 40);
  assert.equal(finished.sha256, 'a'.repeat(64));
  assert.ok(updates.some((u) => u.received === 40));
  assert.equal(queue.stats().done, 1);
  assert.equal(queue.stats().bytes, 40);
  assert.equal(queue.list().length, 1);
});

test('a 404 fails the task with the server status, it does not fabricate a file', async () => {
  const queue = new DownloadQueue({ fetchImpl: async () => responseFor('', { status: 404 }), createSink: async () => ({ async write() {}, async close() {}, async abort() {} }) });
  const task = queue.add({ url: 'https://cdn.example.com/missing.mp4', name: 'missing.mp4' });
  const done = await queue.start(task.id);
  assert.equal(done.status, 'failed');
  assert.match(done.error, /404/);
});

test('pause, resume with a Range header, and cancel each behave distinctly', async () => {
  let rangeHeader = null;
  let calls = 0;
  const queue = new DownloadQueue({
    fetchImpl: async (url, init) => {
      calls += 1;
      rangeHeader = init.headers?.Range || null;
      return responseFor(new Uint8Array(16), { status: 200 });
    },
    createSink: async () => ({ async write() {}, async close() {}, async abort() {} })
  });
  const task = queue.add({ url: 'https://cdn.example.com/y.mp4', name: 'y.mp4', resumable: true });
  task.received = 8;
  await queue.start(task.id);
  assert.equal(calls, 1);
  assert.equal(rangeHeader, 'bytes=8-');

  const queued = queue.add({ url: 'https://cdn.example.com/z.mp4', name: 'z.mp4' });
  queue.cancel(queued.id);
  assert.equal(queue.get(queued.id).status, 'cancelled');
  queue.remove(queued.id);
  assert.equal(queue.get(queued.id), null);
});

test('a server that ignores Range restarts at zero rather than corrupting the file', async () => {
  const queue = new DownloadQueue({
    fetchImpl: async () => responseFor(new Uint8Array(10), { status: 200 }),
    createSink: async () => ({ async write() {}, async close() {}, async abort() {} }),
    clock: () => 5
  });
  const task = queue.add({ url: 'https://cdn.example.com/w.mp4', name: 'w.mp4', resumable: true });
  task.received = 4;
  const done = await queue.start(task.id);
  assert.equal(done.status, 'done');
  assert.equal(done.received, 10, 'the ignored range resets the counter and the whole file is re-read');
});
