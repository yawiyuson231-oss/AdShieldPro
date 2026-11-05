import type { AppConfig, Env } from '../env';
import { ApiError, notImplemented } from '../http';

/**
 * Storage provider abstraction.
 *
 * Two genuinely free-tier backends are supported today and the interface is small enough
 * that a third (B2, IPFS pinning, S3-compatible self-host) can be added without touching
 * the routes:
 *
 *   r2        Cloudflare R2  — 10 GB free, needs a payment method on file to activate
 *   supabase  Supabase Storage — 1 GB free, no payment method, 50 MB per-object ceiling
 *
 * Bytes always stream through the Worker so cloud credentials never reach the APK.
 */
export interface StoredObject {
  size: number;
  etag?: string;
  contentType?: string;
}

export interface MultipartPart {
  partNumber: number;
  etag: string;
  size: number;
}

export interface PartUploadResult {
  etag: string;
}

export interface StorageProvider {
  readonly name: 'r2' | 'supabase';
  /** Largest single request body accepted by this provider. */
  readonly maxObjectBytes: number;
  readonly supportsMultipart: boolean;
  readonly minimumPartSize: number;

  put(key: string, body: ReadableStream | ArrayBuffer, contentType: string, size?: number): Promise<StoredObject>;
  get(key: string, options?: { range?: { offset: number; length?: number } }): Promise<{ body: ReadableStream; size: number; contentType?: string; range?: { offset: number; length: number; total: number } } | null>;
  head(key: string): Promise<StoredObject | null>;
  delete(key: string): Promise<void>;
  copy(sourceKey: string, destinationKey: string): Promise<StoredObject>;
  readHead(key: string, byteCount: number): Promise<Uint8Array>;

  createMultipart(key: string, contentType: string): Promise<string>;
  uploadPart(key: string, uploadId: string, partNumber: number, body: ArrayBuffer): Promise<PartUploadResult>;
  completeMultipart(key: string, uploadId: string, parts: MultipartPart[]): Promise<StoredObject>;
  abortMultipart(key: string, uploadId: string): Promise<void>;
}

export function storageFor(env: Env, config: AppConfig): StorageProvider {
  if (config.storageProvider === 'supabase') {
    if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
      throw new ApiError(503, 'storage_unavailable', 'Supabase Storage is not configured on this deployment');
    }
    return new SupabaseStorageProvider(
      env.SUPABASE_URL,
      env.SUPABASE_SERVICE_ROLE_KEY,
      env.SUPABASE_STORAGE_BUCKET ?? 'adshield-cloud-files'
    );
  }
  if (!env.BUCKET) {
    throw new ApiError(503, 'storage_unavailable', 'R2 bucket binding is not configured on this deployment');
  }
  return new R2StorageProvider(env.BUCKET);
}

/** Workers Free refuses request bodies over 100 MB; keep a safety margin. */
export const WORKER_BODY_LIMIT = 100 * 1024 * 1024;

class R2StorageProvider implements StorageProvider {
  readonly name = 'r2' as const;
  readonly maxObjectBytes = WORKER_BODY_LIMIT;
  readonly supportsMultipart = true;
  readonly minimumPartSize = 5 * 1024 * 1024; // R2 requires >= 5 MiB for non-final parts

  constructor(private readonly bucket: R2Bucket) {}

  async put(key: string, body: ReadableStream | ArrayBuffer, contentType: string, size?: number): Promise<StoredObject> {
    const object = await this.bucket.put(key, body as ReadableStream | ArrayBuffer, {
      httpMetadata: { contentType },
      ...(size ? { customMetadata: { declaredSize: String(size) } } : {}),
    });
    return { size: object.size, etag: object.etag, contentType };
  }

  async get(key: string, options?: { range?: { offset: number; length?: number } }) {
    const object = await this.bucket.get(key, options?.range ? { range: options.range } : undefined);
    if (!object) return null;
    const rangeHeader = object.range;
    const range =
      rangeHeader && 'offset' in rangeHeader
        ? {
            offset: rangeHeader.offset ?? 0,
            length: rangeHeader.length ?? object.size - (rangeHeader.offset ?? 0),
            total: object.size,
          }
        : undefined;
    return {
      body: object.body as ReadableStream,
      size: object.size,
      contentType: object.httpMetadata?.contentType,
      range,
    };
  }

  async head(key: string): Promise<StoredObject | null> {
    const object = await this.bucket.head(key);
    if (!object) return null;
    return { size: object.size, etag: object.etag, contentType: object.httpMetadata?.contentType };
  }

  async delete(key: string): Promise<void> {
    await this.bucket.delete(key);
  }

  async copy(sourceKey: string, destinationKey: string): Promise<StoredObject> {
    const source = await this.bucket.get(sourceKey);
    if (!source) throw new ApiError(404, 'object_missing', 'The stored object is missing from the bucket');
    const body = await source.arrayBuffer();
    return this.put(destinationKey, body, source.httpMetadata?.contentType ?? 'application/octet-stream', body.byteLength);
  }

  async readHead(key: string, byteCount: number): Promise<Uint8Array> {
    const object = await this.bucket.get(key, { range: { offset: 0, length: byteCount } });
    if (!object) throw new ApiError(404, 'object_missing', 'The stored object is missing from the bucket');
    return new Uint8Array(await object.arrayBuffer());
  }

  async createMultipart(key: string, contentType: string): Promise<string> {
    const upload = await this.bucket.createMultipartUpload(key, { httpMetadata: { contentType } });
    return upload.uploadId;
  }

  async uploadPart(key: string, uploadId: string, partNumber: number, body: ArrayBuffer): Promise<PartUploadResult> {
    const upload = this.bucket.resumeMultipartUpload(key, uploadId);
    const part = await upload.uploadPart(partNumber, body);
    return { etag: part.etag };
  }

  async completeMultipart(key: string, uploadId: string, parts: MultipartPart[]): Promise<StoredObject> {
    const upload = this.bucket.resumeMultipartUpload(key, uploadId);
    const object = await upload.complete(
      parts
        .slice()
        .sort((a, b) => a.partNumber - b.partNumber)
        .map((part) => ({ partNumber: part.partNumber, etag: part.etag }))
    );
    return { size: object.size, etag: object.etag };
  }

  async abortMultipart(key: string, uploadId: string): Promise<void> {
    const upload = this.bucket.resumeMultipartUpload(key, uploadId);
    await upload.abort();
  }

}

/**
 * Supabase Storage over its REST API using the service-role key (server-side only).
 * Supabase Storage has no server-side multipart composition and the free tier caps
 * individual objects, so multipart uploads are rejected with a clear message.
 */
class SupabaseStorageProvider implements StorageProvider {
  readonly name = 'supabase' as const;
  readonly maxObjectBytes = 50 * 1024 * 1024;
  readonly supportsMultipart = false;
  readonly minimumPartSize = 0;

  constructor(
    private readonly baseUrl: string,
    private readonly serviceKey: string,
    private readonly bucket: string
  ) {}

  private url(path: string): string {
    return `${this.baseUrl.replace(/\/$/, '')}/storage/v1/object/${this.bucket}/${encodeURI(path)}`;
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    return {
      Authorization: `Bearer ${this.serviceKey}`,
      apikey: this.serviceKey,
      ...extra,
    };
  }

  async put(key: string, body: ReadableStream | ArrayBuffer, contentType: string): Promise<StoredObject> {
    const payload = body instanceof ArrayBuffer ? body : await new Response(body).arrayBuffer();
    if (payload.byteLength > this.maxObjectBytes) {
      throw new ApiError(413, 'provider_object_limit', `Supabase Storage accepts at most ${this.maxObjectBytes} bytes per object`);
    }
    const response = await fetch(this.url(key), {
      method: 'POST',
      headers: this.headers({ 'Content-Type': contentType, 'x-upsert': 'true', 'Cache-Control': 'max-age=3600' }),
      body: payload,
    });
    if (!response.ok) {
      throw new ApiError(502, 'storage_write_failed', `Storage provider rejected the write (${response.status})`);
    }
    return { size: payload.byteLength, etag: undefined, contentType };
  }

  async get(key: string, options?: { range?: { offset: number; length?: number } }) {
    const headers = this.headers();
    if (options?.range) {
      const end = options.range.length ? options.range.offset + options.range.length - 1 : '';
      headers.Range = `bytes=${options.range.offset}-${end}`;
    }
    const response = await fetch(this.url(key), { headers });
    if (response.status === 404) return null;
    if (!response.ok && response.status !== 206) {
      throw new ApiError(502, 'storage_read_failed', `Storage provider read failed (${response.status})`);
    }
    const total = Number(response.headers.get('content-length') ?? 0);
    return { body: response.body as ReadableStream, size: total, contentType: response.headers.get('content-type') ?? undefined };
  }

  async head(key: string): Promise<StoredObject | null> {
    const response = await fetch(this.url(key), { method: 'HEAD', headers: this.headers() });
    if (!response.ok) return null;
    return { size: Number(response.headers.get('content-length') ?? 0), contentType: response.headers.get('content-type') ?? undefined };
  }

  async delete(key: string): Promise<void> {
    await fetch(this.url(key), { method: 'DELETE', headers: this.headers() });
  }

  async copy(sourceKey: string, destinationKey: string): Promise<StoredObject> {
    const source = await this.get(sourceKey);
    if (!source) throw new ApiError(404, 'object_missing', 'The stored object is missing from the bucket');
    const bytes = await new Response(source.body).arrayBuffer();
    return this.put(destinationKey, bytes, source.contentType ?? 'application/octet-stream');
  }

  async readHead(key: string, byteCount: number): Promise<Uint8Array> {
    const object = await this.get(key, { range: { offset: 0, length: byteCount } });
    if (!object) throw new ApiError(404, 'object_missing', 'The stored object is missing from the bucket');
    return new Uint8Array(await new Response(object.body).arrayBuffer());
  }

  async createMultipart(): Promise<string> {
    throw notImplemented('Large multipart uploads require the R2 provider. Supabase Storage allows at most 50 MB per file on the free tier.');
  }

  async uploadPart(): Promise<PartUploadResult> {
    throw notImplemented('Multipart parts require the R2 provider');
  }

  async completeMultipart(): Promise<StoredObject> {
    throw notImplemented('Multipart uploads require the R2 provider');
  }

  async abortMultipart(): Promise<void> {
    /* nothing to abort */
  }

}
