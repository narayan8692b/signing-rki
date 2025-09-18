export interface Env {
  EDGE_SIGNING_KEY: string;   // Secret binding (required)
  ORIGIN_URL: string;         // Origin target (IP allowed)
  ORIGIN_HOST: string;        // Host header to send
  NONCE_CACHE?: KVNamespace;  // KV binding (optional)
}

const MAX_BODY_BYTES = 512 * 1024; // 512 KB
const MAX_SKEW_SECONDS = 60;       // clock skew tolerance
const ALLOWED_CONTENT_TYPES = new Set([
  "application/json",
  "application/cbor", // optional
]);

function bad(status: number, message: string, meta: Record<string, unknown> = {}): Response {
  console.warn("[EDGE-BLOCK]", { status, message, ...meta });
  return new Response(JSON.stringify({ error: "edge_policy", message }), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function getHeader(headers: Headers, name: string): string {
  const v = headers.get(name);
  return v ? v.trim() : "";
}

function isValidJwtShape(token: string): boolean {
  const parts = token.split(".");
  return parts.length === 3 && parts.every((p) => p.length > 0);
}

// --- Helpers ---
async function sha256Base64Url(ab: ArrayBuffer): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", ab);
  return base64UrlEncode(d);
}

function base64UrlEncode(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const { EDGE_SIGNING_KEY, ORIGIN_URL, ORIGIN_HOST, NONCE_CACHE } = env;

    // --- TLS & protocol hygiene ---
    const cf: IncomingRequestCfProperties = (request as any).cf || {};
    if (!cf.tlsVersion || ["TLSv1.0", "TLSv1.1"].includes(cf.tlsVersion)) {
      return bad(403, "Weak TLS");
    }
    const xfp = getHeader(request.headers, "X-Forwarded-Proto");
    if (xfp && xfp.toLowerCase() !== "https") {
      return bad(400, "HTTPS required");
    }

    // --- Basic method/path ACL ---
    const url = new URL(request.url);
    const method = request.method.toUpperCase();
    if (url.pathname.startsWith("/status") && method !== "GET") {
      return bad(405, "Method not allowed for status");
    }

    // --- Content-Type & length checks ---
    let bodyBuf: ArrayBuffer | undefined;
    if (!["GET", "HEAD"].includes(method)) {
      const ct = getHeader(request.headers, "Content-Type").toLowerCase().split(";")[0];
      if (!ALLOWED_CONTENT_TYPES.has(ct)) {
        return bad(415, "Unsupported Content-Type", { ct });
      }
      const len = Number(getHeader(request.headers, "Content-Length") || "0");
      if (len > MAX_BODY_BYTES) {
        return bad(413, "Payload too large", { len });
      }
      bodyBuf = await request.arrayBuffer();
      if (bodyBuf.byteLength > MAX_BODY_BYTES) {
        return bad(413, "Payload too large (chunked)");
      }
    }

    // --- Client headers ---
    const terminalId = getHeader(request.headers, "X-Terminal-Id");
    const reqTsStr = getHeader(request.headers, "X-Req-Timestamp");
    const nonce = getHeader(request.headers, "X-Device-Nonce");
    const bodyHash = getHeader(request.headers, "X-Body-SHA256");
    const bodyHmacHeader = getHeader(request.headers, "X-Body-HMAC");

    if (!terminalId) return bad(400, "Missing X-Terminal-Id");
    if (!reqTsStr || !/^\d+$/.test(reqTsStr)) return bad(400, "Missing/invalid X-Req-Timestamp");

    const now = Math.floor(Date.now() / 1000);
    const reqTs = Number(reqTsStr);
    if (Math.abs(now - reqTs) > MAX_SKEW_SECONDS) {
      return bad(401, "Clock skew too large", { now, reqTs });
    }

    if (!nonce || nonce.length < 16) return bad(400, "Missing/short X-Device-Nonce");

    // Anti-replay (KV set-if-absent with TTL)
    if (NONCE_CACHE) {
      const kvKey = `nonce:${terminalId}:${nonce}`;
      const existed = await NONCE_CACHE.get(kvKey);
      if (existed) return bad(409, "Replay detected");
      await NONCE_CACHE.put(kvKey, "1", { expirationTtl: 300 });
    }

    // --- Body integrity (SHA-256) ---
    if (bodyBuf && bodyBuf.byteLength > 0) {
      const calcHash = await sha256Base64Url(bodyBuf);
      if (!bodyHash || calcHash !== bodyHash) {
        return bad(400, "Body hash mismatch", { calcHash, bodyHash });
      }
    } else if (bodyHash) {
      return bad(400, "Unexpected X-Body-SHA256 without body");
    }

    // --- HMAC authenticity ---
    if (bodyBuf && bodyBuf.byteLength > 0) {
      if (!bodyHmacHeader) {
        return bad(400, "Missing X-Body-HMAC");
      }
      const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(EDGE_SIGNING_KEY),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, bodyBuf);
      const computedHmac = base64UrlEncode(sig);
      if (!safeEqual(computedHmac, bodyHmacHeader)) {
        return bad(401, "Invalid body HMAC", { computedHmac, bodyHmacHeader });
      }
    } else if (bodyHmacHeader) {
      return bad(400, "Unexpected X-Body-HMAC without body");
    }

    // --- Attestation / app integrity ---
    const appIntegrity = getHeader(request.headers, "X-App-Integrity");
    if (!appIntegrity || appIntegrity.split(".").length !== 3) {
      return bad(401, "Missing/invalid X-App-Integrity");
    }

    // Cheap JWT shape pre-check
    const auth = getHeader(request.headers, "Authorization");
    if (!auth.startsWith("Bearer ")) return bad(401, "Missing Bearer token");
    const jwt = auth.slice(7);
    if (!isValidJwtShape(jwt)) return bad(401, "Malformed JWT");

    // --- Edge assertion ---
    const country = (cf.country || "").toUpperCase();
    const asn = Number(cf.asn || 0);
    const clientIp = getHeader(request.headers, "CF-Connecting-IP") || "0.0.0.0";
    const colo = cf.colo || "UNKNOWN";

    const pathWithQuery = url.pathname + (url.search || "");
    const edgeAssertedAt = now.toString();

    const assertion = [
      edgeAssertedAt,
      method,
      pathWithQuery,
      country,
      String(asn),
      clientIp,
      colo,
      terminalId,
      bodyHash || "",
    ].join("|");

    // --- Forward to origin ---
    const fwdHeaders = new Headers(request.headers);
    fwdHeaders.set("X-Edge-Country", country);
    fwdHeaders.set("X-Edge-ASN", String(asn));
    fwdHeaders.set("X-Edge-IP", clientIp);
    fwdHeaders.set("X-Edge-Colo", colo);
    fwdHeaders.set("X-Edge-Asserted-At", edgeAssertedAt);
    fwdHeaders.set("X-Edge-Assertion", assertion);

    // Force Host header from env (important when ORIGIN_URL is an IP)
    fwdHeaders.set("Host", ORIGIN_HOST);

    // Strip hop-by-hop headers
    ["Forwarded", "X-Forwarded-Host", "Te", "Trailer", "Transfer-Encoding"].forEach((h) =>
      fwdHeaders.delete(h)
    );

    const originUrl = new URL(request.url);
    const origin = new URL(ORIGIN_URL);
    originUrl.hostname = origin.hostname;
    originUrl.protocol = origin.protocol;
    originUrl.port = origin.port;

    const reqToOrigin = new Request(originUrl.toString(), {
      method,
      headers: fwdHeaders,
      body: ["GET", "HEAD"].includes(method) ? undefined : bodyBuf,
      redirect: "manual",
    });

    const resp = await fetch(reqToOrigin, { cf: { cacheEverything: false } });
    const out = new Headers(resp.headers);
    out.delete("Server");
    out.set("X-Edge-Decision", "extended_validations_passed");

    return new Response(resp.body, {
      status: resp.status,
      statusText: resp.statusText,
      headers: out,
    });
  },
};
