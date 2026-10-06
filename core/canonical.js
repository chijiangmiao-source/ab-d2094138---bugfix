// Canonical encoding and hashing primitives shared by the browser page,
// the rule tests and the recovery drills.
//
// Canonical form of a segment (hashed as UTF-8 bytes):
//
//   <prevDigestHex>\n
//   <seq>|<payload>\n
//   <seq>|<payload>\n
//   ...
//
// The first line binds the segment to its predecessor digest; every
// following line is one event. The event payload is hashed as its literal
// UTF-8 bytes — fullwidth vs halfwidth letters, combining vs precomposed
// sequences, CRLF vs LF line endings and trailing blanks are all distinct
// sealing identities. Events themselves are hashed without the predecessor
// line to obtain the batch content hash used for idempotency.
//
// Hash formats:
//   review-text-v2 (current): payload bytes are hashed verbatim.
//   review-text-v1 (legacy):  payloads were NFKC-normalized, line endings
//     folded and trailing blanks trimmed before hashing. Kept only so
//     segments sealed by earlier builds remain verifiable on reopen; it
//     must never be used to seal new batches.

export const GENESIS_DIGEST = "0".repeat(64);
export const HASH_FORMAT = "review-text-v2";
export const LEGACY_HASH_FORMAT = "review-text-v1";

const KNOWN_FORMATS = new Set([HASH_FORMAT, LEGACY_HASH_FORMAT]);

export function isKnownHashFormat(format) {
  return KNOWN_FORMATS.has(format);
}

const encoder = new TextEncoder();

export function utf8Bytes(text) {
  return encoder.encode(text);
}

// Legacy v1 payload treatment. Do not use for new seals — it folds together
// payloads whose UTF-8 bytes differ (fullwidth/halfwidth, combining vs
// precomposed characters, line endings, trailing whitespace).
function legacyReviewText(payload) {
  let normalized = payload.normalize("NFKC");
  normalized = normalized.replaceAll("\r\n", "\n");
  normalized = normalized.replaceAll("\r", "\n");
  normalized = normalized.replaceAll("\u2028", "\n");
  normalized = normalized.replaceAll("\u2029", "\n");

  const lines = normalized.split("\n");
  const trimmedLines = lines.map((line) => line.replace(/[ \t]+$/g, ""));
  return trimmedLines.join("\n");
}

function assertKnownFormat(format) {
  if (!KNOWN_FORMATS.has(format)) {
    throw new Error(`unknown hash format: ${String(format)}`);
  }
}

function payloadForHash(payload, format) {
  return format === LEGACY_HASH_FORMAT ? legacyReviewText(payload) : payload;
}

export function canonicalEventLine(event, format = HASH_FORMAT) {
  assertKnownFormat(format);
  return `${event.seq}|${payloadForHash(event.payload, format)}`;
}

export function canonicalEventsText(events, format = HASH_FORMAT) {
  return events.map((event) => canonicalEventLine(event, format)).join("\n");
}

export function canonicalSegmentText(prevDigest, events, format = HASH_FORMAT) {
  return `${prevDigest}\n${canonicalEventsText(events, format)}`;
}

function toHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", utf8Bytes(text));
  return toHex(digest);
}

// Hash of the event payload lines only — identifies "same content" for a
// batch regardless of where it lands in the chain.
export async function contentHashOf(events, format = HASH_FORMAT) {
  return sha256Hex(canonicalEventsText(events, format));
}

// Hash of predecessor digest + event lines — the segment digest.
export async function segmentDigestOf(prevDigest, events, format = HASH_FORMAT) {
  return sha256Hex(canonicalSegmentText(prevDigest, events, format));
}
