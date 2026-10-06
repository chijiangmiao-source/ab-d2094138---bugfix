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
// following line is one event. Events themselves are hashed without the
// predecessor line to obtain the batch content hash used for idempotency.
//
// Hash formats:
//   review-text-v2 (current) — the payload is hashed exactly as submitted:
//     its actual characters, and therefore its actual UTF-8 bytes, are the
//     sealed identity. Full-width vs half-width letters, combining vs
//     precomposed characters, newline conventions and trailing whitespace
//     all produce distinct identities.
//   review-text-v1 (legacy)  — payloads were normalized before hashing
//     (NFKC, newline unification, trailing-whitespace stripping), so
//     look-alike texts collapsed onto one identity and a different-form
//     retransmission was mistaken for the original. Kept solely to
//     re-verify records persisted before the byte-exact rule; never used
//     for new records. Records carry their hashFormat; an untagged record
//     predates format tagging and is verified under the legacy rules it
//     was written with.

export const GENESIS_DIGEST = "0".repeat(64);
export const HASH_FORMAT = "review-text-v2";
export const LEGACY_HASH_FORMAT = "review-text-v1";

const encoder = new TextEncoder();

export function utf8Bytes(text) {
  return encoder.encode(text);
}

// Legacy v1 review text. The normalization made visually similar payloads
// hash identically — the defect that let a different-form retransmission
// return the original receipt. Retained only for verifying old records.
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

// Current v2 review text: the payload exactly as submitted, untouched.
function verbatimReviewText(payload) {
  return payload;
}

const REVIEW_TEXT_BY_FORMAT = new Map([
  [HASH_FORMAT, verbatimReviewText],
  [LEGACY_HASH_FORMAT, legacyReviewText],
]);

// Records persisted before hash formats were tagged must be verified under
// the legacy rules they were written with, so an untagged record resolves
// to the legacy format.
export function resolveRecordFormat(hashFormat) {
  return hashFormat ?? LEGACY_HASH_FORMAT;
}

export function isKnownHashFormat(hashFormat) {
  return REVIEW_TEXT_BY_FORMAT.has(hashFormat);
}

function reviewTextFor(hashFormat) {
  const reviewText = REVIEW_TEXT_BY_FORMAT.get(hashFormat);
  if (!reviewText) {
    throw new TypeError(`unknown hash format: ${hashFormat}`);
  }
  return reviewText;
}

export function canonicalEventLine(event, hashFormat = HASH_FORMAT) {
  return `${event.seq}|${reviewTextFor(hashFormat)(event.payload)}`;
}

export function canonicalEventsText(events, hashFormat = HASH_FORMAT) {
  return events
    .map((event) => canonicalEventLine(event, hashFormat))
    .join("\n");
}

export function canonicalSegmentText(
  prevDigest,
  events,
  hashFormat = HASH_FORMAT
) {
  return `${prevDigest}\n${canonicalEventsText(events, hashFormat)}`;
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
export async function contentHashOf(events, hashFormat = HASH_FORMAT) {
  return sha256Hex(canonicalEventsText(events, hashFormat));
}

// Hash of predecessor digest + event lines — the segment digest.
export async function segmentDigestOf(
  prevDigest,
  events,
  hashFormat = HASH_FORMAT
) {
  return sha256Hex(canonicalSegmentText(prevDigest, events, hashFormat));
}
