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

export const GENESIS_DIGEST = "0".repeat(64);
export const HASH_FORMAT = "review-text-v1";

const encoder = new TextEncoder();

export function utf8Bytes(text) {
  return encoder.encode(text);
}

function reviewText(payload) {
  let normalized = payload.normalize("NFKC");
  normalized = normalized.replaceAll("\r\n", "\n");
  normalized = normalized.replaceAll("\r", "\n");
  normalized = normalized.replaceAll("\u2028", "\n");
  normalized = normalized.replaceAll("\u2029", "\n");

  const lines = normalized.split("\n");
  const trimmedLines = lines.map((line) => line.replace(/[ \t]+$/g, ""));
  return trimmedLines.join("\n");
}

export function canonicalEventLine(event) {
  return `${event.seq}|${reviewText(event.payload)}`;
}

export function canonicalEventsText(events) {
  return events.map(canonicalEventLine).join("\n");
}

export function canonicalSegmentText(prevDigest, events) {
  return `${prevDigest}\n${canonicalEventsText(events)}`;
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
export async function contentHashOf(events) {
  return sha256Hex(canonicalEventsText(events));
}

// Hash of predecessor digest + event lines — the segment digest.
export async function segmentDigestOf(prevDigest, events) {
  return sha256Hex(canonicalSegmentText(prevDigest, events));
}
