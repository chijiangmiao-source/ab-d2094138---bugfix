// Payload-identity acceptance tests.
//
// The sealed identity of an event payload is its literal UTF-8 byte
// content. Only a byte-identical retransmission may return the first
// receipt; anything visually similar but encoded differently — fullwidth
// vs halfwidth letters, combining vs precomposed characters, CRLF vs LF,
// trailing blanks — must be reported as a conflict while the first
// evidence stays put. Also covers the afterSegment interrupt/recovery
// variant and segments persisted under the pre-fix (lossy) hash format.

import { SealEngine, CrashError } from "../../core/engine.js";
import {
  MemoryStorage,
  createMemoryBacking,
} from "../../core/memory-storage.js";
import {
  GENESIS_DIGEST,
  HASH_FORMAT,
  LEGACY_HASH_FORMAT,
  contentHashOf,
  segmentDigestOf,
} from "../../core/canonical.js";

async function reopen(backing) {
  const engine = new SealEngine(new MemoryStorage(backing));
  const { recovery, chain } = await engine.open();
  return { engine, recovery, chain };
}

async function sealFresh(batch) {
  const backing = createMemoryBacking();
  const engine = new SealEngine(new MemoryStorage(backing));
  await engine.open();
  const outcome = await engine.submit(batch);
  return { backing, engine, outcome };
}

// Submit `original` and a visually-similar `variant` under the same id,
// then assert the full conflict contract.
async function assertVariantConflict(t, label, original, variant) {
  const { backing, engine, outcome: first } = await sealFresh({
    batchId: "LOOKALIKE",
    events: [{ seq: 1, payload: original }],
  });
  t.assertEqual(first.status, "sealed", `${label}: first submit sealed`);

  const outcome = await engine.submit({
    batchId: "LOOKALIKE",
    events: [{ seq: 1, payload: variant }],
  });
  t.assertEqual(outcome.status, "conflict", `${label}: variant is a conflict`);
  t.assertEqual(
    outcome.conflict.reason,
    "published-content-mismatch",
    `${label}: conflict reason`
  );
  t.assertDeepEqual(
    outcome.conflict.existingReceipt,
    first.receipt,
    `${label}: conflict carries the original receipt`
  );
  t.assertEqual(
    outcome.conflict.existingContentHash,
    await contentHashOf([{ seq: 1, payload: original }], HASH_FORMAT),
    `${label}: existing hash is the raw-byte hash`
  );
  t.assertEqual(
    outcome.conflict.incomingContentHash,
    await contentHashOf([{ seq: 1, payload: variant }], HASH_FORMAT),
    `${label}: incoming hash is the raw-byte hash`
  );
  t.assert(
    outcome.conflict.incomingContentHash !== outcome.conflict.existingContentHash,
    `${label}: the two byte forms hash differently`
  );

  // First evidence is untouched: active chain, payload and receipt.
  const chain = await engine.sealedChain();
  t.assertEqual(chain.segments.length, 1, `${label}: no segment appended`);
  t.assertEqual(
    chain.segments[0].events[0].payload,
    original,
    `${label}: original payload bytes preserved`
  );
  t.assertEqual(
    chain.segments[0].receipt.digest,
    first.receipt.digest,
    `${label}: head still points at the original receipt`
  );

  const conflicts = await engine.conflicts();
  t.assertEqual(conflicts.length, 1, `${label}: exactly one conflict logged`);
  t.assertEqual(conflicts[0].batchId, "LOOKALIKE", `${label}: conflict batch id`);

  // A byte-exact retransmission still returns the same first receipt.
  const exact = await engine.submit({
    batchId: "LOOKALIKE",
    events: [{ seq: 1, payload: original }],
  });
  t.assertEqual(exact.status, "duplicate", `${label}: exact bytes still duplicate`);
  t.assertDeepEqual(
    exact.receipt,
    first.receipt,
    `${label}: exact bytes return the original receipt`
  );
  t.assertEqual(
    (await engine.sealedChain()).segments.length,
    1,
    `${label}: exact retransmission appends nothing`
  );

  // Reopen: the chain remains reviewable and the conflict never looks like
  // chain damage — the first blocking evidence slot stays empty.
  const reopened = await reopen(backing);
  t.assertEqual(
    reopened.chain.segments.length,
    1,
    `${label}: chain survives reopen intact`
  );
  t.assertEqual(
    reopened.chain.segments[0].digest,
    first.receipt.digest,
    `${label}: same head after reopen`
  );
  t.assertEqual(
    reopened.recovery.firstBlocking,
    null,
    `${label}: no blocking evidence — a conflict is not corruption`
  );
  t.assertEqual(
    (await reopened.engine.conflicts()).length,
    1,
    `${label}: conflict record survives reopen`
  );
}

export function registerIdentityTests(t) {
  t.test(
    "identity: byte-exact retransmission with sensitive bytes returns the original receipt only",
    async () => {
      const batch = {
        batchId: "EXACT-BYTES",
        events: [
          { seq: 1, payload: "姿态机动 ＴＥＬＥ Δv=0.3\r\nline two   " },
          { seq: 2, payload: "café ﬂight\t\t" },
          { seq: 4, payload: "trailing-blank-middle\nx  \ny" },
        ],
      };
      const { backing, engine, outcome: first } = await sealFresh(batch);
      t.assertEqual(first.status, "sealed");
      const chainBefore = await engine.sealedChain();

      const again = await engine.submit(batch);
      t.assertEqual(again.status, "duplicate");
      t.assertDeepEqual(again.receipt, first.receipt);

      const chainAfter = await engine.sealedChain();
      t.assertEqual(chainAfter.segments.length, 1);
      t.assertEqual(chainAfter.version, chainBefore.version);
      t.assertEqual(chainAfter.head, first.receipt.digest);
      t.assertEqual(chainAfter.segments[0].prevDigest, GENESIS_DIGEST);
      t.assertEqual(chainAfter.segments[0].seqStart, 1);
      t.assertEqual(chainAfter.segments[0].seqEnd, 4);
      t.assertEqual(
        chainAfter.segments[0].events[0].payload,
        batch.events[0].payload,
        "CRLF and trailing spaces survive in the sealed bytes"
      );

      // Reopen: an exact retransmission must leave no recovery trace and
      // must not append a segment or change the seq range / predecessor.
      const reopened = await reopen(backing);
      t.assertEqual(reopened.chain.segments.length, 1);
      t.assertEqual(reopened.chain.head, first.receipt.digest);
      t.assertEqual(reopened.chain.segments[0].seqStart, 1);
      t.assertEqual(reopened.chain.segments[0].seqEnd, 4);
      t.assertEqual(reopened.chain.segments[0].prevDigest, GENESIS_DIGEST);
      t.assertEqual(reopened.recovery.actions.length, 0);
      t.assertEqual(reopened.recovery.firstBlocking, null);

      const duplicateAfterReopen = await reopened.engine.submit(batch);
      t.assertEqual(duplicateAfterReopen.status, "duplicate");
      t.assertDeepEqual(duplicateAfterReopen.receipt, first.receipt);
      t.assertEqual((await reopened.engine.sealedChain()).segments.length, 1);
    }
  );

  t.test("identity: fullwidth vs halfwidth letters conflict", async () => {
    await assertVariantConflict(
      t,
      "fullwidth",
      "ＡＢＣ－１２３ ｔｅｌｅ",
      "ABC-123 tele"
    );
  });

  t.test("identity: combining vs precomposed characters conflict", async () => {
    // "e" followed by a combining acute vs the single precomposed code point.
    const combining = "cafe\u0301 detour";
    const precomposed = "caf\u00e9 detour";
    t.assert(combining !== precomposed, "fixture payloads must differ");
    t.assertEqual(
      combining.normalize("NFC"),
      precomposed,
      "fixture payloads must be NFC-equivalent (visually identical)"
    );
    await assertVariantConflict(t, "combining", precomposed, combining);

    // A second, independent combining pair over an accented capital.
    const nfd = "Ångström".normalize("NFD");
    const nfc = "Ångström".normalize("NFC");
    t.assert(nfd !== nfc, "fixture normalization forms must differ");
    await assertVariantConflict(t, "nfc-nfd", nfc, nfd);
  });

  t.test("identity: newline form differences conflict", async () => {
    await assertVariantConflict(t, "crlf", "line1\r\nline2", "line1\nline2");
    await assertVariantConflict(t, "cr", "line1\rline2", "line1\nline2");
    await assertVariantConflict(
      t,
      "line-separator",
      "line1\u2028line2",
      "line1\nline2"
    );
  });

  t.test("identity: trailing whitespace differences conflict", async () => {
    await assertVariantConflict(t, "trail-spaces", "hello   ", "hello");
    await assertVariantConflict(t, "trail-tabs", "hello\t\t", "hello");
    await assertVariantConflict(t, "trail-blank-middle-line", "a   \nb", "a\nb");
    await assertVariantConflict(t, "trail-blank-last", "a\nb\t", "a\nb");
  });

  t.test(
    "identity: afterSegment crash, reopen, then exact vs lookalike resubmission",
    async () => {
      const backing = createMemoryBacking();
      const original = {
        batchId: "CRASH-BYTES",
        events: [
          { seq: 10, payload: "ＴＥＬＥ\r\nreadout 0.3   " },
          { seq: 11, payload: "caf\u00e9" },
        ],
      };

      const drill = new SealEngine(new MemoryStorage(backing), {
        failpoints: { afterSegment: true },
      });
      await drill.open();
      let crashed = null;
      try {
        await drill.submit(original);
      } catch (err) {
        if (err instanceof CrashError) crashed = err;
        else throw err;
      }
      t.assert(crashed instanceof CrashError, "crash injected after segment write");
      t.assertEqual(backing.manifest, null, "manifest not switched before crash");

      const expectedDigest = await segmentDigestOf(
        GENESIS_DIGEST,
        original.events,
        HASH_FORMAT
      );

      // Reopen: the prepared segment is published as the unique outcome.
      const reopened = await reopen(backing);
      const { engine, recovery, chain } = reopened;
      t.assertEqual(chain.segments.length, 1, "prepared segment recovered");
      const segment = chain.segments[0];
      t.assertEqual(segment.digest, expectedDigest);
      t.assertEqual(segment.prevDigest, GENESIS_DIGEST, "predecessor is genesis");
      t.assertEqual(segment.seqStart, 10, "seq range preserved: start");
      t.assertEqual(segment.seqEnd, 11, "seq range preserved: end");
      t.assertEqual(segment.batchId, "CRASH-BYTES");
      t.assertEqual(
        segment.events[0].payload,
        original.events[0].payload,
        "sensitive payload bytes recovered unchanged"
      );
      t.assert(
        recovery.actions.some(
          (a) =>
            a.action === "segment-published-from-intent" &&
            a.batchId === "CRASH-BYTES"
        ),
        "recovery published from the recorded intent"
      );
      t.assertEqual(recovery.firstBlocking, null, "no blocking evidence");

      // Byte-exact retransmission: the same receipt only, nothing appended
      // and the seq range / predecessor / recovery conclusion stay put.
      const exact = await engine.submit(original);
      t.assertEqual(exact.status, "duplicate");
      t.assertEqual(exact.receipt.digest, expectedDigest);
      t.assertDeepEqual(exact.receipt, segment.receipt);
      const afterExact = await engine.sealedChain();
      t.assertEqual(afterExact.segments.length, 1);
      t.assertEqual(afterExact.version, 1, "manifest switched exactly once");
      t.assertEqual(afterExact.head, expectedDigest);
      t.assertEqual(afterExact.segments[0].seqStart, 10);
      t.assertEqual(afterExact.segments[0].seqEnd, 11);
      t.assertEqual(afterExact.segments[0].prevDigest, GENESIS_DIGEST);

      // Lookalike resubmissions all conflict and keep the first evidence.
      const variants = [
        {
          label: "halfwidth",
          events: [
            { seq: 10, payload: "TELE\nreadout 0.3" },
            { seq: 11, payload: "café" },
          ],
        },
        {
          label: "combining",
          events: [
            { seq: 10, payload: "ＴＥＬＥ\r\nreadout 0.3   " },
            { seq: 11, payload: "cafe\u0301" },
          ],
        },
        {
          label: "trailing-blanks",
          events: [
            { seq: 10, payload: "ＴＥＬＥ\r\nreadout 0.3" },
            { seq: 11, payload: "café" },
          ],
        },
        {
          label: "newline",
          events: [
            { seq: 10, payload: "ＴＥＬＥ\nreadout 0.3   " },
            { seq: 11, payload: "café" },
          ],
        },
      ];
      for (const variant of variants) {
        const outcome = await engine.submit({
          batchId: "CRASH-BYTES",
          events: variant.events,
        });
        t.assertEqual(outcome.status, "conflict", `${variant.label}: conflict`);
        t.assertEqual(
          outcome.conflict.reason,
          "published-content-mismatch",
          `${variant.label}: reason`
        );
        t.assertDeepEqual(
          outcome.conflict.existingReceipt,
          segment.receipt,
          `${variant.label}: original receipt reported`
        );
        const chainNow = await engine.sealedChain();
        t.assertEqual(
          chainNow.segments.length,
          1,
          `${variant.label}: no segment appended`
        );
        t.assertEqual(chainNow.head, expectedDigest, `${variant.label}: head unchanged`);
      }
      t.assertEqual((await engine.conflicts()).length, variants.length);

      // Reopen once more: the recovery conclusion is stable and the first
      // evidence remains intact.
      const again = await reopen(backing);
      t.assertEqual(again.chain.segments.length, 1);
      t.assertEqual(again.chain.head, expectedDigest);
      t.assertEqual(again.chain.segments[0].seqStart, 10);
      t.assertEqual(again.chain.segments[0].seqEnd, 11);
      t.assertEqual(again.chain.segments[0].prevDigest, GENESIS_DIGEST);
      t.assertEqual(again.recovery.actions.length, 0, "nothing left to repair");
      t.assertEqual(again.recovery.firstBlocking, null);
      t.assertEqual((await again.engine.conflicts()).length, variants.length);

      const duplicateAtEnd = await again.engine.submit(original);
      t.assertEqual(duplicateAtEnd.status, "duplicate");
      t.assertEqual(duplicateAtEnd.receipt.digest, expectedDigest);
      t.assertEqual((await again.engine.sealedChain()).segments.length, 1);
    }
  );

  t.test(
    "identity: segments persisted under the pre-fix v1 rule stay reviewable",
    async () => {
      // Hand-craft a segment sealed by the earlier lossy build: v1 hash
      // format, raw payload bytes on disk, published in the manifest.
      const backing = createMemoryBacking();
      const storage = new MemoryStorage(backing);
      const legacyEvents = [{ seq: 1, payload: "ＡＢＣ\r\nreadout   " }];
      const v1Digest = await segmentDigestOf(
        GENESIS_DIGEST,
        legacyEvents,
        LEGACY_HASH_FORMAT
      );
      const v1Content = await contentHashOf(legacyEvents, LEGACY_HASH_FORMAT);
      const receipt = {
        batchId: "LEGACY-1",
        digest: v1Digest,
        prevDigest: GENESIS_DIGEST,
        seqStart: 1,
        seqEnd: 1,
        count: 1,
      };
      await storage.putSegment({
        digest: v1Digest,
        batchId: "LEGACY-1",
        hashFormat: LEGACY_HASH_FORMAT,
        contentHash: v1Content,
        prevDigest: GENESIS_DIGEST,
        seqStart: 1,
        seqEnd: 1,
        events: legacyEvents,
        receipt,
      });
      await storage.putManifest({
        id: "active",
        head: v1Digest,
        segmentIds: [v1Digest],
        batches: { "LEGACY-1": v1Digest },
        version: 1,
      });

      const engine = new SealEngine(storage);
      const { recovery, chain } = await engine.open();
      t.assertEqual(chain.segments.length, 1, "legacy segment not truncated");
      t.assertEqual(chain.segments[0].digest, v1Digest);
      t.assertEqual(
        chain.segments[0].events[0].payload,
        legacyEvents[0].payload,
        "legacy raw bytes still readable"
      );
      t.assertEqual(recovery.actions.length, 0, "legacy chain needs no repair");
      t.assertEqual(recovery.firstBlocking, null);

      // Byte-exact resubmission still returns the v1 receipt.
      const exact = await engine.submit({
        batchId: "LEGACY-1",
        events: legacyEvents,
      });
      t.assertEqual(exact.status, "duplicate");
      t.assertDeepEqual(exact.receipt, receipt);
      t.assertEqual((await engine.sealedChain()).segments.length, 1);

      // What the old rule folded into the same receipt must now conflict,
      // and the first evidence is the legacy segment.
      const folded = await engine.submit({
        batchId: "LEGACY-1",
        events: [{ seq: 1, payload: "ABC\nreadout" }],
      });
      t.assertEqual(
        folded.status,
        "conflict",
        "v1 lookalike is no longer the same receipt"
      );
      t.assertEqual(folded.conflict.reason, "published-content-mismatch");
      t.assertDeepEqual(folded.conflict.existingReceipt, receipt);
      t.assertEqual((await engine.sealedChain()).segments.length, 1);

      // A later batch extends the legacy segment and seals under v2;
      // reopen verifies both formats without truncating either.
      const next = await engine.submit({
        batchId: "LEGACY-2",
        events: [{ seq: 2, payload: "new ＴＥＬＥ" }],
      });
      t.assertEqual(next.status, "sealed");
      t.assertEqual(next.receipt.prevDigest, v1Digest);

      const reopened = await reopen(backing);
      t.assertEqual(reopened.chain.segments.length, 2, "mixed-format chain kept");
      t.assertEqual(reopened.chain.segments[0].digest, v1Digest);
      t.assertEqual(reopened.chain.segments[1].digest, next.receipt.digest);
      t.assertEqual(reopened.chain.segments[1].prevDigest, v1Digest);
      t.assertEqual(reopened.recovery.firstBlocking, null);
      t.assertEqual(reopened.recovery.actions.length, 0);
    }
  );

  t.test(
    "identity: a pending v1 intent plus complete segment recovers, then lookalikes conflict",
    async () => {
      // Simulates an afterSegment crash under the OLD build: a v1-tagged
      // prepare intent and its complete segment on disk, manifest unset.
      const backing = createMemoryBacking();
      const storage = new MemoryStorage(backing);
      const events = [{ seq: 1, payload: "ＴＥＳＴ " }];
      const v1Digest = await segmentDigestOf(GENESIS_DIGEST, events, LEGACY_HASH_FORMAT);
      const v1Content = await contentHashOf(events, LEGACY_HASH_FORMAT);
      await storage.putPrepare({
        batchId: "LEGACY-INTENT",
        hashFormat: LEGACY_HASH_FORMAT,
        contentHash: v1Content,
        events,
        prevDigest: GENESIS_DIGEST,
        expectedDigest: v1Digest,
        createdAt: 1,
      });
      await storage.putSegment({
        digest: v1Digest,
        batchId: "LEGACY-INTENT",
        hashFormat: LEGACY_HASH_FORMAT,
        contentHash: v1Content,
        prevDigest: GENESIS_DIGEST,
        seqStart: 1,
        seqEnd: 1,
        events,
        receipt: {
          batchId: "LEGACY-INTENT",
          digest: v1Digest,
          prevDigest: GENESIS_DIGEST,
          seqStart: 1,
          seqEnd: 1,
          count: 1,
        },
      });

      const { engine, recovery, chain } = await reopen(backing);
      t.assertEqual(chain.segments.length, 1, "v1 intent recovered");
      t.assertEqual(chain.segments[0].digest, v1Digest);
      t.assertEqual(recovery.firstBlocking, null);
      t.assert(
        recovery.actions.some(
          (a) =>
            a.action === "segment-published-from-intent" &&
            a.batchId === "LEGACY-INTENT"
        ),
        "published from the recorded v1 intent"
      );

      const folded = await engine.submit({
        batchId: "LEGACY-INTENT",
        events: [{ seq: 1, payload: "TEST" }],
      });
      t.assertEqual(folded.status, "conflict", "old-folded variant conflicts");
      t.assertEqual(folded.conflict.reason, "published-content-mismatch");

      const exact = await engine.submit({
        batchId: "LEGACY-INTENT",
        events,
      });
      t.assertEqual(exact.status, "duplicate");
      t.assertEqual(exact.receipt.digest, v1Digest);
      t.assertEqual((await engine.sealedChain()).segments.length, 1);
    }
  );
}
