// Rule tests: batch validation, idempotent retransmission, conflict
// handling, hash-chain binding and sequencing rules.

import { createHash } from "node:crypto";
import { SealEngine } from "../../core/engine.js";
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
import { FORM_CASES } from "./form-cases.js";

function sha256Node(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function canonicalSegment(prevDigest, events) {
  return [prevDigest, ...events.map((e) => `${e.seq}|${e.payload}`)].join("\n");
}

async function freshEngine() {
  const engine = new SealEngine(new MemoryStorage(createMemoryBacking()));
  await engine.open();
  return engine;
}

export function registerRuleTests(t) {
  t.test("rules: rejects malformed batch ids", async () => {
    const engine = await freshEngine();
    for (const batchId of ["", "has space", "x".repeat(65), "-lead", "批次-1"]) {
      const outcome = await engine.submit({
        batchId,
        events: [{ seq: 1, payload: "a" }],
      });
      t.assertEqual(outcome.status, "rejected", `batchId ${JSON.stringify(batchId)}`);
      t.assertEqual(outcome.error.code, "invalid-batch-id");
    }
  });

  t.test("rules: rejects empty and oversized event lists", async () => {
    const engine = await freshEngine();
    const empty = await engine.submit({ batchId: "B1", events: [] });
    t.assertEqual(empty.error.code, "events-empty");

    const tooMany = await engine.submit({
      batchId: "B2",
      events: Array.from({ length: 25 }, (_, i) => ({ seq: i + 1, payload: "x" })),
    });
    t.assertEqual(tooMany.error.code, "events-too-many");
  });

  t.test("rules: accepts exactly 24 events (upper bound)", async () => {
    const engine = await freshEngine();
    const outcome = await engine.submit({
      batchId: "B24",
      events: Array.from({ length: 24 }, (_, i) => ({ seq: i + 1, payload: `e${i}` })),
    });
    t.assertEqual(outcome.status, "sealed");
    t.assertEqual(outcome.receipt.count, 24);
  });

  t.test("rules: requires strictly increasing integer seqs", async () => {
    const engine = await freshEngine();
    const equal = await engine.submit({
      batchId: "B3",
      events: [
        { seq: 2, payload: "a" },
        { seq: 2, payload: "b" },
      ],
    });
    t.assertEqual(equal.error.code, "seq-not-increasing");

    const decreasing = await engine.submit({
      batchId: "B4",
      events: [
        { seq: 5, payload: "a" },
        { seq: 3, payload: "b" },
      ],
    });
    t.assertEqual(decreasing.error.code, "seq-not-increasing");

    const fractional = await engine.submit({
      batchId: "B5",
      events: [{ seq: 1.5, payload: "a" }],
    });
    t.assertEqual(fractional.error.code, "invalid-seq");

    const nonString = await engine.submit({
      batchId: "B6",
      events: [{ seq: 1, payload: 42 }],
    });
    t.assertEqual(nonString.error.code, "invalid-payload");
  });

  t.test("rules: digest matches independent SHA-256 of canonical UTF-8", async () => {
    const engine = await freshEngine();
    const events = [
      { seq: 7, payload: "姿态机动 Δv=0.3" },
      { seq: 9, payload: "emoji 🚀 and combining é chars" },
    ];
    const outcome = await engine.submit({ batchId: "HASH-1", events });
    t.assertEqual(outcome.status, "sealed");
    const expected = sha256Node(canonicalSegment(GENESIS_DIGEST, events));
    t.assertEqual(outcome.receipt.digest, expected);
    t.assertEqual(outcome.receipt.prevDigest, GENESIS_DIGEST);
  });

  t.test("rules: new segment binds to the previous segment digest", async () => {
    const engine = await freshEngine();
    const first = await engine.submit({
      batchId: "LINK-1",
      events: [{ seq: 1, payload: "one" }],
    });
    const second = await engine.submit({
      batchId: "LINK-2",
      events: [{ seq: 2, payload: "two" }],
    });
    t.assertEqual(second.receipt.prevDigest, first.receipt.digest);
    const expected = sha256Node(
      canonicalSegment(first.receipt.digest, [{ seq: 2, payload: "two" }])
    );
    t.assertEqual(second.receipt.digest, expected);
  });

  t.test("rules: identical retransmission returns the original receipt", async () => {
    const engine = await freshEngine();
    const batch = {
      batchId: "DUP-1",
      events: [
        { seq: 1, payload: "alpha" },
        { seq: 2, payload: "beta" },
      ],
    };
    const first = await engine.submit(batch);
    t.assertEqual(first.status, "sealed");
    const chainBefore = await engine.sealedChain();

    const again = await engine.submit(batch);
    t.assertEqual(again.status, "duplicate");
    t.assertDeepEqual(again.receipt, first.receipt);

    const chainAfter = await engine.sealedChain();
    t.assertEqual(chainAfter.segments.length, 1);
    t.assertEqual(chainAfter.version, chainBefore.version);
  });

  t.test("rules: same id with different content conflicts, evidence kept", async () => {
    const engine = await freshEngine();
    const original = await engine.submit({
      batchId: "CONF-1",
      events: [{ seq: 1, payload: "original" }],
    });
    const conflict = await engine.submit({
      batchId: "CONF-1",
      events: [{ seq: 1, payload: "tampered" }],
    });
    t.assertEqual(conflict.status, "conflict");
    t.assertEqual(conflict.conflict.reason, "published-content-mismatch");
    t.assertDeepEqual(conflict.conflict.existingReceipt, original.receipt);

    const chain = await engine.sealedChain();
    t.assertEqual(chain.segments.length, 1);
    t.assertEqual(chain.segments[0].events[0].payload, "original");

    const conflicts = await engine.conflicts();
    t.assertEqual(conflicts.length, 1);
    t.assertEqual(conflicts[0].batchId, "CONF-1");
  });

  t.test("rules: sequence regression across batches is rejected", async () => {
    const engine = await freshEngine();
    await engine.submit({
      batchId: "SEQ-1",
      events: [
        { seq: 5, payload: "a" },
        { seq: 7, payload: "b" },
      ],
    });
    for (const seq of [3, 7]) {
      const outcome = await engine.submit({
        batchId: `SEQ-X${seq}`,
        events: [{ seq, payload: "late" }],
      });
      t.assertEqual(outcome.status, "rejected");
      t.assertEqual(outcome.error.code, "sequence-regression");
    }
    const ok = await engine.submit({
      batchId: "SEQ-2",
      events: [{ seq: 8, payload: "next" }],
    });
    t.assertEqual(ok.status, "sealed");
  });

  t.test(
    "rules: digest covers the actual UTF-8 bytes of form-sensitive payloads",
    async () => {
      for (const { name, original, altered } of FORM_CASES) {
        const engine = await freshEngine();
        const events = [{ seq: 3, payload: original }];
        const outcome = await engine.submit({ batchId: "BYTES-1", events });
        t.assertEqual(outcome.status, "sealed", name);
        // Independent SHA-256 over the untouched canonical text.
        const expected = sha256Node(canonicalSegment(GENESIS_DIGEST, events));
        t.assertEqual(outcome.receipt.digest, expected, name);
        // The look-alike form is a different identity.
        const alteredDigest = sha256Node(
          canonicalSegment(GENESIS_DIGEST, [{ seq: 3, payload: altered }])
        );
        t.assert(alteredDigest !== expected, `${name}: forms must hash differently`);
      }
    }
  );

  t.test(
    "rules: byte-identical retransmission of form-sensitive payloads returns the original receipt",
    async () => {
      for (const { name, original } of FORM_CASES) {
        const engine = await freshEngine();
        const batch = {
          batchId: "EXACT-1",
          events: [{ seq: 1, payload: original }],
        };
        const first = await engine.submit(batch);
        t.assertEqual(first.status, "sealed", name);

        const again = await engine.submit(batch);
        t.assertEqual(again.status, "duplicate", name);
        t.assertDeepEqual(again.receipt, first.receipt, name);

        const chain = await engine.sealedChain();
        t.assertEqual(chain.segments.length, 1, name);
        t.assertEqual(chain.version, 1, name);
        t.assertEqual((await engine.conflicts()).length, 0, name);
      }
    }
  );

  t.test(
    "rules: look-alike payloads with different character forms conflict",
    async () => {
      for (const { name, original, altered } of FORM_CASES) {
        // Both sealing orders must behave identically.
        for (const [firstPayload, secondPayload] of [
          [original, altered],
          [altered, original],
        ]) {
          const engine = await freshEngine();
          const first = await engine.submit({
            batchId: "FORM-1",
            events: [{ seq: 1, payload: firstPayload }],
          });
          t.assertEqual(first.status, "sealed", name);

          const second = await engine.submit({
            batchId: "FORM-1",
            events: [{ seq: 1, payload: secondPayload }],
          });
          t.assertEqual(second.status, "conflict", name);
          t.assertEqual(
            second.conflict.reason,
            "published-content-mismatch",
            name
          );
          t.assertDeepEqual(second.conflict.existingReceipt, first.receipt, name);
          t.assert(
            second.conflict.incomingContentHash !==
              second.conflict.existingContentHash,
            `${name}: conflict must record distinct content hashes`
          );

          // First evidence is kept: chain untouched, conflict recorded.
          const chain = await engine.sealedChain();
          t.assertEqual(chain.segments.length, 1, name);
          t.assertEqual(chain.segments[0].events[0].payload, firstPayload, name);
          const conflicts = await engine.conflicts();
          t.assertEqual(conflicts.length, 1, name);
          t.assertEqual(conflicts[0].batchId, "FORM-1", name);
        }
      }
    }
  );

  t.test(
    "rules: legacy v1 segments stay reviewable, byte differences still conflict",
    async () => {
      const backing = createMemoryBacking();
      const storage = new MemoryStorage(backing);

      // Two segments exactly as the pre-fix rules persisted them: one
      // tagged review-text-v1, one untagged (predating format tagging).
      // Payloads use the full-width / combining forms.
      const legacyEvents1 = [{ seq: 1, payload: "ＡＢＣ" }];
      const legacyEvents2 = [{ seq: 2, payload: "café" }];
      const digest1 = await segmentDigestOf(
        GENESIS_DIGEST,
        legacyEvents1,
        LEGACY_HASH_FORMAT
      );
      const digest2 = await segmentDigestOf(
        digest1,
        legacyEvents2,
        LEGACY_HASH_FORMAT
      );
      await storage.putSegment({
        digest: digest1,
        batchId: "LEG-1",
        hashFormat: LEGACY_HASH_FORMAT,
        contentHash: await contentHashOf(legacyEvents1, LEGACY_HASH_FORMAT),
        prevDigest: GENESIS_DIGEST,
        seqStart: 1,
        seqEnd: 1,
        events: legacyEvents1,
        receipt: {
          batchId: "LEG-1",
          digest: digest1,
          prevDigest: GENESIS_DIGEST,
          seqStart: 1,
          seqEnd: 1,
          count: 1,
        },
      });
      await storage.putSegment({
        digest: digest2,
        batchId: "LEG-2",
        // no hashFormat: untagged legacy record
        contentHash: await contentHashOf(legacyEvents2, LEGACY_HASH_FORMAT),
        prevDigest: digest1,
        seqStart: 2,
        seqEnd: 2,
        events: legacyEvents2,
        receipt: {
          batchId: "LEG-2",
          digest: digest2,
          prevDigest: digest1,
          seqStart: 2,
          seqEnd: 2,
          count: 1,
        },
      });
      await storage.putManifest({
        id: "active",
        head: digest2,
        segmentIds: [digest1, digest2],
        batches: { "LEG-1": digest1, "LEG-2": digest2 },
        version: 7,
      });

      // Reopening must not truncate the legacy chain or report blocking.
      const engine = new SealEngine(new MemoryStorage(backing));
      const { recovery, chain } = await engine.open();
      t.assertEqual(chain.segments.length, 2, "legacy chain must stay sealed");
      t.assertEqual(recovery.blocking.length, 0, "no blocking evidence");
      t.assertEqual(chain.version, 7, "manifest untouched by recovery");
      t.assertEqual(chain.head, digest2);

      // Byte-identical retransmission of a legacy batch: original receipt.
      const exact = await engine.submit({
        batchId: "LEG-1",
        events: [{ seq: 1, payload: "ＡＢＣ" }],
      });
      t.assertEqual(exact.status, "duplicate");
      t.assertEqual(exact.receipt.digest, digest1);

      // A look-alike but byte-different retransmission under a legacy id is
      // a conflict — the fix must not re-treat different content as the
      // same receipt just because the old rules would have.
      const altered = await engine.submit({
        batchId: "LEG-1",
        events: [{ seq: 1, payload: "ABC" }],
      });
      t.assertEqual(altered.status, "conflict");
      t.assertEqual(altered.conflict.reason, "published-content-mismatch");
      t.assertEqual(altered.conflict.existingReceipt.digest, digest1);
      t.assertEqual((await engine.sealedChain()).segments.length, 2);
      t.assertEqual((await engine.conflicts()).length, 1);

      // New batches chain onto the legacy head under the current format...
      const next = await engine.submit({
        batchId: "LEG-3",
        events: [{ seq: 3, payload: "new era" }],
      });
      t.assertEqual(next.status, "sealed");
      t.assertEqual(next.receipt.prevDigest, digest2);
      const stored = backing.segments.get(next.receipt.digest);
      t.assertEqual(stored.hashFormat, HASH_FORMAT);

      // ...and the mixed-format chain still verifies on the next open.
      const reopened = new SealEngine(new MemoryStorage(backing));
      const again = await reopened.open();
      t.assertEqual(again.chain.segments.length, 3);
      t.assertEqual(again.recovery.blocking.length, 0);
      t.assertEqual(again.chain.head, next.receipt.digest);
    }
  );
}
