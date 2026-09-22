import { describe, expect, it } from "vitest";
import {
  AckRangeError,
  addPacket,
  decodeAckFrame,
  decodeVarint,
  encodeAckFrame,
  encodeVarint,
  normalizeRanges,
  PACKET_NUMBER_MAX,
  VARINT_MAX,
  validateRanges,
  type Range,
} from "../src/index.js";

/** Add a list of packet numbers in the given order. */
function build(packets: bigint[]): Range[] {
  let ranges: Range[] = [];
  for (const p of packets) ranges = addPacket(ranges, p);
  return ranges;
}

const bytes = (...n: number[]) => Uint8Array.from(n);
const hex = (u: Uint8Array) =>
  Array.from(u, (b) => b.toString(16).padStart(2, "0")).join(" ");

// ---------------------------------------------------------------------------
// Varint
// ---------------------------------------------------------------------------

describe("varint", () => {
  it("round-trips boundary values", () => {
    for (const v of [0n, 1n, 63n, 64n, 16383n, 16384n, 2n ** 30n - 1n, 2n ** 30n, VARINT_MAX]) {
      const enc = encodeVarint(v);
      const dec = decodeVarint(enc)!;
      expect(dec.value).toBe(v);
    }
    expect(Array.from(encodeVarint(63n))).toEqual([0x3f]);
    expect(Array.from(encodeVarint(64n))).toEqual([0x40, 0x40]);
    expect(encodeVarint(VARINT_MAX)).toEqual(new Uint8Array(8).fill(0xff));
  });

  it("rejects values outside the 62-bit domain", () => {
    expect(() => encodeVarint(-1n)).toThrow(RangeError);
    expect(() => encodeVarint(VARINT_MAX + 1n)).toThrow(RangeError);
  });

  it("returns null on truncated input", () => {
    expect(decodeVarint(bytes(0x40))).toBeNull();
    expect(decodeVarint(bytes(0x80, 0x00))).toBeNull();
    expect(decodeVarint(new Uint8Array(7).fill(0xff))).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Range set: single / adjacent / gap / duplicate / 0 / max
// ---------------------------------------------------------------------------

describe("addPacket", () => {
  it("single packet", () => {
    expect(build([5n])).toEqual([{ start: 5n, end: 5n }]);
  });

  it("merges adjacent packets above, below and filling a gap", () => {
    expect(build([5n, 6n])).toEqual([{ start: 6n, end: 5n }]);
    expect(build([5n, 4n])).toEqual([{ start: 5n, end: 4n }]);
    expect(build([4n, 6n, 5n])).toEqual([{ start: 6n, end: 4n }]);
    // Filling a one-packet hole bridges two intervals.
    expect(build([10n, 5n, 9n, 6n, 8n, 7n])).toEqual([{ start: 10n, end: 5n }]);
  });

  it("keeps a huge gap as separate ranges", () => {
    expect(build([1000n, 0n])).toEqual([
      { start: 1000n, end: 1000n },
      { start: 0n, end: 0n },
    ]);
  });

  it("ignores duplicate additions and packets inside existing ranges", () => {
    const once = build([1n, 2n, 3n]);
    const many = build([2n, 1n, 3n, 2n, 1n, 3n, 2n, 2n]);
    expect(many).toEqual(once);
    expect(build([7n, 8n, 9n, 7n, 9n, 8n])).toEqual([{ start: 9n, end: 7n }]);
  });

  it("handles packet number 0", () => {
    expect(build([0n])).toEqual([{ start: 0n, end: 0n }]);
    expect(build([2n, 0n, 1n])).toEqual([{ start: 2n, end: 0n }]);
  });

  it("handles the maximum packet number", () => {
    expect(build([PACKET_NUMBER_MAX])).toEqual([
      { start: PACKET_NUMBER_MAX, end: PACKET_NUMBER_MAX },
    ]);
    expect(build([PACKET_NUMBER_MAX, PACKET_NUMBER_MAX - 1n])).toEqual([
      { start: PACKET_NUMBER_MAX, end: PACKET_NUMBER_MAX - 1n },
    ]);
  });

  it("does not mutate the input list", () => {
    const before = [{ start: 5n, end: 5n }];
    addPacket(before, 9n);
    expect(before).toEqual([{ start: 5n, end: 5n }]);
  });

  it("rejects negative or oversized packet numbers", () => {
    expect(() => addPacket([], -1n)).toThrow(AckRangeError);
    expect(() => addPacket([], PACKET_NUMBER_MAX + 1n)).toThrow(AckRangeError);
  });

  it("canonical form is independent of insertion order", () => {
    const asc = [0n, 1n, 2n, 10n, 11n, 100n];
    const desc = [...asc].reverse();
    const shuffled = [11n, 0n, 100n, 1n, 10n, 2n];
    expect(build(desc)).toEqual(build(asc));
    expect(build(shuffled)).toEqual(build(asc));
  });

  it("normalizes non-canonical input (overlapping/adjacent intervals)", () => {
    expect(
      normalizeRanges([
        { start: 3n, end: 0n },
        { start: 8n, end: 5n },
        { start: 4n, end: 4n },
      ]),
    ).toEqual([{ start: 8n, end: 0n }]);
  });
});

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

describe("encodeAckFrame", () => {
  it("encodes a single-packet ACK", () => {
    // type=0x02 largest=5 delay=0 count=0 first_range=0
    expect(hex(encodeAckFrame(build([5n])))).toBe("02 05 00 00 00");
  });

  it("encodes an adjacent run via first_range", () => {
    expect(hex(encodeAckFrame(build([4n, 5n, 6n])))).toBe("02 06 00 00 02");
  });

  it("encodes a huge gap", () => {
    // [1000] gap=998 [0]: 1000=0x43e8, 998=0x43e6
    expect(hex(encodeAckFrame(build([1000n, 0n])))).toBe(
      "02 43 e8 00 01 00 43 e6 00",
    );
  });

  it("encodes packet 0 and the maximum packet number", () => {
    expect(hex(encodeAckFrame(build([0n])))).toBe("02 00 00 00 00");
    const max = new Uint8Array(8).fill(0xff);
    expect(encodeAckFrame(build([PACKET_NUMBER_MAX]))).toEqual(
      bytes(0x02, ...Array.from(max), 0x00, 0x00, 0x00),
    );
  });

  it("encodes a near-maximum gap (gap = VARINT_MAX - 2)", () => {
    const frame = encodeAckFrame([
      { start: PACKET_NUMBER_MAX, end: PACKET_NUMBER_MAX },
      { start: 0n, end: 0n },
    ]);
    const decoded = decodeAckFrame(frame)!;
    expect(decoded.ranges).toEqual([
      { start: PACKET_NUMBER_MAX, end: PACKET_NUMBER_MAX },
      { start: 0n, end: 0n },
    ]);
  });

  it("rejects empty, non-canonical and out-of-budget range sets", () => {
    expect(() => encodeAckFrame([])).toThrow(AckRangeError);
    // Adjacent intervals must have been merged first.
    expect(() =>
      encodeAckFrame([
        { start: 10n, end: 5n },
        { start: 4n, end: 3n },
      ]),
    ).toThrow(AckRangeError);
    const three = build([1n, 10n, 20n]);
    expect(three.length).toBe(3);
    expect(() => encodeAckFrame(three, { maxRanges: 2 })).toThrow(AckRangeError);
    expect(() => encodeAckFrame(three, { maxRanges: 3 })).not.toThrow();
  });

  it("rejects ack_delay outside the varint domain", () => {
    expect(() => encodeAckFrame(build([1n]), { ackDelay: -1n })).toThrow(
      RangeError,
    );
    expect(() =>
      encodeAckFrame(build([1n]), { ackDelay: VARINT_MAX + 1n }),
    ).toThrow(RangeError);
  });

  it("encoding is independent of the order packets were added", () => {
    const packets = [0n, 1n, 3n, 100n, 101n, 9000n];
    const a = encodeAckFrame(build(packets));
    const b = encodeAckFrame(build([...packets].reverse()));
    expect(hex(b)).toBe(hex(a));
  });
});

// ---------------------------------------------------------------------------
// Decoding: malicious inputs
// ---------------------------------------------------------------------------

describe("decodeAckFrame", () => {
  const expectCode = (u: Uint8Array, code: string, opts?: object) => {
    try {
      decodeAckFrame(u, 0, opts);
      throw new Error("expected AckRangeError");
    } catch (e) {
      expect(e).toBeInstanceOf(AckRangeError);
      expect((e as AckRangeError).code).toBe(code);
    }
  };

  it("decodes a single packet", () => {
    const d = decodeAckFrame(bytes(0x02, 0x05, 0x00, 0x00, 0x00))!;
    expect(d.largest).toBe(5n);
    expect(d.ackDelay).toBe(0n);
    expect(d.rangeCount).toBe(0n);
    expect(d.ranges).toEqual([{ start: 5n, end: 5n }]);
  });

  it("decodes a gap and range length", () => {
    const d = decodeAckFrame(
      bytes(0x02, 0x43, 0xe8, 0x00, 0x01, 0x00, 0x43, 0xe6, 0x00),
    )!;
    expect(d.ranges).toEqual([
      { start: 1000n, end: 1000n },
      { start: 0n, end: 0n },
    ]);
  });

  it("accepts ACK-ECN frames (type 0x03) and skips the ECN counts", () => {
    const d = decodeAckFrame(
      bytes(0x03, 0x05, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03),
    )!;
    expect(d.ranges).toEqual([{ start: 5n, end: 5n }]);
  });

  it("returns null for non-ACK frames", () => {
    expect(decodeAckFrame(bytes(0x01))).toBeNull(); // PING
  });

  it("rejects first_range that drives the smallest packet below 0", () => {
    // largest=0, first_range=1
    expectCode(bytes(0x02, 0x00, 0x00, 0x00, 0x01), "UNDERFLOW");
    // largest=5, first_range=6
    expectCode(bytes(0x02, 0x05, 0x00, 0x00, 0x06), "UNDERFLOW");
  });

  it("rejects malicious gaps that imply negative packet numbers", () => {
    // largest=5, count=1, first_range=0, gap=4 -> 5-4-2 = -1
    expectCode(
      bytes(0x02, 0x05, 0x00, 0x01, 0x00, 0x04, 0x00),
      "UNDERFLOW",
    );
  });

  it("rejects range lengths that extend below packet 0", () => {
    // largest=5, count=1, first_range=0, gap=0 (cur largest=3), len=4
    expectCode(
      bytes(0x02, 0x05, 0x00, 0x01, 0x00, 0x00, 0x04),
      "UNDERFLOW",
    );
  });

  it("rejects overlapping or adjacent ranges", () => {
    // Two intervals touching: [10..5] and [4..4] (gap must encode >=1 packet
    // between; construct the ranges directly and run validation).
    expect(() =>
      validateRanges([
        { start: 10n, end: 5n },
        { start: 4n, end: 4n },
      ]),
    ).toThrow(AckRangeError);
    expect(() =>
      validateRanges([
        { start: 10n, end: 5n },
        { start: 6n, end: 3n },
      ]),
    ).toThrow(AckRangeError);
  });

  it("rejects declared range counts above the configured budget", () => {
    // count=4 declared, maxRanges=2 -> rejected before reading range fields.
    expectCode(
      bytes(0x02, 0x0a, 0x00, 0x04, 0x00),
      "TOO_MANY_RANGES",
      { maxRanges: 2 },
    );
  });

  it("rejects absurd range counts without looping", () => {
    // count = 2^60 (> MAX_SAFE_INTEGER) in an 8-byte varint, first_range
    // present, no range fields.
    expectCode(
      bytes(
        0x02, 0x0a, 0x00,
        0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
      ),
      "TOO_MANY_RANGES",
    );
  });

  it("rejects truncated frames", () => {
    expectCode(bytes(0x02), "UNEXPECTED_END");
    expectCode(bytes(0x02, 0x05), "UNEXPECTED_END");
    // gap=0 then a 2-byte varint for range length with its second byte missing
    expectCode(
      bytes(0x02, 0x05, 0x00, 0x01, 0x00, 0x00, 0x40),
      "TRUNCATED",
    );
  });
});

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

describe("round trip", () => {
  const cases: bigint[][] = [
    [0n],
    [PACKET_NUMBER_MAX],
    [1n],
    [1n, 2n, 3n],
    [0n, 1000n],
    [5n, 6n, 4n, 100n, 102n, 103n],
    [0n, PACKET_NUMBER_MAX],
    [PACKET_NUMBER_MAX, PACKET_NUMBER_MAX - 1n, PACKET_NUMBER_MAX - 3n],
    [10n, 20n, 30n, 40n, 50n, 60n, 70n, 80n, 90n],
  ];

  it("encode -> decode preserves the range set", () => {
    for (const packets of cases) {
      const ranges = build(packets);
      const frame = encodeAckFrame(ranges, { ackDelay: 1234n });
      const decoded = decodeAckFrame(frame)!;
      expect(decoded.ranges, `packets ${packets.join(",")}`).toEqual(ranges);
      expect(decoded.ackDelay).toBe(1234n);
      // Re-encoding the decoded set yields identical bytes.
      expect(encodeAckFrame(decoded.ranges, { ackDelay: 1234n })).toEqual(
        frame,
      );
    }
  });

  it("is stable across many shuffled insertion orders", () => {
    const base = [0n, 1n, 2n, 7n, 8n, 100n, 1000n, 4096n, 9999n];
    const canonical = encodeAckFrame(build(base));
    const shuffled = (() => {
      const a = [...base];
      let seed = 1234567;
      for (let i = a.length - 1; i > 0; i--) {
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        const j = seed % (i + 1);
        [a[i], a[j]] = [a[j], a[i]];
      }
      return a;
    })();
    const orders: bigint[][] = [[...base].reverse(), shuffled];
    for (const order of orders) {
      expect(encodeAckFrame(build(order))).toEqual(canonical);
      expect(decodeAckFrame(encodeAckFrame(build(order)))!.ranges).toEqual(
        decodeAckFrame(canonical)!.ranges,
      );
    }
  });
});
