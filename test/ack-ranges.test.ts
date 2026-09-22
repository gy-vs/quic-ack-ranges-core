import { describe, expect, it } from 'vitest';
import {
  AckFrameError,
  MAX_PACKET_NUMBER,
  addPacket,
  decodeAckFrame,
  decodeVarint,
  encodeAckFrame,
  encodeVarint,
  type Range,
} from '../src/index.js';

function addInOrder(packets: bigint[]): Range[] {
  let ranges: Range[] = [];
  for (const p of packets) ranges = addPacket(ranges, p);
  return ranges;
}

function bytes(...hex: number[]): Uint8Array {
  return Uint8Array.from(hex);
}

describe('decodeVarint (existing)', () => {
  it('decodes', () => expect(decodeVarint(Uint8Array.from([37]))?.value).toBe(37n));

  it('returns null on truncated input', () => {
    expect(decodeVarint(Uint8Array.from([0x40]), 0)).toBeNull();
  });

  it('encodes and decodes 62-bit values', () => {
    for (const v of [0n, 1n, 63n, 64n, 16383n, 16384n, MAX_PACKET_NUMBER]) {
      expect(decodeVarint(encodeVarint(v))?.value).toBe(v);
    }
  });
});

describe('addPacket', () => {
  it('handles a single packet', () => {
    expect(addInOrder([7n])).toEqual([{ start: 7n, end: 7n }]);
  });

  it('merges adjacent packets above, below and in the middle', () => {
    expect(addInOrder([5n, 6n])).toEqual([{ start: 6n, end: 5n }]);
    expect(addInOrder([6n, 5n])).toEqual([{ start: 6n, end: 5n }]);
    expect(addInOrder([10n, 0n, 5n, 6n, 4n])).toEqual([
      { start: 10n, end: 10n },
      { start: 6n, end: 4n },
      { start: 0n, end: 0n },
    ]);
    // Adding the missing middle packets bridges both gaps.
    expect(addInOrder([10n, 0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n])).toEqual([
      { start: 10n, end: 0n },
    ]);
  });

  it('keeps a huge gap as two separate ranges', () => {
    const ranges = addInOrder([1_000_000n, 0n]);
    expect(ranges).toEqual([
      { start: 1_000_000n, end: 1_000_000n },
      { start: 0n, end: 0n },
    ]);
  });

  it('treats duplicate adds as a no-op', () => {
    let ranges = addInOrder([3n, 3n, 3n]);
    expect(ranges).toEqual([{ start: 3n, end: 3n }]);

    ranges = addInOrder([10n, 1n, 2n, 3n]);
    const once = addPacket(ranges, 2n);
    const twice = addPacket(once, 2n);
    expect(twice).toEqual(once);
    expect(ranges).toEqual([
      { start: 10n, end: 10n },
      { start: 3n, end: 1n },
    ]);
  });

  it('supports packet number 0', () => {
    expect(addInOrder([0n])).toEqual([{ start: 0n, end: 0n }]);
    expect(addInOrder([1n, 0n])).toEqual([{ start: 1n, end: 0n }]);
  });

  it('supports the maximum packet number', () => {
    expect(addInOrder([MAX_PACKET_NUMBER])).toEqual([
      { start: MAX_PACKET_NUMBER, end: MAX_PACKET_NUMBER },
    ]);
  });

  it('rejects negative and out-of-range packet numbers', () => {
    expect(() => addPacket([], -1n)).toThrow(AckFrameError);
    expect(() => addPacket([], MAX_PACKET_NUMBER + 1n)).toThrow(AckFrameError);
  });

  it('never mutates its input', () => {
    const ranges: Range[] = [{ start: 5n, end: 5n }];
    const frozen = Object.freeze(ranges);
    addPacket(frozen, 6n);
    expect(frozen).toEqual([{ start: 5n, end: 5n }]);
  });
});

describe('encodeAckFrame', () => {
  it('encodes a single packet', () => {
    // type 0x02, largest 5, delay 0, count 0, first range 0
    expect(encodeAckFrame(addInOrder([5n]))).toEqual(bytes(0x02, 0x05, 0x00, 0x00, 0x00));
  });

  it('encodes a merged adjacent range with a first range length', () => {
    // [4..6]: largest 6, first range = 6 - 4 = 2
    expect(encodeAckFrame(addInOrder([5n, 6n, 4n]))).toEqual(
      bytes(0x02, 0x06, 0x00, 0x00, 0x02),
    );
  });

  it('encodes a huge gap as a 2-byte gap varint', () => {
    // ranges [1000..1000],[0..0]: gap = 1000 - 0 - 2 = 998 = 0x03E6
    const frame = encodeAckFrame(addInOrder([1000n, 0n]), 0n);
    expect(frame).toEqual(
      bytes(0x02, 0x43, 0xe8, 0x00, 0x01, 0x00, 0x43, 0xe6, 0x00),
    );
  });

  it('encodes packet number 0', () => {
    expect(encodeAckFrame([{ start: 0n, end: 0n }])).toEqual(
      bytes(0x02, 0x00, 0x00, 0x00, 0x00),
    );
  });

  it('encodes the maximum packet number as an 8-byte varint', () => {
    const frame = encodeAckFrame([{ start: MAX_PACKET_NUMBER, end: MAX_PACKET_NUMBER }]);
    expect(frame).toEqual(bytes(0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00));
  });

  it('preserves the ack delay', () => {
    expect(encodeAckFrame(addInOrder([1n]), 42n)).toEqual(
      bytes(0x02, 0x01, 0x2a, 0x00, 0x00),
    );
  });

  it('rejects empty range sets', () => {
    expect(() => encodeAckFrame([])).toThrow(AckFrameError);
  });

  it('rejects non-canonical inputs that cause gap underflow', () => {
    // Overlapping intervals.
    expect(() =>
      encodeAckFrame([
        { start: 5n, end: 3n },
        { start: 3n, end: 1n },
      ]),
    ).toThrow(/gap underflow/);
    // Adjacent intervals that should have been merged.
    expect(() =>
      encodeAckFrame([
        { start: 5n, end: 3n },
        { start: 2n, end: 1n },
      ]),
    ).toThrow(/gap underflow/);
  });

  it('rejects values above the varint ceiling', () => {
    expect(() => encodeAckFrame(addInOrder([1n]), MAX_PACKET_NUMBER + 1n)).toThrow(
      AckFrameError,
    );
    expect(() => encodeVarint(-1n)).toThrow(AckFrameError);
  });
});

describe('decodeAckFrame', () => {
  it('decodes a single-packet frame', () => {
    const decoded = decodeAckFrame(bytes(0x02, 0x05, 0x00, 0x00, 0x00));
    expect(decoded.ranges).toEqual([{ start: 5n, end: 5n }]);
    expect(decoded.ackDelay).toBe(0n);
    expect(decoded.size).toBe(5);
  });

  it('decodes ranges with a huge gap', () => {
    const decoded = decodeAckFrame(
      bytes(0x02, 0x43, 0xe8, 0x00, 0x01, 0x00, 0x43, 0xe6, 0x00),
    );
    expect(decoded.ranges).toEqual([
      { start: 1000n, end: 1000n },
      { start: 0n, end: 0n },
    ]);
  });

  it('rejects a malicious gap that would produce negative packet numbers', () => {
    // largest 10, count 1, first range 0, then gap 20 (length 0):
    // smallest = 10 - 20 - 2 < 0
    const evil = bytes(0x02, 0x0a, 0x00, 0x01, 0x00, 0x14, 0x00);
    expect(() => decodeAckFrame(evil)).toThrow(/negative packet number/);
  });

  it('rejects a malicious first range that underflows smallest', () => {
    // largest 3, first range 5 -> smallest = -2
    const evil = bytes(0x02, 0x03, 0x00, 0x00, 0x05);
    expect(() => decodeAckFrame(evil)).toThrow(/negative packet number/);
  });

  it('rejects a range length that underflows below zero', () => {
    // largest 5, first range 3 -> [2..5]; gap 0 -> curStart 0; length 1
    // would need packet -1.
    const evil = bytes(0x02, 0x05, 0x00, 0x01, 0x03, 0x00, 0x01);
    expect(() => decodeAckFrame(evil)).toThrow(/negative packet number/);
  });

  it('enforces the range budget before consuming ranges', () => {
    // count = 1024 encoded as a 2-byte varint (0x44 0x00)
    const tooMany = bytes(0x02, 0x0a, 0x00, 0x44, 0x00, 0x00);
    expect(() => decodeAckFrame(tooMany)).toThrow(/budget/);

    // count = 1 means two ranges; a budget of one must reject it.
    const twoRanges = bytes(0x02, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00);
    expect(() => decodeAckFrame(twoRanges, 0, { maxAckRanges: 1 })).toThrow(/budget/);
  });

  it('rejects malformed framing', () => {
    expect(() => decodeAckFrame(bytes(0x06, 0x0a, 0x00, 0x00, 0x00))).toThrow(
      /ACK frame/,
    );
    expect(() => decodeAckFrame(bytes(0x02))).toThrow(AckFrameError);
    expect(() => decodeAckFrame(bytes(0x02, 0x40))).toThrow(/truncated/);
    expect(() => decodeAckFrame(new Uint8Array(0))).toThrow(AckFrameError);
  });

  it('ignores trailing bytes and reports consumed size', () => {
    const frame = bytes(0x02, 0x05, 0x00, 0x00, 0x00, 0xde, 0xad);
    const decoded = decodeAckFrame(frame);
    expect(decoded.size).toBe(5);
    expect(decoded.ranges).toEqual([{ start: 5n, end: 5n }]);
  });
});

describe('canonical encoding and roundtrips', () => {
  it('produces identical bytes regardless of insertion order', () => {
    const packets = [3n, 100n, 4n, 5n, 0n, 99n, 50n, 1n];
    const forward = encodeAckFrame(addInOrder(packets));
    const reverse = encodeAckFrame(addInOrder([...packets].reverse()));
    const shuffled = encodeAckFrame(addInOrder([50n, 0n, 100n, 1n, 5n, 99n, 3n, 4n]));
    expect(reverse).toEqual(forward);
    expect(shuffled).toEqual(forward);
  });

  it('roundtrips a single packet, packet 0 and the max packet', () => {
    for (const p of [0n, 1n, MAX_PACKET_NUMBER]) {
      const frame = encodeAckFrame(addInOrder([p]));
      expect(decodeAckFrame(frame).ranges).toEqual([{ start: p, end: p }]);
    }
  });

  it('roundtrips adjacent packets and a huge gap', () => {
    const ranges = addInOrder([0n, 1n, 2n, 1_000_000n, 999_999n]);
    const frame = encodeAckFrame(ranges, 777n);
    const decoded = decodeAckFrame(frame);
    expect(decoded.ranges).toEqual(ranges);
    expect(decoded.ackDelay).toBe(777n);
  });

  it('roundtrips many shuffled packets near the varint boundaries', () => {
    const packets: bigint[] = [
      0n,
      62n,
      63n,
      64n,
      16383n,
      16384n,
      MAX_PACKET_NUMBER - 1n,
      MAX_PACKET_NUMBER,
    ];
    const ranges = addInOrder(packets);
    const shuffled = addInOrder([
      MAX_PACKET_NUMBER,
      0n,
      16384n,
      63n,
      MAX_PACKET_NUMBER - 1n,
      16383n,
      64n,
      62n,
    ]);
    expect(shuffled).toEqual(ranges);

    const frame = encodeAckFrame(ranges, 123456n);
    const decoded = decodeAckFrame(frame, 0, { maxAckRanges: 8 });
    expect(decoded.ranges).toEqual(ranges);
    expect(decoded.ackDelay).toBe(123456n);
  });

  it('roundtrips 100 disjoint ranges under a matching budget', () => {
    const packets: bigint[] = [];
    for (let i = 0; i < 100; i++) packets.push(BigInt(i * 10));
    const ranges = addInOrder(packets);
    expect(ranges).toHaveLength(100);

    const frame = encodeAckFrame(ranges);
    const decoded = decodeAckFrame(frame, 0, { maxAckRanges: 100 });
    expect(decoded.ranges).toEqual(ranges);
    expect(() => decodeAckFrame(frame, 0, { maxAckRanges: 99 })).toThrow(/budget/);
  });
});
