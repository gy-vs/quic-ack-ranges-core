// QUIC packet number core.
//
// ACK ranges are represented as descending, non-overlapping closed intervals
// {start, end} where `start` is the largest packet number in the interval and
// `end` is the smallest. Adding a packet merges it into an existing interval
// when it is contained or adjacent on either side.

export type Range = { start: bigint; end: bigint };

/** Largest value encodable as a QUIC variable-length integer (RFC 9000 §16). */
export const MAX_VARINT = (1n << 62n) - 1n;

/** Largest QUIC packet number; packet numbers are unsigned 62-bit integers. */
export const MAX_PACKET_NUMBER = (1n << 62n) - 1n;

const ACK_FRAME_TYPE = 0x02;

/** Error thrown when an ACK frame cannot be encoded or decoded. */
export class AckFrameError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AckFrameError';
  }
}

function assertPacketNumber(value: bigint, what: string): void {
  if (value < 0n) throw new AckFrameError(`${what} must not be negative`);
  if (value > MAX_PACKET_NUMBER) {
    throw new AckFrameError(`${what} exceeds the 62-bit packet number limit`);
  }
}

export function decodeVarint(
  data: Uint8Array,
  offset = 0,
): { value: bigint; size: number } | null {
  if (offset >= data.length) return null;
  const size = 1 << (data[offset] >> 6);
  if (data.length < offset + size) return null;
  let value = BigInt(data[offset] & 63);
  for (let i = 1; i < size; i++) value = (value << 8n) | BigInt(data[offset + i]);
  return { value, size };
}

/** Encode a non-negative integer no larger than 2^62-1 as a QUIC varint. */
export function encodeVarint(value: bigint): Uint8Array {
  if (value < 0n) throw new AckFrameError('varint must not be negative');
  if (value > MAX_VARINT) throw new AckFrameError('varint exceeds 2^62-1');

  const length =
    value < 1n << 6n
      ? 1
      : value < 1n << 14n
        ? 2
        : value < 1n << 30n
          ? 4
          : 8;

  const out = new Uint8Array(length);
  for (let i = length - 1; i > 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  out[0] = Number(value) | ((Math.log2(length) << 6) & 0xff);
  return out;
}

/**
 * Add a packet number to a descending, non-overlapping range set.
 * Adjacent and overlapping intervals are merged; duplicates are a no-op.
 * The input array is never mutated.
 */
export function addPacket(ranges: readonly Range[], packet: bigint): Range[] {
  assertPacketNumber(packet, 'packet number');

  // Insert as a singleton in descending order.
  let pos = ranges.length;
  for (let i = 0; i < ranges.length; i++) {
    if (packet > ranges[i].start) {
      pos = i;
      break;
    }
  }
  const next: Range[] = ranges.map((r) => ({ start: r.start, end: r.end }));
  next.splice(pos, 0, { start: packet, end: packet });

  // Merge every interval that overlaps or is adjacent to its predecessor:
  // with intervals sorted descending by start, `second` touches `first`
  // exactly when second.start + 1 >= first.end.
  for (let i = 1; i < next.length; ) {
    const first = next[i - 1];
    const second = next[i];
    if (second.start + 1n >= first.end) {
      first.end = second.end < first.end ? second.end : first.end;
      next.splice(i, 1);
    } else {
      i++;
    }
  }
  return next;
}

function concatChunks(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/**
 * Encode an ACK frame (type 0x02, without ECN counters) from a descending
 * non-overlapping range set. Throws AckFrameError on empty input, underflow
 * while computing gaps/first range, or any value above the varint limit.
 */
export function encodeAckFrame(
  ranges: readonly Range[],
  ackDelay = 0n,
): Uint8Array {
  if (ranges.length === 0) throw new AckFrameError('cannot ACK an empty range set');
  if (ackDelay < 0n) throw new AckFrameError('ack delay must not be negative');

  for (const r of ranges) {
    if (typeof r.start !== 'bigint' || typeof r.end !== 'bigint') {
      throw new AckFrameError('range bounds must be bigint packet numbers');
    }
    if (r.start < r.end) throw new AckFrameError('range start must be >= end');
    assertPacketNumber(r.start, 'packet number');
    assertPacketNumber(r.end, 'packet number');
  }

  const chunks: Uint8Array[] = [
    new Uint8Array([ACK_FRAME_TYPE]),
    encodeVarint(ranges[0].start), // largest acknowledged
    encodeVarint(ackDelay),
    encodeVarint(BigInt(ranges.length - 1)), // ack range count
  ];

  // First ACK Range: number of packets below largest up to the end of the
  // first interval. Checked for underflow and the varint ceiling.
  const firstRange = ranges[0].start - ranges[0].end;
  if (firstRange > MAX_VARINT) throw new AckFrameError('first range exceeds varint limit');
  chunks.push(encodeVarint(firstRange));

  for (let i = 1; i < ranges.length; i++) {
    const prev = ranges[i - 1];
    const cur = ranges[i];

    // Gap is the number of unacknowledged packets between the intervals,
    // minus one (RFC 9000 §19.3.1). If this subtraction is negative the
    // intervals overlapped or were adjacent, i.e. they were not canonical.
    if (prev.end < cur.start + 2n) {
      throw new AckFrameError('ACK ranges overlap or are adjacent (gap underflow)');
    }
    const gap = prev.end - cur.start - 2n;
    if (gap > MAX_VARINT) throw new AckFrameError('gap exceeds varint limit');

    const length = cur.start - cur.end;
    if (length > MAX_VARINT) throw new AckFrameError('range length exceeds varint limit');

    chunks.push(encodeVarint(gap), encodeVarint(length));
  }

  return concatChunks(chunks);
}

export type DecodedAckFrame = {
  ranges: Range[];
  ackDelay: bigint;
  /** Total number of bytes consumed from the input. */
  size: number;
};

export type DecodeOptions = {
  /** Maximum number of ACK ranges the decoder is willing to accept. */
  maxAckRanges?: number;
};

function readVarint(data: Uint8Array, offset: number, what: string) {
  const decoded = decodeVarint(data, offset);
  if (decoded === null) throw new AckFrameError(`truncated ACK frame while reading ${what}`);
  return decoded;
}

/**
 * Decode an ACK frame (type 0x02) back into a descending range set. Rejects
 * frames that would produce negative packet numbers, overlapping ranges, or
 * more ranges than maxAckRanges (default 1024).
 */
export function decodeAckFrame(
  data: Uint8Array,
  offset = 0,
  options: DecodeOptions = {},
): DecodedAckFrame {
  const maxAckRanges = options.maxAckRanges ?? 1024;
  if (!Number.isInteger(maxAckRanges) || maxAckRanges < 1) {
    throw new AckFrameError('maxAckRanges must be a positive integer');
  }

  if (data.length <= offset) throw new AckFrameError('truncated ACK frame: no frame type');
  if (data[offset] !== ACK_FRAME_TYPE) {
    throw new AckFrameError('expected an ACK frame (type 0x02)');
  }
  let pos = offset + 1;

  let field = readVarint(data, pos, 'largest acknowledged');
  const largest = field.value;
  pos += field.size;
  if (largest < 0n || largest > MAX_PACKET_NUMBER) {
    throw new AckFrameError('largest acknowledged is not a valid packet number');
  }

  field = readVarint(data, pos, 'ack delay');
  const ackDelay = field.value;
  pos += field.size;
  if (ackDelay > MAX_VARINT) throw new AckFrameError('ack delay exceeds varint limit');

  field = readVarint(data, pos, 'ACK range count');
  const count = field.value;
  pos += field.size;
  // Reject oversized allocations before attempting to build any ranges.
  if (count > BigInt(maxAckRanges - 1)) {
    throw new AckFrameError(`ACK range count ${count} exceeds the configured budget`);
  }

  field = readVarint(data, pos, 'first ACK range');
  const firstRange = field.value;
  pos += field.size;
  if (firstRange > largest) {
    throw new AckFrameError('first ACK range produces a negative packet number');
  }
  if (firstRange > MAX_VARINT) throw new AckFrameError('first ACK range exceeds varint limit');

  const ranges: Range[] = [{ start: largest, end: largest - firstRange }];

  for (let i = 0n; i < count; i++) {
    field = readVarint(data, pos, 'gap');
    const gap = field.value;
    pos += field.size;
    if (gap > MAX_VARINT) throw new AckFrameError('gap exceeds varint limit');

    field = readVarint(data, pos, 'ACK range length');
    const length = field.value;
    pos += field.size;
    if (length > MAX_VARINT) throw new AckFrameError('ACK range length exceeds varint limit');

    const prevEnd = ranges[ranges.length - 1].end;

    // smallest = prevEnd - gap - 2. Guard the subtraction so a malicious gap
    // can never wrap the packet number below zero.
    if (gap + 2n > prevEnd) {
      throw new AckFrameError('gap produces a negative packet number');
    }
    const rangeStart = prevEnd - gap - 2n;
    if (length > rangeStart) {
      throw new AckFrameError('ACK range length produces a negative packet number');
    }
    const rangeEnd = rangeStart - length;

    // Redundant given the gap underflow guards above, but kept as an explicit
    // overlap/canonical-order invariant.
    if (rangeStart + 1n >= prevEnd) {
      throw new AckFrameError('ACK ranges overlap');
    }

    ranges.push({ start: rangeStart, end: rangeEnd });
  }

  return { ranges, ackDelay, size: pos - offset };
}
