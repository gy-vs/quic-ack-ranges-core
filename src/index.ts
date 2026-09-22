// QUIC (RFC 9000) varint and ACK-frame primitives.
//
// ACK ranges are kept as descending, non-overlapping closed intervals:
// `{ start, end }` with `start >= end`, ordered by `start` descending.
// Adjacent intervals are merged as packets are added, so the canonical
// representation does not depend on the order packets were inserted.

export const VARINT_MAX = (1n << 62n) - 1n;
export const PACKET_NUMBER_MAX = VARINT_MAX;

export type Range = { start: bigint; end: bigint };

// ---------------------------------------------------------------------------
// Varint (RFC 9000 §16)
// ---------------------------------------------------------------------------

/** Encode `value` as a QUIC variable-length integer. Returns a fresh buffer. */
export function encodeVarint(value: bigint): Uint8Array {
  if (typeof value !== "bigint" || value < 0n) {
    throw new RangeError("varint value must be a non-negative bigint");
  }
  if (value <= 63n) {
    return Uint8Array.from([Number(value)]);
  }
  if (value < 1n << 14n) {
    const n = Number(value);
    return Uint8Array.from([0x40 | (n >> 8), n & 0xff]);
  }
  if (value < 1n << 30n) {
    const n = Number(value);
    return Uint8Array.from([
      0x80 | ((n >>> 24) & 0xff),
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    ]);
  }
  if (value <= VARINT_MAX) {
    const out = new Uint8Array(8);
    let v = value;
    for (let i = 7; i >= 1; i--) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    // Remaining v holds the top 6 payload bits.
    out[0] = 0xc0 | Number(v & 0x3fn);
    return out;
  }
  throw new RangeError(`varint value exceeds ${VARINT_MAX}`);
}

/** Decode a varint at `offset`; returns null when the buffer is truncated. */
export function decodeVarint(
  data: Uint8Array,
  offset = 0,
): { value: bigint; size: number } | null {
  if (offset < 0 || offset >= data.length) return null;
  const size = 1 << (data[offset] >> 6);
  if (data.length < offset + size) return null;
  let value = BigInt(data[offset] & 63);
  for (let i = 1; i < size; i++) {
    value = (value << 8n) | BigInt(data[offset + i]);
  }
  return { value, size };
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export type AckErrorCode =
  | "EMPTY_ACK"
  | "INVALID_PACKET_NUMBER"
  | "TOO_MANY_RANGES"
  | "INVALID_RANGE"
  | "OVERLAPPING_RANGES"
  | "UNDERFLOW"
  | "TRUNCATED"
  | "UNEXPECTED_END"
  | "BAD_FRAME_TYPE";

export class AckRangeError extends Error {
  readonly code: AckErrorCode;
  constructor(code: AckErrorCode, message: string) {
    super(message);
    this.name = "AckRangeError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Range set
// ---------------------------------------------------------------------------

function isValidPacketNumber(packet: bigint): boolean {
  return (
    typeof packet === "bigint" &&
    packet >= 0n &&
    packet <= PACKET_NUMBER_MAX
  );
}

/**
 * Add one packet number to a descending, merged range list.
 * The input is never mutated; the canonical result is returned and does
 * not depend on insertion order.
 */
export function addPacket(ranges: readonly Range[], packet: bigint): Range[] {
  if (!isValidPacketNumber(packet)) {
    throw new AckRangeError(
      "INVALID_PACKET_NUMBER",
      `packet number out of range: ${packet}`,
    );
  }
  return normalizeRanges([...ranges, { start: packet, end: packet }]);
}

/** Sort descending and merge any overlapping or adjacent closed intervals. */
export function normalizeRanges(ranges: readonly Range[]): Range[] {
  const sorted = [...ranges].sort((a, b) =>
    a.start === b.start ? 0 : a.start > b.start ? -1 : 1,
  );
  const out: Range[] = [];
  for (const r of sorted) {
    if (typeof r.start !== "bigint" || typeof r.end !== "bigint" || r.start < r.end) {
      throw new AckRangeError(
        "INVALID_RANGE",
        `inverted or non-bigint range: ${String(r.start)} < ${String(r.end)}`,
      );
    }
    const prev = out[out.length - 1];
    // r lies at or below prev (start-wise). It merges when its start reaches
    // within one packet of prev's end, including full containment.
    if (prev && r.start + 1n >= prev.end) {
      if (r.end < prev.end) prev.end = r.end;
    } else {
      out.push({ start: r.start, end: r.end });
    }
  }
  return out;
}

/**
 * Verify the ACK range-set invariant: ordered descending, disjoint,
 * non-adjacent, within packet-number bounds. Used while decoding.
 */
export function validateRanges(ranges: readonly Range[]): void {
  if (ranges.length === 0) {
    throw new AckRangeError("EMPTY_ACK", "ACK range set is empty");
  }
  for (const r of ranges) {
    if (
      typeof r.start !== "bigint" ||
      typeof r.end !== "bigint" ||
      r.start < 0n ||
      r.end < 0n
    ) {
      throw new AckRangeError(
        "INVALID_PACKET_NUMBER",
        "range contains a negative or non-bigint packet number",
      );
    }
    if (r.start > PACKET_NUMBER_MAX || r.end > PACKET_NUMBER_MAX) {
      throw new AckRangeError(
        "INVALID_PACKET_NUMBER",
        "range contains a packet number above VARINT_MAX",
      );
    }
    if (r.start < r.end) {
      throw new AckRangeError(
        "INVALID_RANGE",
        `inverted range: ${r.start} < ${r.end}`,
      );
    }
  }
  for (let i = 1; i < ranges.length; i++) {
    const above = ranges[i - 1];
    const below = ranges[i];
    // Merged form requires at least one unacked packet between intervals,
    // i.e. below.start + 1 < above.end.
    if (below.start + 1n >= above.end) {
      throw new AckRangeError(
        "OVERLAPPING_RANGES",
        `ranges overlap or touch around packet ${below.start}`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Encoding (RFC 9000 §19.3)
// ---------------------------------------------------------------------------

export type EncodeAckOptions = {
  /** ACK Delay field value (default 0n). */
  ackDelay?: bigint;
  /** Maximum number of ACK ranges permitted (the intervals count). */
  maxRanges?: number;
};

function appendVarint(chunks: Uint8Array[], value: bigint): void {
  chunks.push(encodeVarint(value));
}

/**
 * Encode a canonical ACK frame (type 0x02) from a merged range set.
 * Throws AckRangeError on semantic violations and RangeError when a
 * field exceeds the 62-bit varint cap.
 */
export function encodeAckFrame(
  ranges: readonly Range[],
  options: EncodeAckOptions = {},
): Uint8Array {
  if (ranges.length === 0) {
    throw new AckRangeError("EMPTY_ACK", "cannot encode an empty ACK frame");
  }
  validateRanges(ranges);
  if (options.maxRanges !== undefined && ranges.length > options.maxRanges) {
    throw new AckRangeError(
      "TOO_MANY_RANGES",
      `ACK range set has ${ranges.length} ranges, limit is ${options.maxRanges}`,
    );
  }

  const ackDelay = options.ackDelay ?? 0n;
  if (ackDelay < 0n || ackDelay > VARINT_MAX) {
    throw new RangeError("ack_delay exceeds varint range");
  }

  const first = ranges[0];
  const largest = first.start;
  const firstRange = largest - first.end; // cannot underflow: start >= end

  const chunks: Uint8Array[] = [];
  appendVarint(chunks, 0x02n);
  appendVarint(chunks, largest);
  appendVarint(chunks, ackDelay);
  appendVarint(chunks, BigInt(ranges.length - 1));
  appendVarint(chunks, firstRange);

  // Following ranges, high to low. gap = unacked packets strictly between
  // the previous range and this one (>= 1 because the set is merged).
  for (let i = 1; i < ranges.length; i++) {
    const prev = ranges[i - 1];
    const cur = ranges[i];

    const gap = prev.end - cur.start - 2n;
    if (gap < 0n) {
      // Merged/overlapping intervals would mean a negative gap; the set is
      // not canonical.
      throw new AckRangeError(
        "OVERLAPPING_RANGES",
        "ACK ranges are not separated by at least one packet",
      );
    }
    if (gap > VARINT_MAX) {
      throw new RangeError("ACK gap exceeds varint range");
    }
    const rangeLength = cur.start - cur.end; // non-negative by invariant
    if (rangeLength > VARINT_MAX) {
      throw new RangeError("ACK range length exceeds varint range");
    }
    appendVarint(chunks, gap);
    appendVarint(chunks, rangeLength);
  }

  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Decoding (RFC 9000 §19.3)
// ---------------------------------------------------------------------------

export type DecodeAckOptions = {
  /** Maximum number of ACK range intervals permitted (default unlimited). */
  maxRanges?: number;
};

export type DecodedAckFrame = {
  largest: bigint;
  ackDelay: bigint;
  rangeCount: bigint;
  firstRange: bigint;
  ranges: Range[];
};

function readVarint(
  data: Uint8Array,
  offset: number,
): { value: bigint; next: number } {
  if (offset >= data.length) {
    throw new AckRangeError("UNEXPECTED_END", "truncated ACK frame");
  }
  const size = 1 << (data[offset] >> 6);
  if (offset + size > data.length) {
    throw new AckRangeError("TRUNCATED", "truncated ACK frame field");
  }
  let value = BigInt(data[offset] & 63);
  for (let i = 1; i < size; i++) {
    value = (value << 8n) | BigInt(data[offset + i]);
  }
  return { value, next: offset + size };
}

/**
 * Decode an ACK frame (type 0x02, or 0x03 with ECN counts skipped).
 *
 * Returns null when `data` is not an ACK frame at all. Malformed ACK
 * frames raise AckRangeError with codes UNDERFLOW, OVERLAPPING_RANGES,
 * TOO_MANY_RANGES, TRUNCATED/UNEXPECTED_END, or BAD_FRAME_TYPE.
 */
export function decodeAckFrame(
  data: Uint8Array,
  offset = 0,
  options: DecodeAckOptions = {},
): DecodedAckFrame | null {
  let p = offset;
  const type = readVarint(data, p);
  if (type.value !== 0x02n && type.value !== 0x03n) return null;
  p = type.next;

  const largestF = readVarint(data, p);
  const largest = largestF.value;
  p = largestF.next;

  const delayF = readVarint(data, p);
  const ackDelay = delayF.value;
  p = delayF.next;

  const countF = readVarint(data, p);
  const rangeCount = countF.value;
  p = countF.next;

  const firstF = readVarint(data, p);
  const firstRange = firstF.value;
  p = firstF.next;

  // Bound the count before allocating/looping so a hostile large count
  // cannot force long work on truncated input.
  if (rangeCount > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new AckRangeError("TOO_MANY_RANGES", "ACK range count is absurd");
  }
  if (options.maxRanges !== undefined && rangeCount + 1n > BigInt(options.maxRanges)) {
    throw new AckRangeError(
      "TOO_MANY_RANGES",
      `ACK frame declares ${rangeCount + 1n} ranges, limit is ${options.maxRanges}`,
    );
  }

  // First range: smallest = largest - first_range.
  const firstSmallest = largest - firstRange;
  if (firstSmallest < 0n) {
    throw new AckRangeError(
      "UNDERFLOW",
      "first ACK range extends below packet number 0",
    );
  }

  const ranges: Range[] = [{ start: largest, end: firstSmallest }];
  let smallest = firstSmallest;

  for (let i = 0n; i < rangeCount; i++) {
    const gapF = readVarint(data, p);
    const gap = gapF.value;
    p = gapF.next;
    const lenF = readVarint(data, p);
    const rangeLength = lenF.value;
    p = lenF.next;

    // cur_largest  = prev_smallest - gap - 2
    const curLargest = smallest - gap - 2n;
    if (curLargest < 0n) {
      throw new AckRangeError(
        "UNDERFLOW",
        "ACK gap produces a negative packet number",
      );
    }
    const curSmallest = curLargest - rangeLength;
    if (curSmallest < 0n) {
      throw new AckRangeError(
        "UNDERFLOW",
        "ACK range length produces a negative packet number",
      );
    }
    if (curLargest + 1n >= smallest) {
      // Overlaps, or ranges with no gap between them (non-canonical).
      throw new AckRangeError(
        "OVERLAPPING_RANGES",
        "ACK ranges overlap or are adjacent",
      );
    }

    ranges.push({ start: curLargest, end: curSmallest });
    smallest = curSmallest;
  }

  validateRanges(ranges);

  // ACK-ECN (type 0x03) appends three ECN counts after the ACK fields.
  if (type.value === 0x03n) {
    for (let i = 0; i < 3; i++) {
      const f = readVarint(data, p);
      p = f.next;
    }
  }

  return { largest, ackDelay, rangeCount, firstRange, ranges };
}
