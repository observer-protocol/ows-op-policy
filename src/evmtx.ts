// EVM unsigned-transaction parsing from raw_hex.
//
// The released OWS engine (v1.3.2) hands executables `transaction.raw_hex`
// only — the parsed to/value/data fields described in the main-branch docs
// are newer than the latest release. We therefore decode EVM payloads
// ourselves: EIP-1559 (type 2), EIP-2930 (type 1), and legacy RLP. When the
// engine does provide parsed fields, those are used as-is.

export interface ParsedEvmTx {
  chainId?: bigint;
  to?: string; // 0x… or undefined for contract creation
  value: bigint;
  data: string; // 0x…
}

interface RlpItem {
  bytes?: Buffer;
  list?: RlpItem[];
}

function rlpDecode(buf: Buffer, offset = 0): { item: RlpItem; next: number } {
  if (offset >= buf.length) throw new Error('rlp: unexpected end of input');
  const b = buf[offset] as number;
  if (b < 0x80) return { item: { bytes: buf.subarray(offset, offset + 1) }, next: offset + 1 };
  if (b <= 0xb7) {
    const len = b - 0x80;
    return { item: { bytes: buf.subarray(offset + 1, offset + 1 + len) }, next: offset + 1 + len };
  }
  if (b <= 0xbf) {
    const lenLen = b - 0xb7;
    const len = Number(BigInt('0x' + buf.subarray(offset + 1, offset + 1 + lenLen).toString('hex')));
    const start = offset + 1 + lenLen;
    return { item: { bytes: buf.subarray(start, start + len) }, next: start + len };
  }
  let payloadLen: number;
  let start: number;
  if (b <= 0xf7) {
    payloadLen = b - 0xc0;
    start = offset + 1;
  } else {
    const lenLen = b - 0xf7;
    payloadLen = Number(BigInt('0x' + buf.subarray(offset + 1, offset + 1 + lenLen).toString('hex')));
    start = offset + 1 + lenLen;
  }
  const end = start + payloadLen;
  const list: RlpItem[] = [];
  let pos = start;
  while (pos < end) {
    const { item, next } = rlpDecode(buf, pos);
    list.push(item);
    pos = next;
  }
  if (pos !== end) throw new Error('rlp: list payload length mismatch');
  return { item: { list }, next: end };
}

const toBigInt = (item: RlpItem): bigint => {
  const b = item.bytes ?? Buffer.alloc(0);
  return b.length === 0 ? 0n : BigInt('0x' + b.toString('hex'));
};
const toAddress = (item: RlpItem): string | undefined => {
  const b = item.bytes ?? Buffer.alloc(0);
  if (b.length === 0) return undefined; // contract creation
  if (b.length !== 20) throw new Error(`rlp: address field is ${b.length} bytes, expected 20`);
  return '0x' + b.toString('hex');
};
const toData = (item: RlpItem): string => '0x' + (item.bytes ?? Buffer.alloc(0)).toString('hex');

export function parseEvmRawTx(rawHex: string): ParsedEvmTx {
  const hex = rawHex.startsWith('0x') ? rawHex.slice(2) : rawHex;
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length === 0) throw new Error('raw_hex is not hex');
  const buf = Buffer.from(hex, 'hex');
  const typeByte = buf[0] as number;

  if (typeByte === 0x02 || typeByte === 0x01) {
    const { item } = rlpDecode(buf.subarray(1));
    const fields = item.list;
    if (!fields) throw new Error('typed tx payload is not an RLP list');
    if (typeByte === 0x02) {
      // [chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data, accessList, ...]
      if (fields.length < 9) throw new Error(`EIP-1559 tx has ${fields.length} fields, expected ≥9`);
      return {
        chainId: toBigInt(fields[0] as RlpItem),
        to: toAddress(fields[5] as RlpItem),
        value: toBigInt(fields[6] as RlpItem),
        data: toData(fields[7] as RlpItem),
      };
    }
    // type 1: [chainId, nonce, gasPrice, gas, to, value, data, accessList, ...]
    if (fields.length < 8) throw new Error(`EIP-2930 tx has ${fields.length} fields, expected ≥8`);
    return {
      chainId: toBigInt(fields[0] as RlpItem),
      to: toAddress(fields[4] as RlpItem),
      value: toBigInt(fields[5] as RlpItem),
      data: toData(fields[6] as RlpItem),
    };
  }

  if (typeByte >= 0xc0) {
    // Legacy RLP list: [nonce, gasPrice, gas, to, value, data] with optional
    // EIP-155 trailer [chainId, 0, 0] on unsigned transactions.
    const { item } = rlpDecode(buf);
    const fields = item.list;
    if (!fields || fields.length < 6) throw new Error('legacy tx is not a ≥6-field RLP list');
    return {
      chainId: fields.length >= 9 ? toBigInt(fields[6] as RlpItem) : undefined,
      to: toAddress(fields[3] as RlpItem),
      value: toBigInt(fields[4] as RlpItem),
      data: toData(fields[5] as RlpItem),
    };
  }

  throw new Error(`unsupported EVM transaction type byte 0x${typeByte.toString(16)}`);
}
