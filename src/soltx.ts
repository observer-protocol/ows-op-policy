import { base58Encode } from './base58.js';
import { SOLANA_PROGRAMS } from './tokens.js';

// Solana transaction parsing from raw_hex.
//
// The released OWS engine hands the executable the full serialized
// transaction as raw_hex (verified empirically against ows v1.3.2):
//   [compact-u16 sigCount][sigCount × 64-byte sig][message]
// message (legacy):
//   [3-byte header][compact-u16 acctCount][acctCount × 32-byte pubkey]
//   [32-byte recentBlockhash][compact-u16 ixCount][instructions]
// instruction:
//   [u8 programIdIndex][compact-u16 acctIdxCount][acctIdxCount × u8]
//   [compact-u16 dataLen][dataLen bytes]
//
// Versioned (v0) transactions set the high bit (0x80) on the first message
// byte; we detect and reject them as unsupported-for-enforcement rather than
// mis-parse (fail closed).

export interface SolTransfer {
  kind: 'system' | 'spl-transfer' | 'spl-transfer-checked';
  amount: bigint; // lamports (system) or raw token units (spl)
  destination: string; // base58: wallet (system) or token account (spl)
  source?: string;
  mint?: string; // base58 mint, only for transfer-checked
  decimals?: number; // only for transfer-checked
}

export interface ParsedSolTx {
  transfers: SolTransfer[];
  instructionCount: number;
  unsupportedInstructions: number; // instructions we didn't recognise
}

class Reader {
  constructor(private buf: Buffer, public pos = 0) {}
  u8(): number {
    if (this.pos >= this.buf.length) throw new Error('solana: unexpected end of input');
    return this.buf[this.pos++] as number;
  }
  take(n: number): Buffer {
    if (this.pos + n > this.buf.length) throw new Error('solana: unexpected end of input');
    const b = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return b;
  }
  // compact-u16 / shortvec
  shortvec(): number {
    let val = 0;
    let shift = 0;
    for (;;) {
      const b = this.u8();
      val |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
      if (shift > 21) throw new Error('solana: shortvec too long');
    }
    return val >>> 0;
  }
  remaining(): number {
    return this.buf.length - this.pos;
  }
}

const SYSTEM_TRANSFER_IX = 2; // SystemInstruction::Transfer (u32 LE discriminator)
const TOKEN_TRANSFER_IX = 3; // SPL TokenInstruction::Transfer (u8)
const TOKEN_TRANSFER_CHECKED_IX = 12; // SPL TokenInstruction::TransferChecked (u8)

export function parseSolanaRawTx(rawHex: string): ParsedSolTx {
  const hex = rawHex.startsWith('0x') ? rawHex.slice(2) : rawHex;
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) throw new Error('raw_hex is not byte-aligned hex');
  const r = new Reader(Buffer.from(hex, 'hex'));

  // signatures
  const sigCount = r.shortvec();
  r.take(sigCount * 64);

  // message header — detect versioned tx (high bit on first byte)
  const firstMsgByte = r.u8();
  if ((firstMsgByte & 0x80) !== 0) {
    throw new Error('versioned (v0) Solana transactions are not yet parsed — enforcement fails closed on this rail');
  }
  // firstMsgByte is numRequiredSignatures; read the other two header bytes
  r.u8(); // numReadonlySignedAccounts
  r.u8(); // numReadonlyUnsignedAccounts

  // account keys
  const acctCount = r.shortvec();
  const accounts: string[] = [];
  for (let i = 0; i < acctCount; i++) accounts.push(base58Encode(r.take(32)));

  // recent blockhash
  r.take(32);

  // instructions
  const ixCount = r.shortvec();
  const transfers: SolTransfer[] = [];
  let unsupported = 0;

  for (let i = 0; i < ixCount; i++) {
    const programIdIndex = r.u8();
    const nAccts = r.shortvec();
    const acctIdx: number[] = [];
    for (let j = 0; j < nAccts; j++) acctIdx.push(r.u8());
    const dataLen = r.shortvec();
    const data = r.take(dataLen);
    const programId = accounts[programIdIndex];

    if (programId === SOLANA_PROGRAMS.SYSTEM) {
      // SystemInstruction::Transfer { lamports: u64 } — disc u32 LE = 2, accounts [from, to]
      if (data.length >= 12 && data.readUInt32LE(0) === SYSTEM_TRANSFER_IX && acctIdx.length >= 2) {
        transfers.push({
          kind: 'system',
          amount: data.readBigUInt64LE(4),
          source: accounts[acctIdx[0] as number],
          destination: accounts[acctIdx[1] as number] as string,
        });
        continue;
      }
      unsupported++;
      continue;
    }

    if (programId === SOLANA_PROGRAMS.TOKEN || programId === SOLANA_PROGRAMS.TOKEN_2022) {
      const disc = data.length > 0 ? (data[0] as number) : -1;
      if (disc === TOKEN_TRANSFER_CHECKED_IX && data.length >= 9 && acctIdx.length >= 4) {
        // TransferChecked: data = [12][amount u64][decimals u8]; accounts [source, mint, dest, owner]
        transfers.push({
          kind: 'spl-transfer-checked',
          amount: data.readBigUInt64LE(1),
          decimals: data.length >= 10 ? (data[9] as number) : undefined,
          source: accounts[acctIdx[0] as number],
          mint: accounts[acctIdx[1] as number],
          destination: accounts[acctIdx[2] as number] as string,
        });
        continue;
      }
      if (disc === TOKEN_TRANSFER_IX && data.length >= 9 && acctIdx.length >= 3) {
        // Transfer: data = [3][amount u64]; accounts [source, dest, owner]; mint NOT in tx
        transfers.push({
          kind: 'spl-transfer',
          amount: data.readBigUInt64LE(1),
          source: accounts[acctIdx[0] as number],
          destination: accounts[acctIdx[1] as number] as string,
        });
        continue;
      }
      unsupported++;
      continue;
    }

    unsupported++;
  }

  return { transfers, instructionCount: ixCount, unsupportedInstructions: unsupported };
}
