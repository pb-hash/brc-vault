// BRC Vault core: key checks, password encryption, and BrowserCoin wallet-file conversion.
// Runs entirely locally. No network access is needed or used.

import * as ed from '@noble/ed25519';
import { sha512, sha256 } from '@noble/hashes/sha2';
import { scryptAsync } from '@noble/hashes/scrypt';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const BACKUP_TYPE = 'brc-vault-backup';
export const BACKUP_VERSION = 1;
export const COMPACT_PREFIX = 'BRCVAULT1';
// Prefix for an unprotected private key on a paper wallet, so it can't be confused with an address.
export const KEY_PREFIX = 'BRCKEY1';
export const BROWSERCOIN_WALLET_TYPE = 'browsercoin-wallet';
// Matches the warning text BrowserCoin's own Export writes into wallet files.
export const BROWSERCOIN_WARNING = 'Anyone with the private key controls the wallet. Keep this safe.';

// scrypt cost. N = 2^17, r = 8, p = 1 uses 128 MiB of memory per attempt, which
// makes password guessing expensive. Stored in each backup so future versions
// can raise it without breaking old backups.
export const DEFAULT_KDF = { name: 'scrypt', logN: 17, r: 8, p: 1, dkLen: 32 };
// Backups are only accepted within these limits, so a crafted backup can't freeze
// the page with an enormous memory or time cost.
const MIN_LOG_N = 14;
const MAX_LOG_N = 18;

export const MIN_PASSWORD_LENGTH = 12;

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

const HEX_RE = /^[0-9a-f]*$/;

export function bytesToHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function hexToBytes(hex, expectedLen) {
  let h = String(hex).trim().toLowerCase();
  if (h.startsWith('0x')) h = h.slice(2);
  if (h.length % 2 !== 0 || !HEX_RE.test(h)) throw new Error('Not valid hex.');
  if (expectedLen !== undefined && h.length !== expectedLen * 2) {
    throw new Error(`Expected ${expectedLen} bytes (${expectedLen * 2} hex characters), got ${h.length / 2}.`);
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/** BrowserCoin addresses are the 32-byte Ed25519 public key, written as 64 hex characters. */
export function addressFromPrivateKey(privateKeyBytes) {
  if (!(privateKeyBytes instanceof Uint8Array) || privateKeyBytes.length !== 32) {
    throw new Error('A BrowserCoin private key is exactly 32 bytes (64 hex characters).');
  }
  return bytesToHex(ed.getPublicKey(privateKeyBytes));
}

/** Short form for display: first 10 and last 4 characters, like the BrowserCoin explorer. */
export function shortAddress(address) {
  return `${address.slice(0, 10)}…${address.slice(-4)}`;
}

/**
 * A loaded wallet: private key bytes plus the address they control. The address
 * is always recomputed from the key, never trusted from a file.
 */
export function walletFromPrivateKeyHex(privateKeyHex) {
  const privateKey = hexToBytes(privateKeyHex, 32);
  return { privateKey, address: addressFromPrivateKey(privateKey) };
}

// ---------------------------------------------------------------------------
// BrowserCoin wallet files (the format BrowserCoin's Settings → Export/Import uses)
// ---------------------------------------------------------------------------

/**
 * Parse a BrowserCoin wallet export. Checks that the address written in the file
 * really belongs to the private key, so a corrupted or edited file is caught.
 */
export function parseBrowserCoinWallet(text) {
  let parsed;
  try { parsed = JSON.parse(text); } catch { throw new Error('This file is not valid JSON.'); }
  if (!parsed || parsed.type !== BROWSERCOIN_WALLET_TYPE) {
    throw new Error('This is not a BrowserCoin wallet file (it should come from BrowserCoin Settings → Export key).');
  }
  if (typeof parsed.privateKeyHex !== 'string') throw new Error('The wallet file has no private key in it.');
  const wallet = walletFromPrivateKeyHex(parsed.privateKeyHex);
  if (parsed.address && String(parsed.address).toLowerCase() !== wallet.address) {
    throw new Error('The address written in this file does not match its private key. The file may be damaged.');
  }
  return wallet;
}

/** Produce a wallet file byte-for-byte in the layout BrowserCoin's own Export writes. */
export function browserCoinWalletJson(wallet) {
  return JSON.stringify({
    type: BROWSERCOIN_WALLET_TYPE,
    version: 1,
    address: wallet.address,
    privateKeyHex: bytesToHex(wallet.privateKey),
    warning: BROWSERCOIN_WARNING,
  }, null, 2);
}

export function browserCoinWalletFilename(wallet) {
  return `browsercoin-wallet-${wallet.address.slice(0, 8)}.json`;
}

// ---------------------------------------------------------------------------
// Password encryption
// ---------------------------------------------------------------------------

function checkKdf(kdf) {
  if (!kdf || kdf.name !== 'scrypt') throw new Error('Unsupported key-stretching method in this backup.');
  const { logN, r, p, dkLen } = kdf;
  const ok = Number.isInteger(logN) && logN >= MIN_LOG_N && logN <= MAX_LOG_N
    && r === 8 && p === 1 && dkLen === 32;
  if (!ok) throw new Error('This backup has invalid or unsafe key-stretching settings.');
}

async function deriveKey(password, salt, kdf, onProgress) {
  checkKdf(kdf);
  const pw = new TextEncoder().encode(password.normalize('NFKC'));
  const raw = await scryptAsync(pw, salt, {
    N: 2 ** kdf.logN, r: kdf.r, p: kdf.p, dkLen: kdf.dkLen,
    onProgress: onProgress ? (x) => onProgress(x) : undefined,
    asyncTick: 25,
  });
  pw.fill(0);
  const key = await globalThis.crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  raw.fill(0);
  return key;
}

/**
 * Everything except the ciphertext is bound into the encryption as associated
 * data, so swapping the address or weakening the settings makes decryption fail.
 */
function associatedData(address, kdf, saltHex, ivHex) {
  return new TextEncoder().encode(
    [BACKUP_TYPE, BACKUP_VERSION, address, kdf.name, kdf.logN, kdf.r, kdf.p, kdf.dkLen, saltHex, ivHex].join('|'),
  );
}

export function passwordProblems(password, confirm) {
  const problems = [];
  if (password.length < MIN_PASSWORD_LENGTH) problems.push(`Use at least ${MIN_PASSWORD_LENGTH} characters.`);
  else if (new Set(password).size < 6) problems.push('That password is too repetitive. Use a mix of words or characters.');
  if (confirm !== undefined && password !== confirm) problems.push('The two passwords do not match.');
  return problems;
}

const HEX_FIELD = (name, len) => (v) => {
  const h = String(v ?? '').toLowerCase();
  if (!new RegExp(`^[0-9a-f]{${len * 2}}$`).test(h)) {
    throw new Error(`The ${name} in this backup is damaged (expected ${len * 2} hex characters).`);
  }
  return h;
};
const checkAddress = HEX_FIELD('address', 32);
const checkSalt = HEX_FIELD('salt', 16);
const checkIv = HEX_FIELD('iv', 12);
const checkCiphertext = HEX_FIELD('locked key', 48);

/**
 * Check every field of a backup before anything is shown or any slow work is
 * done, and return a clean copy. Throws a plain-English error if anything is off.
 */
export function validateBackup(b) {
  if (!b || typeof b !== 'object' || b.type !== BACKUP_TYPE) throw new Error('This is not a BRC Vault backup.');
  if (b.version !== BACKUP_VERSION) throw new Error(`This backup is version ${String(b.version).slice(0, 8)}; this copy of BRC Vault reads version ${BACKUP_VERSION}.`);
  const k = b.kdf || {};
  const kdf = { name: k.name, logN: k.logN, r: k.r, p: k.p, dkLen: k.dkLen };
  checkKdf(kdf);
  if (!b.cipher || b.cipher.name !== 'aes-256-gcm') throw new Error('Unsupported encryption method in this backup.');
  return {
    type: BACKUP_TYPE,
    version: BACKUP_VERSION,
    address: checkAddress(b.address),
    kdf: { ...kdf, salt: checkSalt(k.salt) },
    cipher: { name: 'aes-256-gcm', iv: checkIv(b.cipher.iv) },
    ciphertext: checkCiphertext(b.ciphertext),
  };
}

/** Encrypt a wallet with a password. Returns the backup object (format described on the page). */
export async function encryptWallet(wallet, password, { kdf = DEFAULT_KDF, onProgress } = {}) {
  const problems = passwordProblems(password);
  if (problems.length) throw new Error(problems.join(' '));
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const saltHex = bytesToHex(salt);
  const ivHex = bytesToHex(iv);
  const key = await deriveKey(password, salt, kdf, onProgress);
  const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: associatedData(wallet.address, kdf, saltHex, ivHex), tagLength: 128 },
    key,
    wallet.privateKey,
  ));
  return {
    type: BACKUP_TYPE,
    version: BACKUP_VERSION,
    address: wallet.address,
    kdf: { ...kdf, salt: saltHex },
    cipher: { name: 'aes-256-gcm', iv: ivHex },
    ciphertext: bytesToHex(ct),
    created: new Date().toISOString().slice(0, 10),
    note: 'Locked BRC Vault backup. The private key is encrypted inside "ciphertext" and can only be unlocked with your password in BRC Vault. The address is public and safe to share.',
  };
}

/** Decrypt a backup object. Throws a plain-English error on a wrong password or damaged backup. */
export async function decryptBackup(backup, password, { onProgress } = {}) {
  const b = validateBackup(backup);
  const { salt: saltHex, ...kdf } = b.kdf;
  const salt = hexToBytes(saltHex, 16);
  const iv = hexToBytes(b.cipher.iv, 12);
  const ct = hexToBytes(b.ciphertext, 48);
  const key = await deriveKey(password, salt, kdf, onProgress);
  let pt;
  try {
    pt = new Uint8Array(await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: associatedData(b.address, kdf, saltHex, b.cipher.iv), tagLength: 128 },
      key,
      ct,
    ));
  } catch {
    throw new Error('Wrong password, or the backup has been changed or damaged.');
  }
  const wallet = { privateKey: pt, address: addressFromPrivateKey(pt) };
  if (wallet.address !== b.address) throw new Error('The decrypted key does not match the address in the backup.');
  return wallet;
}

// ---------------------------------------------------------------------------
// Compact one-line form (for paper QR codes and typing back in)
// BRCVAULT1:<address>:<logN>:<r>:<p>:<salt>:<iv>:<ciphertext>
// ---------------------------------------------------------------------------

export function backupToCompact(b) {
  // Upper case keeps it inside the QR "alphanumeric" alphabet, which gives a smaller code.
  return [COMPACT_PREFIX, b.address, b.kdf.logN, b.kdf.r, b.kdf.p, b.kdf.salt, b.cipher.iv, b.ciphertext].join(':').toUpperCase();
}

const SMALL_INT = /^(0|[1-9][0-9]{0,2})$/;

export function compactToBackup(text) {
  const parts = String(text).replace(/\s+/g, '').split(':');
  if (parts[0].toUpperCase() !== COMPACT_PREFIX) throw new Error('This is not a BRC Vault backup code.');
  if (parts.length !== 8) throw new Error('This backup code has the wrong number of parts. Check that every line, including the colons, was copied.');
  const [, address, logN, r, p, salt, iv, ciphertext] = parts;
  for (const [label, v] of [['strength settings', logN], ['strength settings', r], ['strength settings', p]]) {
    if (!SMALL_INT.test(v)) throw new Error(`The ${label} in this backup code are damaged.`);
  }
  return validateBackup({
    type: BACKUP_TYPE,
    version: BACKUP_VERSION,
    address,
    kdf: { name: 'scrypt', logN: Number(logN), r: Number(r), p: Number(p), dkLen: 32, salt },
    cipher: { name: 'aes-256-gcm', iv },
    ciphertext,
  });
}

// ---------------------------------------------------------------------------
// Paper layout with per-line typo checks
// ---------------------------------------------------------------------------

/**
 * Text for a QR code: the code itself, starting "BRCVAULT1:" or "BRCKEY1:".
 * Phone camera apps treat a leading "WORD:" as a link to an app they don't
 * have, so they show nothing and, importantly, never offer to search the web
 * for it. (Plain text would be one tap away from a web search.) Paper codes are
 * meant to be scanned with BRC Vault's own scanner.
 */
export function qrPayload(compactOrKey) {
  return String(compactOrKey).replace(/^(BRCVAULT1|BRCKEY1) /, '$1:');
}

/** 4-character check for one printed line, so a typo is caught before the slow password step. */
export function lineCheck(content) {
  const norm = String(content).replace(/\s+/g, '').toUpperCase();
  return bytesToHex(sha256(new TextEncoder().encode(norm))).slice(0, 4).toUpperCase();
}

/**
 * Lay the paper code out one field per line. Each line gets a 4-character check
 * printed in brackets. When the code is typed back in, a wrong check names the
 * exact line with the typo. Spaces and line breaks are ignored.
 */
export function paperCodeLines(code) {
  const [prefix, address, logN, r, p, salt, iv, ct] = code.split(':');
  // At most 32 hex characters per line, so every line fits on a Letter or A4 page.
  const lines = [
    `${prefix}:`,
    chunkForPaper(address.slice(0, 32)),
    `${chunkForPaper(address.slice(32))}:`,
    `${logN}:${r}:${p}:`,
    `${chunkForPaper(salt)}:`,
    `${chunkForPaper(iv)}:`,
    chunkForPaper(ct.slice(0, 32)),
    chunkForPaper(ct.slice(32, 64)),
    chunkForPaper(ct.slice(64)),
  ];
  return lines.map((text) => ({ text, check: lineCheck(text) }));
}

/** Format paper lines as plain text, the same way they are printed. */
export function paperCodeText(code) {
  return paperCodeLines(code).map((l) => `${l.text} [${l.check}]`).join('\n');
}

/**
 * Accept a code typed from paper, with or without the [XXXX] checks. If checks
 * are present they are verified line by line before anything else happens.
 */
export function stripPaperChecks(text) {
  const t = String(text);
  if (!t.includes('[')) return t;
  const re = /([^[\]]*)\[\s*([0-9a-fA-F]{4})\s*\]/g;
  let m;
  let line = 0;
  let joined = '';
  let consumed = 0;
  while ((m = re.exec(t)) !== null) {
    line++;
    if (lineCheck(m[1]) !== m[2].toUpperCase()) {
      throw new Error(`Line ${line} of the backup code has a typo: it doesn't match its check [${m[2].toUpperCase()}]. Compare that line with the paper, watching for 0/D and 8/B.`);
    }
    joined += m[1];
    consumed = re.lastIndex;
  }
  if (line === 0 || t.slice(consumed).trim() !== '') {
    throw new Error('Part of the backup code is missing its check in brackets. Copy every line, including the [XXXX] at the end.');
  }
  return joined;
}

/** Group a long code into blocks for easier copying by hand. */
export function chunkForPaper(code, size = 4) {
  return code.match(new RegExp(`.{1,${size}}`, 'g')).join(' ');
}

// ---------------------------------------------------------------------------
// Reading whatever the person gives us
// ---------------------------------------------------------------------------

/**
 * Work out what a pasted or loaded text is:
 *   { kind: 'browsercoin-wallet', wallet }
 *   { kind: 'vault-backup', backup }
 *   { kind: 'private-key', wallet, ambiguous }
 * A bare 64-character hex string is `ambiguous`: it could be a private key, or
 * it could be an address pasted by mistake, which looks exactly the same.
 */
export function identifyInput(text) {
  // QR codes carry "BRCVAULT1 …" / "BRCKEY1 …" with a space, because phone
  // cameras treat "WORD:" as a link to an unknown app and refuse to show it.
  const t = String(text).trim().replace(/^(BRCVAULT1|BRCKEY1)[ \t]+(?=[0-9A-Fa-f])/i, (m, p) => `${p.toUpperCase()}:`);
  if (!t) throw new Error('Nothing to read yet.');
  const squashed = t.toUpperCase().replace(/\s+/g, '');
  if (squashed.startsWith(COMPACT_PREFIX + ':')) {
    return { kind: 'vault-backup', backup: compactToBackup(stripPaperChecks(t)) };
  }
  if (squashed.startsWith(KEY_PREFIX + ':')) {
    const hex = squashed.slice(KEY_PREFIX.length + 1).toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error('This private key code is damaged. It should have 64 characters after BRCKEY1:.');
    return { kind: 'private-key', wallet: walletFromPrivateKeyHex(hex), ambiguous: false };
  }
  if (t.startsWith('{')) {
    const parsed = parseJsonLoose(t);
    if (parsed) {
      if (parsed.type === BACKUP_TYPE) return { kind: 'vault-backup', backup: validateBackup(parsed) };
      if (parsed.type === BROWSERCOIN_WALLET_TYPE) return { kind: 'browsercoin-wallet', wallet: parseBrowserCoinWallet(JSON.stringify(parsed)) };
      throw new Error('This file is neither a BrowserCoin wallet nor a BRC Vault backup.');
    }
    const rescued = rescueFromDamagedText(t);
    if (rescued) return rescued;
    if (/^\{\\rtf/.test(t)) {
      throw new Error('This file was re-saved by a word processor such as TextEdit, which changed its format, and the key could not be recovered from it. Use the original file BrowserCoin downloaded.');
    }
    throw new Error("This file is incomplete or was changed by another app, so it can't be read. Use the original file BrowserCoin downloaded (named browsercoin-wallet-…json), not a copy opened and saved in a text editor.");
  }
  const hex = t.replace(/\s+/g, '').toLowerCase().replace(/^0x/, '');
  if (/^[0-9a-f]{64}$/.test(hex)) return { kind: 'private-key', wallet: walletFromPrivateKeyHex(hex), ambiguous: true };
  throw new Error('Could not recognise this. Use a BrowserCoin wallet file, a BRC Vault backup, or a private key.');
}

// ---------------------------------------------------------------------------
// Files that another app has changed
// ---------------------------------------------------------------------------

/**
 * Parse JSON, tolerating harmless changes other apps commonly make: a
 * byte-order mark at the start, straight quotes turned into curly ones, and the
 * same file pasted twice. Returns null if it still isn't JSON.
 */
function parseJsonLoose(text) {
  const t = String(text).replace(/^﻿/, '');
  for (const candidate of [t, t.replace(/[“”„‟″‶«»]/g, '"')]) {
    try { return JSON.parse(candidate); } catch { /* try the next repair */ }
    const single = singleObject(candidate);
    if (single) return single;
  }
  return null;
}

/**
 * The same file pasted twice (or pasted after leftover text) gives several JSON
 * objects in a row. If they are all the same wallet or backup, use it once.
 */
function singleObject(text) {
  const objects = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
    } else if (ch === '"') {
      inString = true;
    } else if (ch === '{') {
      if (depth++ === 0) start = i;
    } else if (ch === '}' && depth > 0 && --depth === 0) {
      objects.push(text.slice(start, i + 1));
    }
  }
  if (objects.length < 2) return null;
  let leftover = text;
  for (const o of objects) leftover = leftover.replace(o, '');
  if (leftover.trim()) return null;
  let parsed;
  try { parsed = objects.map((o) => JSON.parse(o)); } catch { return null; }
  const canon = (o) => (o && o.type === BROWSERCOIN_WALLET_TYPE
    ? `wallet:${String(o.privateKeyHex).toLowerCase()}`
    : JSON.stringify(o));
  if (!parsed.every((o) => canon(o) === canon(parsed[0]))) {
    throw new Error('This contains more than one different wallet or backup. Use just one.');
  }
  return parsed[0];
}

// A field name in quotes (straight, curly, or as an RTF escape such as \'93),
// then a short gap of punctuation or RTF escapes, then its value.
const Q_OPEN = String.raw`(?:"|“|\\'93|\\u8220 ?)`;
const Q_CLOSE = String.raw`(?:"|”|\\'94|\\u8221 ?)`;
const GAP = String.raw`(?:\\'[0-9a-fA-F]{2}|\\u-?\d+ ?|\\[a-zA-Z]+\d* ?|[^0-9a-fA-F\\]){1,40}?`;
const field = (text, name, pattern) => {
  const m = new RegExp(`${Q_OPEN}${name}${Q_CLOSE}${GAP}(${pattern})(?![0-9a-fA-F])`).exec(text);
  return m ? m[1] : null;
};

/**
 * Last resort for a wallet or backup file that a word processor has re-saved:
 * pick the values out by name. Every value is then checked exactly as usual,
 * and a wallet is only accepted if its key still produces its own address.
 */
function rescueFromDamagedText(text) {
  if (/browsercoin-wallet/.test(text)) {
    const key = field(text, 'privateKeyHex', '[0-9a-fA-F]{64}');
    const address = field(text, 'address', '[0-9a-fA-F]{64}');
    if (!key || !address) return null;
    const wallet = walletFromPrivateKeyHex(key);
    if (wallet.address !== address.toLowerCase()) { wipeWallet(wallet); return null; }
    return { kind: 'browsercoin-wallet', wallet, rescued: true };
  }
  if (/brc-vault-backup/.test(text)) {
    try {
      const backup = validateBackup({
        type: BACKUP_TYPE,
        version: BACKUP_VERSION,
        address: field(text, 'address', '[0-9a-fA-F]{64}'),
        kdf: {
          name: 'scrypt',
          logN: Number(field(text, 'logN', '[0-9]{1,3}')),
          r: Number(field(text, 'r', '[0-9]{1,3}')),
          p: Number(field(text, 'p', '[0-9]{1,3}')),
          dkLen: 32,
          salt: field(text, 'salt', '[0-9a-fA-F]{32}'),
        },
        cipher: { name: 'aes-256-gcm', iv: field(text, 'iv', '[0-9a-fA-F]{24}') },
        ciphertext: field(text, 'ciphertext', '[0-9a-fA-F]{96}'),
      });
      return { kind: 'vault-backup', backup, rescued: true };
    } catch { return null; }
  }
  return null;
}

/** Overwrite key bytes in memory once they are no longer needed. */
export function wipeWallet(wallet) {
  if (wallet && wallet.privateKey instanceof Uint8Array) wallet.privateKey.fill(0);
}
