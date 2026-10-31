// BRC Vault core: key checks, password encryption, and BrowserCoin wallet-file conversion.
// Runs entirely locally. No network access is needed or used.

import * as ed from '@noble/ed25519';
import { sha512, sha256 } from '@noble/hashes/sha2';
import { scryptAsync } from '@noble/hashes/scrypt';
import { entropyToMnemonic, mnemonicToEntropy } from '@scure/bip39';
import { wordlist as BIP39_ENGLISH } from '@scure/bip39/wordlists/english';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const BACKUP_TYPE = 'brc-vault-backup';
export const BACKUP_VERSION = 1;
export const COMPACT_PREFIX = 'BRCVAULT1';
/**
 * A mailbox key: a key used only to open sealed letters and sign in BRC Seal,
 * never to hold coins. Its backup is the same format with its own type, which
 * is bound into the encryption, so a coin backup can't be relabelled as one.
 */
export const MAILBOX_TYPE = 'brc-vault-mailbox-key';
export const MAILBOX_COMPACT_PREFIX = 'BRCMBOX1';
const isBackupType = (t) => t === BACKUP_TYPE || t === MAILBOX_TYPE;
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

/**
 * A brand-new wallet: 32 fresh bytes from the browser's secure random
 * generator (crypto.getRandomValues), made entirely on this page.
 */
export function newWallet() {
  const privateKey = randomBytes(32);
  return { privateKey, address: addressFromPrivateKey(privateKey) };
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
  if (parsed.encrypted === true) throw new Error('This wallet file is password-protected by the BRC Wallet desktop app. Open it in Restore.');
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

async function deriveKey(password, salt, kdf, onProgress, { normalize = true } = {}) {
  checkKdf(kdf);
  // BRC Vault normalizes the password (so the same characters typed on any
  // keyboard give the same key). The desktop wallet uses it exactly as typed.
  const pw = new TextEncoder().encode(normalize ? password.normalize('NFKC') : password);
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
function associatedData(type, address, kdf, saltHex, ivHex) {
  return new TextEncoder().encode(
    [type, BACKUP_VERSION, address, kdf.name, kdf.logN, kdf.r, kdf.p, kdf.dkLen, saltHex, ivHex].join('|'),
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
  if (!b || typeof b !== 'object' || !isBackupType(b.type)) throw new Error('This is not a BRC Vault backup.');
  if (b.version !== BACKUP_VERSION) throw new Error(`This backup is version ${String(b.version).slice(0, 8)}; this copy of BRC Vault reads version ${BACKUP_VERSION}.`);
  const k = b.kdf || {};
  const kdf = { name: k.name, logN: k.logN, r: k.r, p: k.p, dkLen: k.dkLen };
  checkKdf(kdf);
  if (!b.cipher || b.cipher.name !== 'aes-256-gcm') throw new Error('Unsupported encryption method in this backup.');
  return {
    type: b.type,
    version: BACKUP_VERSION,
    address: checkAddress(b.address),
    kdf: { ...kdf, salt: checkSalt(k.salt) },
    cipher: { name: 'aes-256-gcm', iv: checkIv(b.cipher.iv) },
    ciphertext: checkCiphertext(b.ciphertext),
  };
}

/** Encrypt a wallet with a password. Returns the backup object (format described on the page). */
export async function encryptWallet(wallet, password, { kdf = DEFAULT_KDF, onProgress, purpose = 'coins' } = {}) {
  const type = purpose === 'mailbox' ? MAILBOX_TYPE : BACKUP_TYPE;
  const problems = passwordProblems(password);
  if (problems.length) throw new Error(problems.join(' '));
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const saltHex = bytesToHex(salt);
  const ivHex = bytesToHex(iv);
  const key = await deriveKey(password, salt, kdf, onProgress);
  const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: associatedData(type, wallet.address, kdf, saltHex, ivHex), tagLength: 128 },
    key,
    wallet.privateKey,
  ));
  return {
    type,
    version: BACKUP_VERSION,
    address: wallet.address,
    kdf: { ...kdf, salt: saltHex },
    cipher: { name: 'aes-256-gcm', iv: ivHex },
    ciphertext: bytesToHex(ct),
    created: new Date().toISOString().slice(0, 10),
    note: type === MAILBOX_TYPE
      ? 'Locked BRC mailbox key. It opens sealed letters and signs in BRC Seal; it is not for holding coins. The key is encrypted inside "ciphertext" and only your password unlocks it, in BRC Seal or BRC Vault. The address is public and safe to share.'
      : 'Locked BRC Vault backup. The private key is encrypted inside "ciphertext" and can only be unlocked with your password in BRC Vault. The address is public and safe to share.',
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
      { name: 'AES-GCM', iv, additionalData: associatedData(b.type, b.address, kdf, saltHex, b.cipher.iv), tagLength: 128 },
      key,
      ct,
    ));
  } catch {
    throw new Error('Wrong password, or the backup has been changed or damaged.');
  }
  const wallet = { privateKey: pt, address: addressFromPrivateKey(pt), purpose: b.type === MAILBOX_TYPE ? 'mailbox' : 'coins' };
  if (wallet.address !== b.address) { wipeWallet(wallet); throw new Error('The decrypted key does not match the address in the backup.'); }
  return wallet;
}

// ---------------------------------------------------------------------------
// Password-protected files from the BRC Wallet desktop app (Windows), so they
// can be opened here too. Their layout, from that app's src/wallet.js:
//   { type: "browsercoin-wallet", version: 2, address, encrypted: true,
//     kdf: "scrypt", kdfParams: { N, r, p, salt }, cipher: "aes-256-gcm",
//     iv, authTag, ciphertext, warning }
// The password is used exactly as typed, and there is no associated data.
// ---------------------------------------------------------------------------

export const DESKTOP_FORMAT = 'brc-wallet-desktop';
const checkTag = HEX_FIELD('check code', 16);
const checkDesktopCiphertext = HEX_FIELD('locked key', 32);

/** Check a desktop-app encrypted wallet file and return a clean copy. */
export function validateDesktopBackup(d) {
  if (!d || typeof d !== 'object' || d.type !== BROWSERCOIN_WALLET_TYPE || d.encrypted !== true) {
    throw new Error('This is not a password-protected BRC Wallet file.');
  }
  if (d.version !== 2) throw new Error(`This BRC Wallet file has a version (${JSON.stringify(d.version ?? null).slice(0, 12)}) BRC Vault doesn't know; it reads version 2.`);
  if (d.kdf !== 'scrypt' || d.cipher !== 'aes-256-gcm') throw new Error('This wallet file uses an encryption method BRC Vault does not know.');
  const kp = d.kdfParams || {};
  const N = kp.N;
  const logN = Number.isInteger(N) && N > 1 && (N & (N - 1)) === 0 ? Math.log2(N) : NaN;
  const kdf = { name: 'scrypt', logN, r: kp.r, p: kp.p, dkLen: 32 };
  checkKdf(kdf);
  return {
    format: DESKTOP_FORMAT,
    address: checkAddress(d.address),
    kdf: { ...kdf, salt: checkSalt(kp.salt) },
    iv: checkIv(d.iv),
    authTag: checkTag(d.authTag),
    ciphertext: checkDesktopCiphertext(d.ciphertext),
  };
}

/** Unlock a desktop-app wallet file with its password. */
export async function decryptDesktopBackup(backup, password, { onProgress } = {}) {
  const b = validateDesktopBackup({
    type: BROWSERCOIN_WALLET_TYPE, version: 2, encrypted: true, kdf: 'scrypt', cipher: 'aes-256-gcm',
    address: backup.address, kdfParams: { N: 2 ** backup.kdf.logN, r: backup.kdf.r, p: backup.kdf.p, salt: backup.kdf.salt },
    iv: backup.iv, authTag: backup.authTag, ciphertext: backup.ciphertext,
  });
  const { salt: saltHex, ...kdf } = b.kdf;
  const key = await deriveKey(password, hexToBytes(saltHex, 16), kdf, onProgress, { normalize: false });
  let pt;
  try {
    pt = new Uint8Array(await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: hexToBytes(b.iv, 12), tagLength: 128 },
      key,
      hexToBytes(b.ciphertext + b.authTag, 48),
    ));
  } catch {
    throw new Error('Wrong password, or the wallet file has been changed or damaged.');
  }
  const wallet = { privateKey: pt, address: addressFromPrivateKey(pt) };
  if (wallet.address !== b.address) {
    wipeWallet(wallet);
    throw new Error('The unlocked key does not match the address in the wallet file.');
  }
  return wallet;
}

/** Unlock whichever kind of password-protected backup was loaded. */
export function unlockAny(backup, password, opts) {
  return backup && backup.format === DESKTOP_FORMAT
    ? decryptDesktopBackup(backup, password, opts)
    : decryptBackup(backup, password, opts);
}

// ---------------------------------------------------------------------------
// 24 recovery words: standard BIP39 English, with the 32-byte private key used
// directly as the entropy. This is exactly what the BRC Wallet Android app
// shows and accepts (its Bip39Helper uses bitcoinj's MnemonicCode the same
// way), so the same words restore in that app, here, and, through the file
// this page saves, in the browser.
// ---------------------------------------------------------------------------

export function walletToWords(wallet) {
  return entropyToMnemonic(wallet.privateKey, BIP39_ENGLISH).split(' ');
}

const WORD_SET = new Set(BIP39_ENGLISH);
const BY_PREFIX = new Map(BIP39_ENGLISH.map((w) => [w.slice(0, 4), w]));

/** True if the text looks like a list of words rather than a key, file or code. */
export function looksLikeWords(text) {
  const t = String(text).trim();
  if (!/^[\sa-z0-9.,():;-]+$/i.test(t)) return false;
  return wordTokens(t).words.filter((w) => /^[a-z]+$/.test(w)).length >= 6;
}

/**
 * Split typed words into a list. Numbers written next to the words ("1." "1)"
 * "(1)") are kept, because people often copy a grid in a different order than
 * it was numbered: when numbers are present they decide the order.
 */
function wordTokens(text) {
  const words = [];
  const numbers = [];
  let pending = null;
  for (const raw of String(text).toLowerCase().split(/[\s,;]+/)) {
    const m = /^\(?(\d{1,3})[.):-]*\)?(.*)$/.exec(raw);
    let rest = raw;
    if (m) { pending = Number(m[1]); rest = m[2]; }
    rest = rest.replace(/[.]$/, '');
    if (!rest) continue;
    words.push(rest);
    numbers.push(pending);
    pending = null;
  }
  return { words, numbers };
}

/**
 * Read 24 recovery words. Commas and capital letters don't matter, and since
 * every word on the list is unique in its first four letters, those four are
 * enough. If the words are numbered, every word needs its number, 1 to 24.
 */
export function walletFromWords(text) {
  const { words: tokens, numbers } = wordTokens(text);
  if (tokens.length !== 24) {
    throw new Error(tokens.length === 12
      ? 'That is 12 words. BrowserCoin wallets use 24 recovery words.'
      : `That is ${tokens.length} words. BrowserCoin recovery words are a list of 24.`);
  }
  let ordered = tokens;
  if (numbers.some((n) => n !== null)) {
    const seen = new Set(numbers);
    const complete = numbers.every((n) => Number.isInteger(n) && n >= 1 && n <= 24) && seen.size === 24;
    if (!complete) {
      throw new Error('Some words are numbered and some aren\'t, or a number is missing or used twice. Number every word 1 to 24, or leave all the numbers out and type the words in order.');
    }
    ordered = [];
    numbers.forEach((n, i) => { ordered[n - 1] = tokens[i]; });
  }
  const words = ordered.map((t, i) => {
    if (WORD_SET.has(t)) return t;
    const full = t.length >= 4 ? BY_PREFIX.get(t.slice(0, 4)) : undefined;
    if (full && full.startsWith(t)) return full;
    throw new Error(`Word ${i + 1} isn't on the recovery word list. Check its spelling against the paper.`);
  });
  let entropy;
  try {
    entropy = mnemonicToEntropy(words.join(' '), BIP39_ENGLISH);
  } catch {
    throw new Error("These words don't pass their built-in check, so one of them is wrong or two are swapped. Compare them with the paper, word by word.");
  }
  const wallet = { privateKey: Uint8Array.from(entropy), address: addressFromPrivateKey(entropy) };
  entropy.fill(0);
  return wallet;
}

// Keys published as test examples (official BIP39 and RFC 8032 test vectors,
// and keys made of one repeated byte). Anyone can take coins sent to them.
const PUBLISHED_TEST_KEYS = new Set([
  '68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c',
  '9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863',
  '066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad',
  'f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f',
  '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
  'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
  'f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5',
  '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
]);

/** Refuse keys that are published online as examples. */
export function refuseWellKnownKey(wallet) {
  const hex = bytesToHex(wallet.privateKey);
  if (/^(..)\1{31}$/.test(hex) || PUBLISHED_TEST_KEYS.has(hex)) {
    wipeWallet(wallet);
    throw new Error('This is a well-known example key that is published online, so anyone can take coins sent to it. Use your own wallet\'s key or words.');
  }
  return wallet;
}

// ---------------------------------------------------------------------------
// Compact one-line form (for paper QR codes and typing back in)
// BRCVAULT1:<address>:<logN>:<r>:<p>:<salt>:<iv>:<ciphertext>
// ---------------------------------------------------------------------------

export function backupToCompact(b) {
  // Upper case keeps it inside the QR "alphanumeric" alphabet, which gives a smaller code.
  return [b.type === MAILBOX_TYPE ? MAILBOX_COMPACT_PREFIX : COMPACT_PREFIX, b.address, b.kdf.logN, b.kdf.r, b.kdf.p, b.kdf.salt, b.cipher.iv, b.ciphertext].join(':').toUpperCase();
}

const SMALL_INT = /^(0|[1-9][0-9]{0,2})$/;

export function compactToBackup(text) {
  const parts = String(text).replace(/\s+/g, '').split(':');
  const prefix = parts[0].toUpperCase();
  if (prefix !== COMPACT_PREFIX && prefix !== MAILBOX_COMPACT_PREFIX) throw new Error('This is not a BRC Vault backup code.');
  if (parts.length !== 8) throw new Error('This backup code has the wrong number of parts. Check that every line, including the colons, was copied.');
  const [, address, logN, r, p, salt, iv, ciphertext] = parts;
  for (const [label, v] of [['strength settings', logN], ['strength settings', r], ['strength settings', p]]) {
    if (!SMALL_INT.test(v)) throw new Error(`The ${label} in this backup code are damaged.`);
  }
  return validateBackup({
    type: prefix === MAILBOX_COMPACT_PREFIX ? MAILBOX_TYPE : BACKUP_TYPE,
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
  return String(compactOrKey).replace(/^(BRCVAULT1|BRCMBOX1|BRCKEY1) /, '$1:');
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
  // Read line by line, front to back, so every part of the text must belong to
  // a checked line and no input can make this slow.
  const CHECK = /\[\s*([0-9a-fA-F]{4})\s*\]/y;
  const missing = () => new Error('Part of the code is missing its check in brackets. Copy every line, including the [XXXX] at the end.');
  let pos = 0;
  let line = 0;
  let joined = '';
  for (let open = t.indexOf('[', pos); open !== -1; open = t.indexOf('[', pos)) {
    const content = t.slice(pos, open);
    CHECK.lastIndex = open;
    const m = CHECK.exec(t);
    if (!m || content.includes(']')) throw missing();
    line++;
    if (lineCheck(content) !== m[1].toUpperCase()) {
      throw new Error(`Line ${line} of the code has a typo: it doesn't match its check [${m[1].toUpperCase()}]. Compare that line with the paper, watching for 0/D and 8/B.`);
    }
    joined += content;
    pos = CHECK.lastIndex;
  }
  if (line === 0 || t.slice(pos).trim() !== '') throw missing();
  return joined;
}

// ---------------------------------------------------------------------------
// Unprotected key code: BRCKEY1:<private key>:<first 8 characters of the address>
// The address part is a typo check: any 64 characters make a valid key, so
// without it a single wrong character would quietly open a different, empty wallet.
// ---------------------------------------------------------------------------

export function keyToCode(wallet) {
  return `${KEY_PREFIX}:${bytesToHex(wallet.privateKey)}:${wallet.address.slice(0, 8)}`.toUpperCase();
}

/** Paper layout for a key code, one checked line at a time, like the backup code. */
export function keyCodeLines(code) {
  const [prefix, key, check] = code.split(':');
  return [
    `${prefix}:`,
    chunkForPaper(key.slice(0, 32)),
    `${chunkForPaper(key.slice(32))}:`,
    chunkForPaper(check),
  ].map((text) => ({ text, check: lineCheck(text) }));
}

/** Longest text identifyInput will look at. Real wallets, backups and codes are far smaller. */
export const MAX_INPUT_LENGTH = 64 * 1024;

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
  if (String(text).length > MAX_INPUT_LENGTH) throw new Error('This is far too long to be a wallet, a backup or a key.');
  // QR codes carry "BRCVAULT1 …" / "BRCKEY1 …" with a space, because phone
  // cameras treat "WORD:" as a link to an unknown app and refuse to show it.
  // Text copied on phones and from chat apps can carry invisible characters
  // (zero-width spaces, non-breaking spaces, special line breaks). Remove them.
  const clean = String(text)
    .replace(/[\u200B-\u200D\u2060\uFEFF\u00AD]/g, '')
    .replace(/[\u00A0\u2007\u202F]/g, ' ')
    .replace(/[\u2028\u2029\r]/g, '\n');
  const t = clean.trim().replace(/^(BRCVAULT1|BRCMBOX1|BRCKEY1)[ \t]+(?=[0-9A-Fa-f])/i, (m, p) => `${p.toUpperCase()}:`);
  if (!t) throw new Error('Nothing to read yet.');
  const squashed = t.toUpperCase().replace(/\s+/g, '');
  if (squashed.startsWith(COMPACT_PREFIX + ':') || squashed.startsWith(MAILBOX_COMPACT_PREFIX + ':')) {
    return { kind: 'vault-backup', backup: compactToBackup(stripPaperChecks(t)) };
  }
  if (squashed.startsWith(KEY_PREFIX + ':')) {
    const parts = stripPaperChecks(t).replace(/\s+/g, '').toLowerCase().split(':');
    if (parts.length > 3 || !/^[0-9a-f]{64}$/.test(parts[1] || '')) {
      throw new Error('This private key code is damaged. It should have 64 characters after BRCKEY1:.');
    }
    const wallet = refuseWellKnownKey(walletFromPrivateKeyHex(parts[1]));
    if (parts.length === 3) {
      if (!parts[2]) {
        wipeWallet(wallet);
        throw new Error('The last line of the code, the address check after the final colon, is missing.');
      }
      if (wallet.address.slice(0, 8) !== parts[2]) {
        wipeWallet(wallet);
        throw new Error("This private key has a typo: it doesn't match the address check at the end of the code. Compare it with the paper, watching for 0/D and 8/B.");
      }
      return { kind: 'private-key', wallet, ambiguous: false, checked: true };
    }
    // An older code with no address check: it may still have a typo, so it
    // gets the same "is this your address?" warning as a bare key.
    return { kind: 'private-key', wallet, ambiguous: false, checked: false };
  }
  // Selecting text on a phone often misses the first "{" or the last "}".
  // When the text is plainly the inside of a wallet file or backup, put them
  // back; every value is still checked exactly as usual afterwards.
  let body = t;
  if (!body.startsWith('{') && /browsercoin-wallet|brc-vault-backup|brc-vault-mailbox-key|privateKeyHex/.test(body)) {
    body = `{${body.replace(/^[\s{]*/, '').replace(/[\s}]*$/, '')}}`;
  } else if (body.startsWith('{') && !body.endsWith('}') && /"(type|privateKeyHex)"\s*:/.test(body)) {
    body = `${body.replace(/[\s,]*$/, '')}}`;
  }
  if (body.startsWith('{')) {
    let parsed = parseJsonLoose(body);
    // The "type" line was cut off: a private key with its own address is
    // still a wallet file, and the two must match below.
    if (parsed && parsed.type === undefined && typeof parsed.privateKeyHex === 'string' && typeof parsed.address === 'string') {
      parsed = { ...parsed, type: BROWSERCOIN_WALLET_TYPE };
    }
    if (parsed) {
      if (isBackupType(parsed.type)) return { kind: 'vault-backup', backup: validateBackup(parsed) };
      if (parsed.type === BROWSERCOIN_WALLET_TYPE && parsed.encrypted === true) return { kind: 'desktop-backup', backup: validateDesktopBackup(parsed) };
      if (parsed.type === BROWSERCOIN_WALLET_TYPE) return { kind: 'browsercoin-wallet', wallet: refuseWellKnownKey(parseBrowserCoinWallet(JSON.stringify(parsed))) };
      throw new Error('This file is neither a BrowserCoin wallet nor a BRC Vault backup.');
    }
    const rescued = rescueFromDamagedText(body);
    if (rescued) return rescued;
    if (/browsercoin-wallet/.test(body) && /encrypted/.test(body)) {
      throw new Error('This password-protected BRC Wallet file was changed by another app, such as a text editor, and can\'t be read. Use the original file the BRC Wallet desktop app saved.');
    }
    if (/^\{\\rtf/.test(body)) {
      throw new Error('This file was re-saved by a word processor such as TextEdit, which changed its format, and the key could not be recovered from it. Use the original file BrowserCoin downloaded.');
    }
    throw new Error("This file is incomplete or was changed by another app, so it can't be read. Use the original file BrowserCoin downloaded (named browsercoin-wallet-…json), not a copy opened and saved in a text editor.");
  }
  const hex = t.replace(/\s+/g, '').toLowerCase().replace(/^0x/, '');
  if (/^[0-9a-f]{64}$/.test(hex)) return { kind: 'private-key', wallet: refuseWellKnownKey(walletFromPrivateKeyHex(hex)), ambiguous: true };
  // Recovery words have only a small built-in check, so the address still
  // needs a look: the page asks, as it does for an unchecked key.
  if (looksLikeWords(t)) return { kind: 'private-key', wallet: refuseWellKnownKey(walletFromWords(t)), ambiguous: false, checked: false, words: true };
  throw new Error('Could not recognise this. Use a BrowserCoin wallet file, a BRC Vault backup, a private key, or 24 recovery words.');
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
  const canon = (o) => (o && o.type === BROWSERCOIN_WALLET_TYPE && typeof o.privateKeyHex === 'string'
    ? `wallet:${o.privateKeyHex.toLowerCase()}`
    : JSON.stringify(o));
  if (!parsed.every((o) => canon(o) === canon(parsed[0]))) {
    throw new Error(MULTIPLE);
  }
  return parsed[0];
}

// A field name in quotes (straight, curly, or as an RTF escape such as \'93),
// then a short gap of punctuation or RTF escapes, then its value.
const Q_OPEN = String.raw`(?:"|“|\\'93|\\u8220 ?)`;
const Q_CLOSE = String.raw`(?:"|”|\\'94|\\u8221 ?)`;
// The gap is read one piece at a time (an RTF escape such as \'7b or 舡,
// or one non-hex character), never by a single backtracking regex: a crafted
// file must not be able to freeze the page.
const GAP_PIECE = /\\'[0-9a-fA-F]{2}|\\[a-zA-Z]+(?:-?\d+)? ?|[^0-9a-fA-F\\]/y;
const MAX_GAP = 40;
const MULTIPLE = 'This contains more than one different wallet or backup. Use just one.';
const field = (text, name, pattern) => {
  const names = new RegExp(`${Q_OPEN}${name}${Q_CLOSE}`, 'g');
  const value = new RegExp(`(?:${pattern})(?![0-9a-fA-F])`, 'y');
  const found = new Set();
  for (let m = names.exec(text); m; m = names.exec(text)) {
    let i = names.lastIndex;
    let pieces = 0;
    while (pieces < MAX_GAP) {
      GAP_PIECE.lastIndex = i;
      if (!GAP_PIECE.test(text)) break;
      i = GAP_PIECE.lastIndex;
      pieces++;
    }
    if (pieces === 0) continue;
    value.lastIndex = i;
    const v = value.exec(text);
    if (v) found.add(v[0].toLowerCase());
  }
  // Two different values for the same field (say, two wallets in one file):
  // refuse rather than guess which one was meant.
  if (found.size > 1) throw new Error(MULTIPLE);
  return found.size ? [...found][0] : null;
};

/**
 * Last resort for a wallet or backup file that a word processor has re-saved:
 * pick the values out by name. Every value is then checked exactly as usual,
 * and a wallet is only accepted if its key still produces its own address.
 */
function rescueFromDamagedText(text) {
  if (/browsercoin-wallet|privateKeyHex/.test(text)) {
    const key = field(text, 'privateKeyHex', '[0-9a-fA-F]{64}');
    const address = field(text, 'address', '[0-9a-fA-F]{64}');
    if (!key || !address) return null;
    const wallet = walletFromPrivateKeyHex(key);
    if (wallet.address !== address.toLowerCase()) { wipeWallet(wallet); return null; }
    return { kind: 'browsercoin-wallet', wallet, rescued: true };
  }
  const rescueType = /brc-vault-mailbox-key/.test(text) ? MAILBOX_TYPE : /brc-vault-backup/.test(text) ? BACKUP_TYPE : null;
  if (rescueType) {
    // Read every field first, so "more than one backup" is reported as such.
    const f = {
      address: field(text, 'address', '[0-9a-fA-F]{64}'),
      logN: field(text, 'logN', '[0-9]{1,3}'),
      r: field(text, 'r', '[0-9]{1,3}'),
      p: field(text, 'p', '[0-9]{1,3}'),
      salt: field(text, 'salt', '[0-9a-fA-F]{32}'),
      iv: field(text, 'iv', '[0-9a-fA-F]{24}'),
      ciphertext: field(text, 'ciphertext', '[0-9a-fA-F]{96}'),
    };
    try {
      const backup = validateBackup({
        type: rescueType,
        version: BACKUP_VERSION,
        address: f.address,
        kdf: { name: 'scrypt', logN: Number(f.logN), r: Number(f.r), p: Number(f.p), dkLen: 32, salt: f.salt },
        cipher: { name: 'aes-256-gcm', iv: f.iv },
        ciphertext: f.ciphertext,
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
