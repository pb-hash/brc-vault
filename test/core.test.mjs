// Tests for the BRC Vault core, cross-checked against BrowserCoin's wallet behaviour
// and the official Ed25519 test vectors (RFC 8032).
// Usage: node test/core.test.mjs
import assert from 'node:assert/strict';
import * as core from '../build/core.mjs';
import * as bc from './browsercoin-reference.mjs';

const FAST = { name: 'scrypt', logN: 14, r: 8, p: 1, dkLen: 32 }; // cheap settings for repeated tests only
let passed = 0;
const test = async (name, fn) => { await fn(); passed++; console.log('ok -', name); };

await test('Ed25519 key → address matches the RFC 8032 official test vectors', async () => {
  const vectors = [
    ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'],
    ['4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c'],
    ['c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7', 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025'],
  ];
  for (const [sk, pk] of vectors) assert.equal(core.walletFromPrivateKeyHex(sk).address, pk);
});

await test('address derivation matches BrowserCoin for 200 random keys', async () => {
  for (let i = 0; i < 200; i++) {
    const kp = bc.generateKeyPair();
    assert.equal(core.addressFromPrivateKey(kp.privateKey), kp.address);
  }
});

await test('wallet file we write is identical to BrowserCoin Export, and BrowserCoin imports it', async () => {
  const kp = bc.generateKeyPair();
  const theirs = bc.exportWalletJson(kp);
  const mine = core.browserCoinWalletJson({ privateKey: kp.privateKey, address: kp.address });
  assert.equal(mine, theirs);
  const back = bc.importWalletJson(mine);
  assert.equal(back.address, kp.address);
});

await test('reads a real BrowserCoin export and catches an edited address', async () => {
  const kp = bc.generateKeyPair();
  const w = core.parseBrowserCoinWallet(bc.exportWalletJson(kp));
  assert.equal(w.address, kp.address);
  const tampered = JSON.parse(bc.exportWalletJson(kp));
  tampered.address = bc.generateKeyPair().address;
  assert.throws(() => core.parseBrowserCoinWallet(JSON.stringify(tampered)), /does not match/);
});

await test('encrypt → decrypt round trip at the real default settings (128 MiB scrypt)', async () => {
  const kp = bc.generateKeyPair();
  const t0 = Date.now();
  const b = await core.encryptWallet({ privateKey: kp.privateKey, address: kp.address }, 'correct horse battery staple');
  const tEnc = Date.now() - t0;
  assert.equal(b.kdf.logN, 17);
  const w = await core.decryptBackup(JSON.parse(JSON.stringify(b)), 'correct horse battery staple');
  assert.equal(w.address, kp.address);
  assert.deepEqual([...w.privateKey], [...kp.privateKey]);
  console.log(`   (default-strength encryption took ${tEnc} ms in Node)`);
});

await test('wrong password is rejected', async () => {
  const kp = bc.generateKeyPair();
  const b = await core.encryptWallet({ privateKey: kp.privateKey, address: kp.address }, 'a very good password', { kdf: FAST });
  await assert.rejects(core.decryptBackup(b, 'a very good passworD'), /Wrong password/);
});

await test('tampering with any field is caught', async () => {
  const kp = bc.generateKeyPair();
  const b = await core.encryptWallet({ privateKey: kp.privateKey, address: kp.address }, 'a very good password', { kdf: FAST });
  const flip = (hex) => (hex[0] === '0' ? '1' : '0') + hex.slice(1);
  const variants = [
    { ...b, ciphertext: flip(b.ciphertext) },
    { ...b, address: bc.generateKeyPair().address },
    { ...b, cipher: { ...b.cipher, iv: flip(b.cipher.iv) } },
    { ...b, kdf: { ...b.kdf, salt: flip(b.kdf.salt) } },
    { ...b, kdf: { ...b.kdf, r: 9 } },
  ];
  for (const v of variants) await assert.rejects(core.decryptBackup(v, 'a very good password'));
  await assert.rejects(core.decryptBackup({ ...b, kdf: { ...b.kdf, logN: 30 } }, 'a very good password'), /unsafe/);
});

await test('compact paper code round-trips and still decrypts', async () => {
  const kp = bc.generateKeyPair();
  const b = await core.encryptWallet({ privateKey: kp.privateKey, address: kp.address }, 'paper backup password', { kdf: FAST });
  const code = core.backupToCompact(b);
  assert.match(code, /^BRCVAULT1:[0-9A-F]{64}:14:8:1:[0-9A-F]{32}:[0-9A-F]{24}:[0-9A-F]{96}$/);
  const lines = core.paperCodeLines(code);
  assert.equal(lines.length, 9);
  const id = core.identifyInput(core.paperCodeText(code).toLowerCase());
  assert.equal(id.kind, 'vault-backup');
  const w = await core.decryptBackup(id.backup, 'paper backup password');
  assert.equal(w.address, kp.address);
});

await test('identifyInput recognises each kind and rejects junk', async () => {
  const kp = bc.generateKeyPair();
  assert.equal(core.identifyInput(bc.exportWalletJson(kp)).kind, 'browsercoin-wallet');
  const keyHex = core.bytesToHex(kp.privateKey);
  const k = core.identifyInput('  0x' + keyHex.toUpperCase() + '\n');
  assert.equal(k.kind, 'private-key');
  assert.equal(k.wallet.address, kp.address);
  const b = await core.encryptWallet({ privateKey: kp.privateKey, address: kp.address }, 'a very good password', { kdf: FAST });
  assert.equal(core.identifyInput(JSON.stringify(b)).kind, 'vault-backup');
  assert.throws(() => core.identifyInput('hello'), /Could not recognise/);
  assert.throws(() => core.identifyInput(kp.address.slice(0, 60)), /Could not recognise/);
});

await test('short passwords and mismatches are refused', async () => {
  assert.ok(core.passwordProblems('short').length > 0);
  assert.deepEqual(core.passwordProblems('long enough password', 'long enough password'), []);
  assert.ok(core.passwordProblems('long enough password', 'long enough passw0rd').length > 0);
  const kp = bc.generateKeyPair();
  await assert.rejects(core.encryptWallet({ privateKey: kp.privateKey, address: kp.address }, 'short'), /at least 12/);
});

await test('a typo in a typed paper code names the line before any slow work', async () => {
  const kp = bc.generateKeyPair();
  const b = await core.encryptWallet({ privateKey: kp.privateKey, address: kp.address }, 'paper backup password', { kdf: FAST });
  const lines = core.paperCodeText(core.backupToCompact(b)).split('\n');
  const bad = [...lines];
  bad[4] = bad[4].replace(/[0-9A-F](?=[^[]*\[)/, (c) => (c === '0' ? 'D' : '0'));
  assert.throws(() => core.identifyInput(bad.join('\n')), /Line 5 of the backup code has a typo/);
  assert.throws(() => core.identifyInput(lines.slice(0, 8).join('\n') + '\nABCD'), /missing its check/);
  // All on one line with checks still works.
  assert.equal(core.identifyInput(lines.join(' ')).kind, 'vault-backup');
  // The compact form, and the QR form with a space after the prefix, both work.
  assert.equal(core.identifyInput(core.backupToCompact(b)).kind, 'vault-backup');
  // QR codes hold the colon form, so phone cameras never offer a web search for them.
  const qr = core.qrPayload(core.backupToCompact(b));
  assert.match(qr, /^BRCVAULT1:[0-9A-F]{64}:/);
  assert.equal(core.identifyInput(qr).backup.address, kp.address);
  // Copies printed briefly with a space after the prefix still restore.
  assert.equal(core.identifyInput(qr.replace('BRCVAULT1:', 'BRCVAULT1 ').toLowerCase()).backup.address, kp.address);
});

await test('backups are fully checked when loaded, before showing anything', async () => {
  const kp = bc.generateKeyPair();
  const b = await core.encryptWallet({ privateKey: kp.privateKey, address: kp.address }, 'a very good password', { kdf: FAST });
  const scam = { ...b, address: 'Send 500 BRC to support to unlock: 0123abcd' };
  assert.throws(() => core.identifyInput(JSON.stringify(scam)), /address in this backup is damaged/);
  assert.throws(() => core.identifyInput(JSON.stringify({ ...b, kdf: { ...b.kdf, logN: 20, r: 7, p: 16 } })), /unsafe/);
  assert.throws(() => core.identifyInput(JSON.stringify({ ...b, ciphertext: b.ciphertext.slice(2) })), /locked key/);
  const code = core.backupToCompact(b);
  for (const weird of ['014', '14.0', '0xE', '1e1', '+14']) {
    assert.throws(() => core.identifyInput(code.replace(':14:8:1:', `:${weird}:8:1:`)));
  }
  assert.equal(core.identifyInput(JSON.stringify(b)).backup.address, kp.address);
});

await test('a bare 64-character string is flagged as possibly an address; BRCKEY1 keys are not', async () => {
  const kp = bc.generateKeyPair();
  const asAddress = core.identifyInput(kp.address);
  assert.equal(asAddress.kind, 'private-key');
  assert.equal(asAddress.ambiguous, true);
  assert.notEqual(asAddress.wallet.address, kp.address); // pasting an address gives an unrelated wallet
  const keyQr = core.qrPayload(`${core.KEY_PREFIX}:${core.bytesToHex(kp.privateKey).toUpperCase()}`);
  assert.ok(keyQr.startsWith('BRCKEY1:'), 'a key QR must never be plain, searchable text');
  const viaQr = core.identifyInput(keyQr.replace('BRCKEY1:', 'BRCKEY1 '));
  assert.equal(viaQr.ambiguous, false);
  assert.equal(viaQr.wallet.address, kp.address);
  const prefixed = core.identifyInput(`${core.KEY_PREFIX}:${core.bytesToHex(kp.privateKey).toUpperCase()}`);
  assert.equal(prefixed.ambiguous, false);
  assert.equal(prefixed.wallet.address, kp.address);
});

await test('repetitive passwords are refused and key bytes can be wiped', async () => {
  assert.match(core.passwordProblems('aaaaaaaaaaaaaaaa').join(' '), /repetitive/);
  const kp = bc.generateKeyPair();
  const w = { privateKey: Uint8Array.from(kp.privateKey), address: kp.address };
  core.wipeWallet(w);
  assert.ok(w.privateKey.every((x) => x === 0));
});

// TextEdit-style rich text: escaped braces, curly quotes written as \'93 and \'94.
const toRtf = (json) => '{\\rtf1\\ansi\\ansicpg1252\\cocoartf2761\n{\\fonttbl\\f0\\fswiss\\fcharset0 Helvetica;}\n\\f0\\fs24 \\cf0 '
  + json.replace(/"([^"]*)"/g, "\\'93$1\\'94").replace(/\{/g, '\\{').replace(/\}/g, '\\}').replace(/\n/g, '\\\n') + '}';

await test('files changed by other apps still load: byte-order mark, curly quotes, TextEdit rich text', async () => {
  const kp = bc.generateKeyPair();
  const json = bc.exportWalletJson(kp);
  for (const t of ['﻿' + json, json.replace(/"([^"]*)"/g, '“$1”'), toRtf(json)]) {
    const id = core.identifyInput(t);
    assert.equal(id.kind, 'browsercoin-wallet');
    assert.equal(id.wallet.address, kp.address);
    assert.deepEqual([...id.wallet.privateKey], [...kp.privateKey]);
  }
  const b = await core.encryptWallet({ privateKey: kp.privateKey, address: kp.address }, 'a very good password', { kdf: FAST });
  const id = core.identifyInput(toRtf(JSON.stringify(b, null, 2)));
  assert.equal(id.kind, 'vault-backup');
  assert.equal((await core.decryptBackup(id.backup, 'a very good password')).address, kp.address);
});

await test('a damaged file is never accepted with a key that does not match its address', async () => {
  const kp = bc.generateKeyPair();
  const other = bc.generateKeyPair();
  const json = bc.exportWalletJson(kp).replace(kp.address, other.address);
  assert.throws(() => core.identifyInput(toRtf(json)), /re-saved by a word processor/);
  assert.throws(() => core.identifyInput(bc.exportWalletJson(kp).slice(0, 80)), /incomplete or was changed/);
  const flipped = bc.exportWalletJson(kp).replace(/"privateKeyHex": "(.)/, (m, c) => m.slice(0, -1) + (c === '0' ? '1' : '0'));
  assert.throws(() => core.identifyInput(toRtf(flipped)), /re-saved by a word processor/);
});

console.log(`\n${passed} tests passed`);
