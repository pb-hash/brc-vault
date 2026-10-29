// Tests for the BRC Vault core, cross-checked against BrowserCoin's wallet behaviour
// and the official Ed25519 test vectors (RFC 8032).
// Usage: node test/core.test.mjs
import assert from 'node:assert/strict';
import * as core from '../build/core.mjs';
import * as bc from './browsercoin-reference.mjs';
import { desktopEncryptedWalletJson } from './desktop-wallet-reference.mjs';

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
  assert.throws(() => core.identifyInput(bad.join('\n')), /Line 5 of the code has a typo/);
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
  assert.equal(prefixed.checked, false); // an old-style code with no address check gets the address warning
});

await test('the unprotected key code carries an address check, so a typo is caught instead of opening another wallet', async () => {
  const kp = bc.generateKeyPair();
  const w = { privateKey: Uint8Array.from(kp.privateKey), address: kp.address };
  const code = core.keyToCode(w);
  assert.equal(code, `BRCKEY1:${core.bytesToHex(kp.privateKey)}:${kp.address.slice(0, 8)}`.toUpperCase());
  const ok = core.identifyInput(core.qrPayload(code));
  assert.equal(ok.checked, true);
  assert.equal(ok.wallet.address, kp.address);
  // Typed from paper, with the checks in brackets, in lower case.
  const typed = core.keyCodeLines(code).map((l) => `${l.text} [${l.check}]`).join('\n');
  assert.equal(core.identifyInput(typed.toLowerCase()).wallet.address, kp.address);
  // One wrong character in the key: caught by the address check even without the bracket checks.
  const i = 20;
  const typo = code.slice(0, i) + (code[i] === '0' ? '1' : '0') + code.slice(i + 1);
  assert.throws(() => core.identifyInput(typo), /has a typo/);
  // With the bracket checks, the exact line is named.
  const lines = typed.split('\n');
  lines[1] = lines[1].replace(/^./, (c) => (c === '0' ? '1' : '0'));
  assert.throws(() => core.identifyInput(lines.join('\n')), /Line 2 of the code has a typo/);
  // The last line left off.
  assert.throws(() => core.identifyInput(typed.split('\n').slice(0, 3).join('\n')), /address check after the final colon, is missing/);
});

await test('typed codes and very long pastes are read quickly', async () => {
  for (const t of [
    'BRCVAULT1:' + 'A'.repeat(64000) + '[zz',
    'BRCVAULT1:' + '[ '.repeat(30000),
    'BRCVAULT1:' + 'AB]'.repeat(20000) + '[ABCD]',
    'BRCKEY1:' + 'A '.repeat(30000) + '[1234]',
  ]) {
    const start = Date.now();
    assert.throws(() => core.identifyInput(t));
    assert.ok(Date.now() - start < 500, `took ${Date.now() - start} ms`);
  }
  assert.throws(() => core.identifyInput('x'.repeat(core.MAX_INPUT_LENGTH + 1)), /far too long/);
  // A stray "]" can't hide text from the line checks.
  const kp = bc.generateKeyPair();
  const b = await core.encryptWallet({ privateKey: kp.privateKey, address: kp.address }, 'paper backup password', { kdf: FAST });
  const lines = core.paperCodeText(core.backupToCompact(b)).split('\n');
  lines[3] = 'junk] ' + lines[3];
  assert.throws(() => core.identifyInput(lines.join('\n')), /missing its check/);
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

await test('damaged text holding two different wallets or backups is refused, not guessed', async () => {
  const a = bc.exportWalletJson(bc.generateKeyPair());
  const b = bc.exportWalletJson(bc.generateKeyPair());
  assert.throws(() => core.identifyInput(toRtf(a + '\n' + b)), /more than one different wallet/);
  // The same wallet twice is fine.
  assert.equal(core.identifyInput(toRtf(a + '\n' + a)).kind, 'browsercoin-wallet');
  // A second key hidden inside another field is refused too.
  const kp = bc.generateKeyPair(), decoy = bc.generateKeyPair();
  const hex = (u) => Buffer.from(u).toString('hex');
  const evil = `{"type":"browsercoin-wallet","note":"“privateKeyHex”: “${hex(decoy.privateKey)}”", "privateKeyHex":"${hex(kp.privateKey)}","address":"${kp.address}" junk`;
  assert.throws(() => core.identifyInput(evil), /more than one different wallet/);
  const k1 = bc.generateKeyPair(), k2 = bc.generateKeyPair();
  const b1 = JSON.stringify(await core.encryptWallet({ privateKey: k1.privateKey, address: k1.address }, 'a very good password', { kdf: FAST }));
  const b2 = JSON.stringify(await core.encryptWallet({ privateKey: k2.privateKey, address: k2.address }, 'a very good password', { kdf: FAST }));
  assert.throws(() => core.identifyInput(toRtf(b1 + b2)), /more than one different wallet/);
});

await test('crafted damaged text cannot freeze the page (64 KB inputs finish fast)', async () => {
  const hex63 = 'a'.repeat(63);
  const inputs = [
    '{\\rtf browsercoin-wallet "privateKeyHex"' + '\\u1 '.repeat(16000) + hex63 + 'z',
    '{\\rtf browsercoin-wallet "privateKeyHex"' + '\\zz'.repeat(21000) + hex63 + 'z',
    '{\\rtf browsercoin-wallet ' + '"privateKeyHex"\\u1 '.repeat(3000),
    '{\\rtf brc-vault-backup ' + '"r" '.repeat(16000),
  ];
  for (const t of inputs) {
    const start = Date.now();
    try { core.identifyInput(t); } catch { /* an error message is fine */ }
    assert.ok(Date.now() - start < 500, `took ${Date.now() - start} ms on a ${t.length}-character input`);
  }
});

const hexOf = (u) => Buffer.from(u).toString('hex');

await test('24 recovery words match the official BIP39 test vectors for 32-byte keys', async () => {
  // From the reference BIP39 vectors (trezor/python-mnemonic vectors.json), which bitcoinj's MnemonicCode also passes.
  const vectors = [
    ['00'.repeat(32), 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'],
    ['7f'.repeat(32), 'legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title'],
    ['80'.repeat(32), 'letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless'],
    ['ff'.repeat(32), 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote'],
    ['68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c', 'hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length'],
  ];
  for (const [hex, words] of vectors) {
    const w = core.walletFromPrivateKeyHex(hex);
    assert.equal(core.walletToWords(w).join(' '), words);
    assert.equal(hexOf(core.walletFromWords(words).privateKey), hex);
    // These keys are published, so the page refuses them as wallets.
    assert.throws(() => core.identifyInput(words), /well-known example key/);
    assert.throws(() => core.identifyInput(hex), /well-known example key/);
  }
  for (const k of ['9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', '11'.repeat(32)]) {
    assert.throws(() => core.identifyInput(`BRCKEY1:${k}`), /well-known example key/);
  }
});

await test('recovery words: forgiving about layout, strict about mistakes', async () => {
  const kp = bc.generateKeyPair();
  const w = { privateKey: Uint8Array.from(kp.privateKey), address: kp.address };
  const words = core.walletToWords(w);
  // Numbered, upper case, one per line, or just the first four letters of each word.
  for (const t of [
    words.map((x, i) => `${i + 1}. ${x.toUpperCase()}`).join('\n'),
    words.map((x, i) => `${i + 1}) ${x}`).join('  '),
    words.map((x, i) => `(${i + 1}) ${x}`).join(' '),
    words.map((x, i) => `${i + 1}.${x}`).join(' '),
    words.join(', '),
    words.map((x) => x.slice(0, 4)).join(' '),
  ]) {
    const id = core.identifyInput(t);
    assert.equal(id.wallet.address, kp.address);
    assert.equal(id.checked, false); // words still get the "is this your address?" check
  }
  // A numbered grid copied across the rows instead of down the columns: the numbers decide the order.
  const grid = [];
  for (let row = 0; row < 6; row++) for (let col = 0; col < 4; col++) { const n = col * 6 + row; grid.push(`${n + 1}. ${words[n]}`); }
  assert.equal(core.identifyInput(grid.join(' ')).wallet.address, kp.address);
  // Numbers that don't run 1 to 24 once each are refused rather than guessed.
  const dup = words.map((x, i) => `${i === 5 ? 1 : i + 1}. ${x}`).join(' ');
  assert.throws(() => core.identifyInput(dup), /Number every word 1 to 24/);
  const someNumbered = words.map((x, i) => (i < 3 ? `${i + 1}. ${x}` : x)).join(' ');
  assert.throws(() => core.identifyInput(someNumbered), /Number every word 1 to 24/);
  // Misspelt word: named by position.
  const bad = [...words]; bad[6] = 'qqqqzz';
  assert.throws(() => core.identifyInput(bad.join(' ')), (e) => /Word 7 isn't on the recovery word list/.test(e.message) && !e.message.includes('qqqq'));
  // Two words swapped: almost always caught by the built-in check.
  let caught = 0;
  for (let i = 0; i < 20; i++) {
    const sw = [...words]; [sw[i], sw[i + 1]] = [sw[i + 1], sw[i]];
    if (sw[i] === sw[i + 1]) { caught++; continue; }
    try { core.identifyInput(sw.join(' ')); } catch (e) { if (/built-in check/.test(e.message)) caught++; }
  }
  assert.ok(caught >= 18, `only ${caught} of 20 swaps caught`);
  assert.throws(() => core.identifyInput(words.slice(0, 12).join(' ')), /12 words/);
  assert.throws(() => core.identifyInput(words.slice(0, 23).join(' ')), /23 words/);
});

await test('opens password-protected files from the BRC Wallet desktop app', async () => {
  const kp = bc.generateKeyPair();
  const wallet = { privateKeyHex: hexOf(kp.privateKey), address: kp.address };
  const file = desktopEncryptedWalletJson(wallet, 'desktop pass 1', { N: 16384 }); // fast; older files used this
  const id = core.identifyInput(file);
  assert.equal(id.kind, 'desktop-backup');
  assert.equal(id.backup.address, kp.address);
  const opened = await core.unlockAny(id.backup, 'desktop pass 1');
  assert.equal(opened.address, kp.address);
  assert.equal(hexOf(opened.privateKey), wallet.privateKeyHex);
  await assert.rejects(core.unlockAny(id.backup, 'desktop pass 2'), /Wrong password/);
  // The app uses the password exactly as typed: no Unicode normalisation.
  const nfd = 'café password';
  const id2 = core.identifyInput(desktopEncryptedWalletJson(wallet, nfd, { N: 16384 }));
  assert.equal((await core.unlockAny(id2.backup, nfd)).address, kp.address);
  await assert.rejects(core.unlockAny(id2.backup, nfd.normalize('NFKC')), /Wrong password/);
  // A file whose address was swapped for another one is refused after unlocking.
  const other = bc.generateKeyPair();
  const swapped = JSON.parse(file); swapped.address = other.address;
  await assert.rejects(core.unlockAny(core.identifyInput(JSON.stringify(swapped)).backup, 'desktop pass 1'), /does not match/);
  // Unsafe or odd settings are refused before any slow work.
  for (const kdfParams of [{ N: 2 ** 20, r: 8, p: 1 }, { N: 16384, r: 16, p: 1 }, { N: 10000, r: 8, p: 1 }, { N: '16384', r: 8, p: 1 }]) {
    const f = JSON.parse(file); f.kdfParams = { ...f.kdfParams, ...kdfParams };
    assert.throws(() => core.identifyInput(JSON.stringify(f)), /unsafe|invalid/);
  }
  const short = JSON.parse(file); short.authTag = short.authTag.slice(2);
  assert.throws(() => core.identifyInput(JSON.stringify(short)), /damaged/);
  // Two different desktop files pasted together are refused, not merged.
  const file2 = desktopEncryptedWalletJson(wallet, 'desktop pass 1', { N: 16384 });
  assert.throws(() => core.identifyInput(file + file2), /more than one different wallet/);
  // The old, misleading message is gone.
  assert.throws(() => core.parseBrowserCoinWallet(file), /BRC Wallet desktop app/);
});

await test('desktop files at the app\'s current setting (N = 2^17) open too', async () => {
  const kp = bc.generateKeyPair();
  const file = desktopEncryptedWalletJson({ privateKeyHex: hexOf(kp.privateKey), address: kp.address }, 'current settings');
  const id = core.identifyInput(file);
  assert.equal(id.backup.kdf.logN, 17);
  assert.equal((await core.unlockAny(id.backup, 'current settings')).address, kp.address);
});

console.log(`\n${passed} tests passed`);
