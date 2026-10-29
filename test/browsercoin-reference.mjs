// Reference copy of BrowserCoin's wallet behaviour, written from its source
// (src/crypto/keys.ts and src/storage/wallet.ts; the repository has no license file) so tests can check
// that BRC Vault reads and writes exactly what BrowserCoin's Export/Import expect.
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));

export function generateKeyPair() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = ed.getPublicKey(privateKey);
  return { privateKey, publicKey, address: hex(publicKey) };
}

export function fromPrivateKey(privateKey) {
  if (privateKey.length !== 32) throw new Error('private key must be 32 bytes');
  const publicKey = ed.getPublicKey(privateKey);
  return { privateKey, publicKey, address: hex(publicKey) };
}

export function exportWalletJson(kp) {
  return JSON.stringify({
    type: 'browsercoin-wallet',
    version: 1,
    address: kp.address,
    privateKeyHex: hex(kp.privateKey),
    warning: 'Anyone with the private key controls the wallet. Keep this safe.',
  }, null, 2);
}

export function importWalletJson(text) {
  const parsed = JSON.parse(text);
  if (parsed.type !== 'browsercoin-wallet') throw new Error('not a BrowserCoin wallet file');
  if (!parsed.privateKeyHex) throw new Error('missing privateKeyHex');
  return fromPrivateKey(unhex(parsed.privateKeyHex));
}
