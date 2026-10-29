// Writes password-protected wallet files the way the BRC Wallet desktop app
// (github.com/Mattpomeranian/BRC-Wallet, src/wallet.js: encryptPrivateKeyHex and
// saveEncryptedWalletFile) does, using Node's own crypto just like that app.
// Written from its source so tests can check BRC Vault opens those files.
import crypto from 'node:crypto';

export function desktopEncryptedWalletJson({ privateKeyHex, address }, password, { N = 131072, r = 8, p = 1 } = {}) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32, { N, r, p, maxmem: 512 * 1024 * 1024 });
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(privateKeyHex, 'hex')), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return JSON.stringify({
    type: 'browsercoin-wallet',
    version: 2,
    address,
    encrypted: true,
    kdf: 'scrypt',
    kdfParams: { N, r, p, salt: salt.toString('hex') },
    cipher: 'aes-256-gcm',
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    ciphertext: ciphertext.toString('hex'),
    warning: 'This file is password-protected, but treat it as sensitive regardless.',
  }, null, 2);
}
