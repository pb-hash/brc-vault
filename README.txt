BRC Vault
=========

Offline, password-protected backups and paper wallets for BrowserCoin (BRC).

BRC Vault is a single web page, dist/brc-vault.html. Open it in any modern
browser, with the internet off if you like. It never uploads anything.

Use it online:  https://pb-hash.github.io/brc-vault/
Or download it: https://github.com/pb-hash/brc-vault/releases (brc-vault.html),
                save it, and open the saved file with Wi-Fi off.
Tested in Chrome on desktop and Safari on iPhone.

What it does
------------
Back up:  load the wallet file from BrowserCoin (browsercoin.org/app, then
          Settings > Export key...), a private key, or 24 recovery words.
          Choose a password, and get a locked backup file and/or a printable
          paper backup with QR codes.
Restore:  load the backup file or type the paper code, enter the password, and
          get a wallet file that BrowserCoin's Settings > Import key... accepts.
          It also opens 24 recovery words and password-protected files from the
          BRC Wallet desktop app.

Works with the other BrowserCoin wallets
----------------------------------------
- BRC Wallet for Android (github.com/ils94/BRC_Wallet_Android): its 24 words
  are standard BIP39 English with the private key as the entropy. BRC Vault
  reads and prints exactly those words, so the same paper restores in either.
- BRC Wallet desktop app for Windows (github.com/Mattpomeranian/BRC-Wallet):
  its password-protected export (version 2, scrypt + AES-256-GCM) opens in
  Restore with that app's password.

How it protects your key
------------------------
- The password is stretched with scrypt (N = 2^17, r = 8, p = 1; 128 MB per
  guess), then the 32-byte private key is encrypted with AES-256-GCM. All
  backup fields are bound to the encryption, so any change makes it fail.
- Each backup is test-opened before you can save it. Each restored key is
  checked against its address.
- The page's Content Security Policy allows only its own script (pinned by
  SHA-256) and blocks network requests. Peer-to-peer connections are disabled.
- Printed codes carry a 4-character check on every line, so a typo is caught
  and named before the password step.
- An unprotected paper key is printed as BRCKEY1:<key>:<address check>, so it
  can't be mistaken for a wallet address and a typo in it is caught. The same
  sheet lists the 24 recovery words.
- The camera scanner reads only BRC Vault codes, and the camera turns off as
  soon as the scanner closes.

The full file format is described under "Technical details" on the page.

Verify your copy
----------------
dist/SHA256.txt holds the SHA-256 of dist/brc-vault.html. Compare it with the
hash published on the project page:
    shasum -a 256 dist/brc-vault.html
Builds are reproducible: npm ci && npm run build gives the same file and hash.

Build and test
--------------
Needs Node 20+ and, for the browser tests, Python 3 with Playwright.
    npm ci
    npm run build    # writes dist/brc-vault.html and dist/SHA256.txt
    npm test         # unit tests + end-to-end browser tests

Code layout
-----------
src/core.js      keys, encryption, backup format, paper codes
src/app.js       page behaviour
src/index.html   page markup and styles
build.mjs        bundles everything into one self-contained file
test/            unit and browser tests
fonts/           Geist and Geist Mono, subset to Latin (SIL OFL 1.1)

BRC Vault is a community project. It is not made by the BrowserCoin
developers. MIT License; see LICENSE.
