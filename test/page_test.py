"""End-to-end test of dist/brc-vault.html in headless Chromium.

Usage: python3 test/page_test.py <output-dir-for-screenshots>
"""
import json, re, subprocess, sys, pathlib
from playwright.sync_api import sync_playwright, expect

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = (ROOT / "dist" / "brc-vault.html").as_uri()
OUT = pathlib.Path(sys.argv[1]); OUT.mkdir(parents=True, exist_ok=True)
PASSWORD = "my coins live in a browser tab"

def node(code):
    return subprocess.run(["node", "--input-type=module", "-e", code], cwd=ROOT, check=True,
                          capture_output=True, text=True).stdout

# A fresh test wallet in exactly BrowserCoin's export format.
wallet_json = node("""
import * as c from './build/core.mjs';
import { randomBytes } from 'node:crypto';
process.stdout.write(c.browserCoinWalletJson(c.walletFromPrivateKeyHex(randomBytes(32).toString('hex'))));
""")
wallet = json.loads(wallet_json)
wallet_file = OUT / "test-wallet.json"; wallet_file.write_text(wallet_json)

def decode_qr(locator, name):
    p = OUT / f"{name}.png"
    locator.screenshot(path=str(p))
    return subprocess.run(["node", "test/qrdecode.mjs", str(p)], cwd=ROOT, capture_output=True, text=True).stdout

passed = []
def ok(msg): passed.append(msg); print("ok -", msg)

def open_paste(page, panel):
    page.click("#b-paste-open" if panel == "backup" else "#r-paste-open")
    expect(page.locator("#b-paste" if panel == "backup" else "#r-paste")).to_be_focused()

def tick_restore_confirms(page):
    page.check("#r-ok-address")
    expect(page.locator("#r-download")).to_be_disabled()
    page.check("#r-ok-replace")
    expect(page.locator("#r-download")).to_be_enabled()

with sync_playwright() as pw:
    browser = pw.chromium.launch()
    ctx = browser.new_context(accept_downloads=True, viewport={"width": 1100, "height": 1400})
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(PAGE)

    # --- Lockdown ---
    blocked = page.evaluate("""async () => { try { await fetch('https://example.com/'); return false; } catch { return true; } }""")
    assert blocked, "fetch was not blocked"
    ran = page.evaluate("""async () => {
        window.__pwned = false;
        const d = document.createElement('div');
        d.innerHTML = '<img src="data:," onerror="window.__pwned = true"><svg onload="window.__pwned = true"></svg>';
        document.body.appendChild(d);
        await new Promise(r => setTimeout(r, 300));
        d.remove();
        return window.__pwned;
    }""")
    assert ran is False, "inline event handler executed"
    assert page.evaluate("typeof window.RTCPeerConnection") == "undefined"
    ok("page blocks network requests, injected inline scripts, and peer-to-peer connections")
    page.screenshot(path=str(OUT / "1-start.png"), full_page=True)

    # --- Back up: an address pasted by mistake must be caught ---
    open_paste(page, "backup")
    page.fill("#b-paste", wallet["address"])
    page.click("#b-paste-go")
    expect(page.locator("#b-key-confirm-wrap")).to_be_visible()
    expect(page.locator("#b-load-msg")).to_contain_text("looks exactly like a private key")
    assert page.locator("#b-address").inner_text() != wallet["address"]
    expect(page.locator("#b-step2")).to_have_attribute("data-state", "waiting")
    ok("pasting a wallet address on Back up is flagged, and password step stays locked until confirmed")

    # --- Back up from the real wallet file ---
    page.set_input_files("#b-file", str(wallet_file))
    expect(page.locator("#b-address")).to_have_text(wallet["address"])
    expect(page.locator("#b-chip-name")).to_have_text(wallet_file.name)
    expect(page.locator("#b-loaded")).to_contain_text("The key matches this address")
    expect(page.locator("#b-key-confirm-wrap")).to_be_hidden()
    ok("loads a BrowserCoin wallet file and shows its address")

    page.fill("#b-password", "too short")
    expect(page.locator("#b-make")).to_be_disabled()
    page.fill("#b-password", "aaaaaaaaaaaaaaaa")
    page.fill("#b-confirm", "aaaaaaaaaaaaaaaa")
    expect(page.locator("#b-pw-hint")).to_contain_text("repetitive")
    page.fill("#b-password", PASSWORD)
    page.fill("#b-confirm", PASSWORD + "x")
    expect(page.locator("#b-pw-hint")).to_contain_text("do not match")
    page.fill("#b-confirm", PASSWORD)
    expect(page.locator("#b-make")).to_be_disabled()  # still needs the "I understand" box
    page.check("#b-understand")
    expect(page.locator("#b-make")).to_be_enabled()
    ok("password rules and the no-recovery checkbox gate the button")

    page.click("#b-make")
    expect(page.locator("#b-done")).to_be_visible(timeout=60000)
    with page.expect_download() as dl:
        page.click("#b-download")
    backup_path = OUT / dl.value.suggested_filename
    dl.value.save_as(backup_path)
    backup = json.loads(backup_path.read_text())
    assert backup["type"] == "brc-vault-backup" and backup["address"] == wallet["address"]
    assert wallet["privateKeyHex"] not in backup_path.read_text()
    ok(f"made and downloaded an encrypted backup ({dl.value.suggested_filename}); private key not in it")
    page.wait_for_timeout(1200)
    page.screenshot(path=str(OUT / "2-backup-done.png"), full_page=True)

    # --- Paper backup: opens an on-screen preview with its own Print button ---
    page.click("#b-print")
    expect(page.locator("#paper-preview")).to_be_visible()
    expect(page.locator("#pp-print")).to_be_focused()
    page.screenshot(path=str(OUT / "3a-paper-preview.png"))
    qrs = page.locator("#print-sheet .ps-qr")
    assert decode_qr(qrs.nth(0), "qr-address") == wallet["address"]
    paper_code = decode_qr(qrs.nth(1), "qr-code")
    qrs.nth(1).locator("svg").screenshot(path=str(OUT / "qr-code-svg.png"))
    assert paper_code.startswith("BRCVAULT1:") and wallet["privateKeyHex"].upper() not in paper_code, paper_code[:20]
    printed_code = page.locator("#print-sheet .is-key .sheet-code").inner_text()
    assert printed_code.count("[") == 9, printed_code
    ok("paper backup opens a preview; its QR codes scan and every line carries a check")

    # Print really calls the browser's print, and the printout contains only the sheet.
    page.evaluate("() => { window.__printed = 0; window.print = () => { window.__printed++; window.dispatchEvent(new Event('beforeprint')); }; }")
    page.click("#pp-print")
    assert page.evaluate("window.__printed") == 1
    page.wait_for_timeout(1700)
    expect(page.locator("#pp-hint")).not_to_contain_text("didn't open")
    page.emulate_media(media="print")
    expect(page.locator(".app")).to_be_hidden()
    expect(page.locator(".pp-bar")).to_be_hidden()
    page.screenshot(path=str(OUT / "3-paper-encrypted.png"), full_page=True)
    page.pdf(path=str(OUT / "paper-backup.pdf"), format="Letter")
    page.emulate_media(media="screen")
    ok("Print opens the browser's print window, and the printout is only the sheet")

    # If the browser blocks printing (as some app previews do), say so instead of doing nothing.
    page.evaluate("() => { window.print = () => {}; }")
    page.click("#pp-print")
    expect(page.locator("#pp-hint")).to_contain_text("didn't open", timeout=4000)
    ok("a blocked print window is explained, with what to do next")
    page.keyboard.press("Escape")
    expect(page.locator("#paper-preview")).to_be_hidden()
    assert page.locator("#print-sheet").inner_html() == ""
    expect(page.locator("#b-print")).to_be_focused()

    page.click("details.risky summary")
    expect(page.locator("#b-print-plain")).to_be_disabled()
    page.check("#b-plain-ok")
    page.click("#b-print-plain")
    expect(page.locator("#pp-title")).to_contain_text("Unprotected")
    page.emulate_media(media="print")
    page.screenshot(path=str(OUT / "4-paper-plain.png"), full_page=True)
    key_qr = decode_qr(page.locator("#print-sheet .ps-qr").nth(1), "qr-key")
    assert key_qr == "BRCKEY1:" + wallet["privateKeyHex"].upper() + ":" + wallet["address"][:8].upper(), key_qr
    sheet_words = [re.sub(r"^\d+\s*", "", t) for t in page.locator("#print-sheet .ps-wordgrid li").all_inner_texts()]
    assert sheet_words == node(f"""
import * as c from './build/core.mjs';
process.stdout.write(c.walletToWords(c.walletFromPrivateKeyHex('{wallet["privateKeyHex"]}')).join(' '));
""").split(), sheet_words
    plain_lines = page.locator("#print-sheet .sheet-code .ps-codeline").all_inner_texts()
    assert len(plain_lines) == 4 and all(re.search(r"\[[0-9A-F]{4}\]$", l) for l in plain_lines), plain_lines
    ok("unprotected paper wallet needs a confirmation, and its QR is clearly marked as a key")
    page.emulate_media(media="screen")
    page.click("#pp-close")

    # --- Restore: crafted backup with fake address text is refused on load ---
    page.click("#tab-restore")
    scam = dict(backup, address="Send 500 BRC to support to unlock: 0123abcd")
    scam_file = OUT / "scam-backup.json"; scam_file.write_text(json.dumps(scam))
    page.set_input_files("#r-file", str(scam_file))
    expect(page.locator("#r-load-msg")).to_contain_text("damaged")
    expect(page.locator("#r-loaded")).to_be_hidden()
    ok("a backup with a fake address is refused before anything is shown")

    # --- Restore from the file: wrong password, then right ---
    page.set_input_files("#r-file", str(backup_path))
    expect(page.locator("#r-address")).to_have_text(wallet["address"])
    expect(page.locator("#r-address-label")).to_have_text("In backup")
    # Reprinting waits until the password has confirmed the address.
    expect(page.locator("#r-reprint-row")).to_be_hidden()
    page.fill("#r-password", "not the password at all")
    page.click("#r-unlock")
    expect(page.locator("#r-unlock-msg")).to_contain_text("Wrong password", timeout=60000)
    ok("wrong password is refused with a clear message")
    # A password pasted with Ctrl/Cmd+V while focus is outside the field doesn't wipe the loaded backup.
    page.evaluate("""() => {
        const dt = new DataTransfer(); dt.setData('text/plain', 'not the password at all');
        document.body.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true }));
    }""")
    expect(page.locator("#r-address")).to_have_text(wallet["address"])
    expect(page.locator("#r-load-msg")).to_be_hidden()
    ok("a stray paste on the page never replaces a loaded backup")
    page.fill("#r-password", PASSWORD)
    page.click("#r-unlock")
    expect(page.locator("#r-done")).to_be_visible(timeout=60000)
    expect(page.locator("#r-done-title")).to_have_text("Backup unlocked")
    expect(page.locator("#r-download")).to_be_disabled()
    page.evaluate("() => { window.print = () => {}; }")
    page.click("#r-reprint")
    expect(page.locator("#paper-preview")).to_be_visible()
    reprint_qr = decode_qr(page.locator("#print-sheet .ps-qr").nth(1), "qr-reprint")
    assert reprint_qr == paper_code, (reprint_qr[:30], paper_code[:30])
    page.locator("#print-sheet").click()  # focus leaves the buttons; Escape must still close
    page.keyboard.press("Escape")
    expect(page.locator("#paper-preview")).to_be_hidden()
    ok("after unlocking, a new paper copy can be printed, and Escape closes the preview")
    tick_restore_confirms(page)
    with page.expect_download() as dl2:
        page.click("#r-download")
    restored = OUT / ("restored-" + dl2.value.suggested_filename)
    dl2.value.save_as(restored)
    assert restored.read_text() == wallet_json, "restored file differs from the original export"
    ok("restore needs both confirmations, and the file is byte-for-byte identical to the original export")
    # After a restore, a different backup can be loaded without clearing the page.
    page.click("[data-restart='r']")
    expect(page.locator("#r-drop")).to_be_visible()
    expect(page.locator("#r-step2")).to_have_attribute("data-state", "waiting")
    page.set_input_files("#r-file", str(backup_path))
    expect(page.locator("#r-address")).to_have_text(wallet["address"])
    ok("after a restore, 'Load a different backup' brings the file picker back")
    page.screenshot(path=str(OUT / "5-restore-done.png"), full_page=True)

    # --- Restore from the code as printed on paper ---
    page.click("#clear-all")
    page.click("#tab-restore")
    open_paste(page, "restore")
    page.fill("#r-paste", printed_code.lower())
    page.click("#r-paste-go")
    page.fill("#r-password", PASSWORD)
    page.click("#r-unlock")
    expect(page.locator("#r-done-address")).to_have_text(wallet["address"], timeout=60000)
    ok("restores from the code exactly as printed on paper, typed in lower case")

    # --- Restore from exactly what a phone shows when it scans the QR code ---
    page.click("#clear-all")
    page.click("#tab-restore")
    open_paste(page, "restore")
    page.fill("#r-paste", paper_code)
    page.click("#r-paste-go")
    page.fill("#r-password", PASSWORD)
    page.click("#r-unlock")
    expect(page.locator("#r-done-address")).to_have_text(wallet["address"], timeout=60000)
    ok("restores from the exact text inside the locked backup QR code")

    # --- A typo is named by line, before the password step ---
    page.click("#clear-all")
    page.click("#tab-restore")
    open_paste(page, "restore")
    lines = printed_code.split("\n")
    lines[4] = ("D" if lines[4][0] != "D" else "0") + lines[4][1:]
    page.fill("#r-paste", "\n".join(lines))
    page.click("#r-paste-go")
    expect(page.locator("#r-load-msg")).to_contain_text("Line 5")
    expect(page.locator("#r-step2")).to_have_attribute("data-state", "waiting")
    ok("a typo in the paper code names the exact line, before any password is asked")

    # --- Unprotected key: with prefix it's clear; bare hex gets a warning ---
    page.click("#clear-all")
    page.click("#tab-restore")
    open_paste(page, "restore")
    page.fill("#r-paste", key_qr)
    page.click("#r-paste-go")
    expect(page.locator("#r-done-address")).to_have_text(wallet["address"])
    expect(page.locator("#r-done-msg")).to_be_hidden()
    page.click("#clear-all")
    page.click("#tab-restore")
    open_paste(page, "restore")
    page.fill("#r-paste", wallet["address"])  # someone scans the address QR by mistake
    page.click("#r-paste-go")
    expect(page.locator("#r-done-msg")).to_contain_text("wallet address")
    expect(page.locator("#r-done-title")).to_have_text("Wallet ready")
    expect(page.locator("#r-download")).to_be_disabled()
    ok("restores a BRCKEY1 key; a bare 64-character code gets an address warning and stays locked")

    # --- 24 recovery words (as the BRC Wallet Android app shows them) ---
    words = node(f"""
import * as c from './build/core.mjs';
process.stdout.write(c.walletToWords(c.walletFromPrivateKeyHex('{wallet["privateKeyHex"]}')).join(' '));
""").split()
    assert len(words) == 24
    page.click("#clear-all")
    page.click("#tab-restore")
    open_paste(page, "restore")
    page.fill("#r-paste", "\n".join(f"{i + 1}. {w}" for i, w in enumerate(words)))
    page.click("#r-paste-go")
    expect(page.locator("#r-done-address")).to_have_text(wallet["address"])
    expect(page.locator("#r-done-title")).to_have_text("Wallet ready")
    expect(page.locator("#r-done-check")).to_contain_text("these words")
    expect(page.locator("#r-chip-name")).to_have_text("Recovery words")
    expect(page.locator("#r-done-msg")).to_be_hidden()
    expect(page.locator("#r-words li")).to_have_count(0)  # not on screen until asked for
    page.click("#r-words-wrap summary")
    expect(page.locator("#r-words li")).to_have_count(24)
    shown = [re.sub(r"^\d+\s*", "", t) for t in page.locator("#r-words li").all_inner_texts()]
    assert shown == words, shown
    page.click("#r-words-wrap summary")
    expect(page.locator("#r-words li")).to_have_count(0)
    tick_restore_confirms(page)
    with page.expect_download() as dl3:
        page.click("#r-download")
    p3 = OUT / ("from-words-" + dl3.value.suggested_filename); dl3.value.save_as(p3)
    assert p3.read_text() == wallet_json
    page.click("#r-to-backup")
    expect(page.locator("#b-address")).to_have_text(wallet["address"])
    expect(page.locator("#b-chip-name")).to_have_text("Wallet from Restore")
    ok("24 recovery words restore the exact wallet file; the words show only on request; one click backs it up")

    # --- A password-protected file from the BRC Wallet desktop app ---
    desktop_json = node(f"""
import {{ desktopEncryptedWalletJson }} from './test/desktop-wallet-reference.mjs';
process.stdout.write(desktopEncryptedWalletJson({{ privateKeyHex: '{wallet["privateKeyHex"]}', address: '{wallet["address"]}' }}, 'windows wallet pw'));
""")
    desktop_file = OUT / "brc-wallet-desktop-encrypted.json"; desktop_file.write_text(desktop_json)
    page.click("#clear-all")
    page.click("#tab-backup")
    page.set_input_files("#b-file", str(desktop_file))
    expect(page.locator("#b-load-msg")).to_contain_text("BRC Wallet desktop app")
    page.click("#tab-restore")
    page.set_input_files("#r-file", str(desktop_file))
    expect(page.locator("#r-address-label")).to_have_text("In wallet file")
    expect(page.locator("#r-load-msg")).to_contain_text("desktop app")
    page.fill("#r-password", "wrong password here")
    page.click("#r-unlock")
    expect(page.locator("#r-unlock-msg")).to_contain_text("Wrong password", timeout=60000)
    page.fill("#r-password", "windows wallet pw")
    page.click("#r-unlock")
    expect(page.locator("#r-done-title")).to_have_text("Wallet file unlocked", timeout=60000)
    expect(page.locator("#r-reprint-row")).to_be_hidden()
    tick_restore_confirms(page)
    with page.expect_download() as dl4:
        page.click("#r-download")
    p4 = OUT / ("from-desktop-" + dl4.value.suggested_filename); dl4.value.save_as(p4)
    assert p4.read_text() == wallet_json
    ok("a password-protected BRC Wallet desktop file unlocks into the exact BrowserCoin wallet file")

    # --- Pasting into a box with leftover text replaces it; a doubled paste still loads ---
    page.click("#clear-all")
    page.click("#tab-backup")
    open_paste(page, "backup")
    page.fill("#b-paste", "leftover text from before")
    page.evaluate("""(text) => {
        const dt = new DataTransfer(); dt.setData('text/plain', text);
        document.querySelector('#b-paste').dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
    }""", wallet_json)
    expect(page.locator("#b-address")).to_have_text(wallet["address"])
    page.click("#clear-all")
    open_paste(page, "backup")
    page.fill("#b-paste", wallet_json + "\n" + wallet_json)
    page.click("#b-paste-go")
    expect(page.locator("#b-address")).to_have_text(wallet["address"])
    ok("pasting replaces leftover text in the box, and a wallet pasted twice still loads")

    # --- A wallet file re-saved by TextEdit (rich text, curly quotes) still loads, with a note ---
    page.click("#clear-all")
    page.click("#tab-backup")
    rtf = ("{\\rtf1\\ansi\\ansicpg1252\\cocoartf2761\n{\\fonttbl\\f0\\fswiss\\fcharset0 Helvetica;}\n\\f0\\fs24 \\cf0 "
           + re.sub(r'"([^"]*)"', lambda m: "\\'93" + m.group(1) + "\\'94", wallet_json).replace("{", "\\{").replace("}", "\\}").replace("\n", "\\\n") + "}")
    rtf_file = OUT / "textedit-wallet.json"; rtf_file.write_text(rtf)
    page.set_input_files("#b-file", str(rtf_file))
    expect(page.locator("#b-address")).to_have_text(wallet["address"])
    expect(page.locator("#b-load-msg")).to_contain_text("changed by another app")
    ok("a wallet file re-saved by TextEdit is recovered, checked against its address, and flagged")

    # --- Wrong kind of file in Back up ---
    page.click("#clear-all")
    page.click("#tab-backup")
    page.set_input_files("#b-file", str(backup_path))
    expect(page.locator("#b-load-msg")).to_contain_text("already a BRC Vault backup")
    ok("backup tab explains when given a backup instead of a wallet")

    # --- Oversize file shows a message instead of failing silently ---
    big = OUT / "big.json"; big.write_text("x" * 70000)
    page.set_input_files("#b-file", str(big))
    expect(page.locator("#b-load-msg")).to_contain_text("too large")
    ok("an oversized file is refused with a message")

    # --- Clear resets everything, including revealed passwords ---
    page.set_input_files("#b-file", str(wallet_file))
    page.fill("#b-password", PASSWORD)
    page.click("[data-reveal='b-password b-confirm']")
    assert page.get_attribute("#b-password", "type") == "text"
    page.click("#clear-all")
    assert page.get_attribute("#b-password", "type") == "password"
    assert page.input_value("#b-password") == ""
    expect(page.locator("#b-loaded")).to_be_hidden()
    ok("Clear page empties fields and hides revealed passwords")

    # --- Polish: paste anywhere, drop anywhere, copy, toast ---
    page.click("#clear-all")
    page.click("#tab-backup")
    page.evaluate("""(text) => {
        const dt = new DataTransfer(); dt.setData('text/plain', text);
        document.body.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true }));
    }""", wallet_json)
    expect(page.locator("#b-address")).to_have_text(wallet["address"])
    ok("pressing Ctrl/Cmd+V anywhere on the page loads a pasted wallet")

    page.click("#clear-all")
    page.evaluate("""(text) => {
        const dt = new DataTransfer(); dt.items.add(new File([text], 'dropped-wallet.json', { type: 'application/json' }));
        document.querySelector('.hero h1').dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true }));
    }""", wallet_json)
    expect(page.locator("#b-address")).to_have_text(wallet["address"])
    expect(page.locator("#b-chip-name")).to_have_text("dropped-wallet.json")
    assert page.url.endswith("brc-vault.html")
    ok("a file dropped anywhere on the page loads, and the page doesn't navigate away")

    ctx.grant_permissions(["clipboard-read", "clipboard-write"])
    page.click("[data-copy='b-address']")
    expect(page.locator("#toast")).to_contain_text("Address copied")
    assert page.evaluate("navigator.clipboard.readText()") == wallet["address"]
    ok("the copy button puts the full address on the clipboard and confirms it")

    # --- Lock moment and sound switch ---
    page.click("#clear-all")
    page.click("#tab-backup")
    page.set_input_files("#b-file", str(wallet_file))
    page.fill("#b-password", PASSWORD); page.fill("#b-confirm", PASSWORD); page.check("#b-understand")
    page.click("#b-make")
    expect(page.locator("#b-done")).to_have_class(re.compile("is-in"), timeout=60000)
    assert page.evaluate("getComputedStyle(document.querySelector('#b-done .lm-dot')).animationName") == "lm-drop"
    assert page.evaluate("getComputedStyle(document.querySelector('#b-done .lm-word i:last-child')).animationName") == "lm-wave"
    expect(page.locator("#sound-toggle")).to_have_attribute("aria-pressed", "true")
    page.click("#sound-toggle")
    expect(page.locator("#sound-toggle")).to_have_attribute("aria-pressed", "false")
    expect(page.locator("#sound-label")).to_have_text("Sound off")
    page.reload()
    expect(page.locator("#sound-toggle")).to_have_attribute("aria-pressed", "false")
    page.click("#sound-toggle")
    expect(page.locator("#sound-toggle")).to_have_attribute("aria-pressed", "true")
    ok("locking plays the logo animation; the sound switch works and is remembered")

    # --- Scan a paper backup with the camera (a fake camera showing the printed QR) ---
    qr_png = OUT / "qr-code-svg.png"
    from PIL import Image
    im = Image.open(qr_png).convert("RGB")
    side = 720
    canvas = Image.new("RGB", (1280, 720), (238, 236, 230))
    q = im.resize((520, 520), Image.NEAREST)
    canvas.paste(q, ((1280 - 520) // 2, (720 - 520) // 2))
    frame_png = OUT / "camera-frame.png"; canvas.save(frame_png)
    y4m = OUT / "camera.y4m"
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-loop", "1", "-i", str(frame_png), "-t", "3", "-r", "15", "-pix_fmt", "yuv420p", str(y4m)], check=True)
    cam = pw.chromium.launch(args=["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", f"--use-file-for-fake-video-capture={y4m}"])
    cp = cam.new_page()
    cp.on("pageerror", lambda e: errors.append(str(e)))
    cp.goto(PAGE)
    cp.click("#tab-restore")
    cp.click("#r-scan-open")
    expect(cp.locator("#r-scan-panel")).to_be_visible()
    expect(cp.locator("#r-address")).to_have_text(wallet["address"], timeout=20000)
    expect(cp.locator("#r-chip-name")).to_have_text("Scanned paper backup")
    assert cp.evaluate("document.querySelector('#r-scan-video').srcObject") is None, "camera left on after scanning"
    cp.fill("#r-password", PASSWORD)
    cp.click("#r-unlock")
    expect(cp.locator("#r-done-address")).to_have_text(wallet["address"], timeout=60000)
    ok("scanning the printed QR with the built-in camera scanner restores the wallet, and the camera turns off")

    # Closing the scanner (Cancel, another tab, Clear page) while the browser is still
    # asking for camera permission must leave the camera off when permission arrives.
    slow_cam = """() => {
        window.__streams = [];
        const real = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
        navigator.mediaDevices.getUserMedia = async (c) => {
            await new Promise((r) => setTimeout(r, 1200));
            const s = await real(c); window.__streams.push(s); return s;
        };
    }"""
    live_tracks = "() => window.__streams.flatMap((s) => s.getTracks()).filter((t) => t.readyState === 'live').length"
    for how in ["cancel", "tab", "clear", "reopen"]:
        sp = cam.new_page()
        sp.add_init_script(f"({slow_cam})()")
        sp.goto(PAGE)
        sp.click("#tab-restore")
        sp.click("#r-scan-open")
        sp.wait_for_timeout(300)
        if how == "cancel": sp.click("#r-scan-panel [data-scan-cancel]")
        elif how == "tab": sp.click("#tab-backup")
        elif how == "clear": sp.click("#clear-all")
        else:
            sp.click("#r-scan-panel [data-scan-cancel]"); sp.click("#r-scan-open")
        sp.wait_for_timeout(2500)
        if how == "reopen":
            # The first, abandoned request is switched off; only the reopened scanner runs
            # (and this fake camera shows a real backup QR, so it reads it and stops too).
            assert sp.evaluate("window.__streams[0].getTracks()[0].readyState") == "ended"
            assert sp.evaluate(live_tracks) <= 1
            if sp.locator("#r-scan-panel").is_visible(): sp.click("#r-scan-panel [data-scan-cancel]")
            sp.wait_for_timeout(200)
            assert sp.evaluate(live_tracks) == 0
        else:
            assert sp.evaluate(live_tracks) == 0, (how, sp.evaluate(live_tracks))
            expect(sp.locator("#r-loaded")).to_be_hidden()  # the closed scanner never loads anything
        sp.close()
    cam.close()
    ok("closing the scanner while camera permission is pending leaves the camera off, and nothing loads")

    # Holding up the small wallet address QR is named, ignored, and scanning carries on.
    im = Image.open(OUT / "qr-address.png").convert("RGB")
    canvas = Image.new("RGB", (1280, 720), (238, 236, 230))
    canvas.paste(im.resize((520, 520), Image.NEAREST), ((1280 - 520) // 2, (720 - 520) // 2))
    canvas.save(OUT / "camera-frame-address.png")
    y4m_addr = OUT / "camera-address.y4m"
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-loop", "1", "-i", str(OUT / "camera-frame-address.png"), "-t", "3", "-r", "15", "-pix_fmt", "yuv420p", str(y4m_addr)], check=True)
    cam = pw.chromium.launch(args=["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream", f"--use-file-for-fake-video-capture={y4m_addr}"])
    ap = cam.new_page()
    ap.on("pageerror", lambda e: errors.append(str(e)))
    ap.goto(PAGE)
    ap.click("#tab-restore")
    ap.click("#r-scan-open")
    expect(ap.locator("#r-scan-hint")).to_contain_text("wallet address QR code", timeout=20000)
    expect(ap.locator("#r-loaded")).to_be_hidden()
    expect(ap.locator("#r-done")).to_be_hidden()
    assert ap.evaluate("document.querySelector('#r-scan-video').srcObject !== null"), "scanning should carry on"
    ap.click("#r-scan-panel [data-scan-cancel]")
    assert ap.evaluate("document.querySelector('#r-scan-video').srcObject") is None
    cam.close()
    ok("scanning the address QR by mistake is explained and ignored; it never counts as a key")

    # Inside a locked-down preview (like an app's file viewer) the camera can't work: say so clearly.
    import http.server, threading, functools
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(ROOT / "dist"))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    fp = browser.new_page()
    fp.goto(f"http://127.0.0.1:{port}/")
    fp.set_content(f'<iframe sandbox="allow-scripts allow-downloads" src="http://127.0.0.1:{port}/brc-vault.html" style="width:420px;height:900px"></iframe>')
    fp.wait_for_timeout(1500)
    fr = [f for f in fp.frames if f.url.endswith("brc-vault.html")][0]
    fr.click("#tab-restore")
    fr.click("#r-scan-open")
    fr.wait_for_selector(".scan-view[data-state='problem']", timeout=10000)
    assert "inside this preview" in fr.inner_text("#r-scan-overlay-text")
    assert fr.is_visible("#r-scan-to-type")
    fr.click("#r-scan-to-type")
    assert fr.is_visible("#r-paste")
    fp.close(); srv.shutdown()
    ok("inside a locked-down preview, the scanner explains the camera can't be used and offers typing instead")

    assert not errors, errors
    ok("no script errors")

    # Visual checks at phone width.
    phone = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2)
    pp = phone.new_page(); pp.goto(PAGE)
    pp.screenshot(path=str(OUT / "6-phone.png"), full_page=True)
    browser.close()

print(f"\n{len(passed)} page checks passed")
