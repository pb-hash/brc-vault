"""The English / 中文 switch in dist/brc-vault.html, in headless Chromium.

Usage: python3 test/i18n_test.py <output-dir-for-screenshots>

The switch must only change words. These checks make sure it never changes what Vault makes:
a backup made and restored in Chinese gives back the exact wallet file.
"""
import json, re, subprocess, sys, pathlib
from playwright.sync_api import sync_playwright, expect

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = (ROOT / "dist" / "brc-vault.html").as_uri()
OUT = pathlib.Path(sys.argv[1]); OUT.mkdir(parents=True, exist_ok=True)
PASSWORD = "my coins live in a browser tab"
HAN = re.compile(r"[一-鿿]")

passed = []
def ok(msg): passed.append(msg); print("ok -", msg)

wallet_json = subprocess.run(["node", "--input-type=module", "-e", """
import * as c from './build/core.mjs';
import { randomBytes } from 'node:crypto';
process.stdout.write(c.browserCoinWalletJson(c.walletFromPrivateKeyHex(randomBytes(32).toString('hex'))));
"""], cwd=ROOT, check=True, capture_output=True, text=True).stdout
wallet = json.loads(wallet_json)
wallet_file = OUT / "i18n-wallet.json"; wallet_file.write_text(wallet_json)

ENGLISH_LEFT = """() => {
  const skip = (e) => { for (; e; e = e.parentElement) { if (/^(SCRIPT|STYLE|CODE|PRE|KBD|SAMP|TEXTAREA)$/.test(e.tagName) || e.getAttribute('translate') === 'no' || /(^|\\s)(mono|addr|message-box|signed-box|unsigned-box|signed-msg)(\\s|$)/.test(e.className && e.className.baseVal === undefined ? e.className : '')) return true; } return false; };
  const vis = (e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden'; };
  const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let all = 0; const left = [];
  for (let n; (n = w.nextNode());) {
    const t = n.data.replace(/\\s+/g, ' ').trim();
    if (!/[a-z]{3,}/.test(t) || !n.parentElement || skip(n.parentElement) || !vis(n.parentElement)) continue;
    const words = t.replace(/\\b(BrowserCoin|BRC|Vault|Pulse|Post|Works|Geist|scrypt|AES|GCM|BIP39|Ed25519|Settings|Export|Import|key|pb-hash|Chrome|Safari|Edge|Firefox|iPhone|Android|Windows|SHA|JSON|QR|MIT|Wi-Fi|BRCVAULT1|BRCKEY1|browsercoin|org|app|github|com|brc|vault|build|json|http|https|ils94|Mattpomeranian|Wallet|Desktop|BRC_Wallet_Android)\\b/g, '');
    all++;
    if (/[a-z]{3,}/.test(words) && !/[\\u4e00-\\u9fff]/.test(t)) left.push(t.slice(0, 80));
  }
  return { all, left };
}"""

def body_text(page):
    return page.evaluate("() => document.body.innerText")

with sync_playwright() as pw:
    browser = pw.chromium.launch()
    errors = []

    # --- Default follows the browser: English for an English browser ---
    ctx = browser.new_context(accept_downloads=True, viewport={"width": 1100, "height": 1400}, locale="en-US")
    page = ctx.new_page(); page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(PAGE)
    expect(page.locator("[data-lang-toggle]")).to_have_text("中文")
    assert page.evaluate("document.documentElement.lang") == "en"
    english = body_text(page)
    assert not HAN.search(english.replace("中文", "")), "Chinese text on the English page"
    ok("an English browser gets English, with a 中文 button in the top bar")

    # --- Switch to Chinese ---
    page.click("[data-lang-toggle]")
    expect(page.locator("[data-lang-toggle]")).to_have_text("EN")
    assert page.evaluate("document.documentElement.lang") == "zh-CN"
    expect(page.locator(".hero h1")).to_contain_text(HAN)
    expect(page.locator("#tab-backup")).to_contain_text(HAN)
    cover = page.evaluate(ENGLISH_LEFT)
    print("   visible text left in English:", len(cover["left"]), "of", cover["all"], cover["left"][:8])
    assert len(cover["left"]) <= max(3, cover["all"] // 25), cover["left"]
    page.screenshot(path=str(OUT / "zh-1-start.png"), full_page=True)
    ok(f"中文 switches the page to Chinese ({cover['all'] - len(cover['left'])} of {cover['all']} visible texts)")

    # --- And back, to exactly the same English ---
    page.click("[data-lang-toggle]")
    expect(page.locator("[data-lang-toggle]")).to_have_text("中文")
    back = body_text(page)
    if back != english:
        import difflib
        print("\n".join(difflib.unified_diff(english.splitlines(), back.splitlines(), lineterm="", n=0)))
    assert back == english, "switching back did not restore the exact English text"
    ok("EN switches back to exactly the original English")

    # --- Typed text is never touched ---
    page.click("[data-lang-toggle]")
    page.click("#b-paste-open")
    page.fill("#b-paste", "Back up")
    page.click("[data-lang-toggle]"); page.click("[data-lang-toggle]")
    assert page.input_value("#b-paste") == "Back up"
    page.fill("#b-paste", "")
    ok("what you type stays exactly as typed, even when it matches a button's words")

    # --- A full backup and restore in Chinese gives back the identical wallet file ---
    page.reload()
    expect(page.locator("[data-lang-toggle]")).to_have_text("EN")
    assert page.evaluate("document.documentElement.lang") == "zh-CN"
    ok("the choice is remembered on this device after a reload")
    page.set_input_files("#b-file", str(wallet_file))
    expect(page.locator("#b-address")).to_have_text(wallet["address"])
    page.fill("#b-password", PASSWORD)
    page.fill("#b-confirm", PASSWORD)
    page.check("#b-understand")
    page.click("#b-make")
    expect(page.locator("#b-done")).to_be_visible(timeout=60000)
    expect(page.locator("#b-done-address")).to_have_text(wallet["address"])
    with page.expect_download() as dl:
        page.click("#b-download")
    backup_path = OUT / ("zh-" + dl.value.suggested_filename); dl.value.save_as(backup_path)
    backup = json.loads(backup_path.read_text())
    assert backup["type"] == "brc-vault-backup" and backup["address"] == wallet["address"]
    page.screenshot(path=str(OUT / "zh-2-backup-done.png"), full_page=True)
    page.click("#tab-restore")
    page.set_input_files("#r-file", str(backup_path))
    expect(page.locator("#r-address")).to_have_text(wallet["address"])
    page.fill("#r-password", PASSWORD)
    page.click("#r-unlock")
    expect(page.locator("#r-done")).to_be_visible(timeout=60000)
    expect(page.locator("#r-done-title")).to_contain_text(HAN)
    words = subprocess.run(["node", "--input-type=module", "-e", f"""
import * as c from './build/core.mjs';
process.stdout.write(c.walletToWords(c.walletFromPrivateKeyHex('{wallet["privateKeyHex"]}')).join(' '));
"""], cwd=ROOT, check=True, capture_output=True, text=True).stdout.split()
    page.evaluate("() => { const d = document.querySelector('#r-words-wrap'); d.open = true; }")
    expect(page.locator("#r-words li")).to_have_count(24)
    shown = page.evaluate("() => [...document.querySelectorAll('#r-words li')].map((li) => li.lastChild.textContent)")
    assert shown == words, (shown[:5], words[:5])
    ok("the 24 recovery words show exactly as they are in Chinese, never translated")
    page.check("#r-ok-address"); page.check("#r-ok-replace")
    with page.expect_download() as dl2:
        page.click("#r-download")
    restored = OUT / ("zh-restored-" + dl2.value.suggested_filename); dl2.value.save_as(restored)
    assert restored.read_text() == wallet_json, "restored file differs from the original export"
    page.screenshot(path=str(OUT / "zh-3-restore-done.png"), full_page=True)
    ok("back up and restore in Chinese: the restored wallet file is byte-for-byte the original")

    # --- Paper backup in Chinese: the codes are untouched ---
    page.evaluate("() => { window.print = () => {}; }")
    page.click("#r-reprint")
    expect(page.locator("#paper-preview")).to_be_visible()
    codes = page.evaluate("() => [...document.querySelectorAll('#print-sheet .ps-mono, #print-sheet .ps-codeline, #print-sheet .ps-wordgrid')].map((e) => e.textContent).join('\\n')")
    assert codes.strip() and not HAN.search(codes), "Chinese inside a printed code"
    sheet = page.locator("#print-sheet").inner_text()
    assert HAN.search(sheet), "the paper backup's instructions should be in Chinese"
    words = page.evaluate("() => [...document.querySelectorAll('#print-sheet .ps-wordgrid li')].map((e) => e.textContent.trim()).filter(Boolean)")
    assert all(re.fullmatch(r"[0-9. ]*[a-z]+", w) for w in words), words[:6]
    page.screenshot(path=str(OUT / "zh-4-paper.png"), full_page=True)
    page.keyboard.press("Escape")
    ok("the paper backup's codes and address stay exactly as they are")
    ctx.close()

    # --- A Chinese browser gets Chinese at once; ?lang=en wins ---
    ctx = browser.new_context(locale="zh-CN", viewport={"width": 390, "height": 844})
    page = ctx.new_page(); page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(PAGE)
    expect(page.locator(".hero h1")).to_contain_text(HAN)
    expect(page.locator("[data-lang-toggle]")).to_be_visible()
    width = page.evaluate("() => document.documentElement.scrollWidth")
    assert width <= 390, f"page is {width}px wide on a phone"
    page.screenshot(path=str(OUT / "zh-5-phone.png"), full_page=True)
    page.goto(PAGE + "?lang=en")
    expect(page.locator("[data-lang-toggle]")).to_have_text("中文")
    ok("a Chinese browser opens in Chinese and fits a phone; ?lang=en opens English")
    ctx.close()

    assert not errors, errors
    ok("no script errors")
    browser.close()

print(f"\n{len(passed)} language checks passed")
