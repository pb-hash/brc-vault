// BRC Vault page logic. Everything happens in this tab; nothing is sent anywhere.
import qrcode from 'qrcode-generator';
import jsQR from 'jsqr';
import * as core from './core.js';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function show(el, on = true) { el.hidden = !on; }

function setMessage(el, text, tone = 'info') {
  el.textContent = text || '';
  el.dataset.tone = tone;
  show(el, Boolean(text));
}

function setStep(id, state) { $(id).dataset.state = state; }

function download(filename, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

/** Render a QR code as crisp SVG (prints sharply at any size). */
function qrSvg(text, { mode = 'Byte', ecc = 'M', label = '' } = {}) {
  const qr = qrcode(0, ecc);
  qr.addData(text, mode);
  qr.make();
  const n = qr.getModuleCount();
  const quiet = 4;
  const size = n + quiet * 2;
  let path = '';
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (qr.isDark(r, c)) path += `M${c + quiet} ${r + quiet}h1v1h-1z`;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" role="img" aria-label="${escapeHtml(label)}"><rect width="${size}" height="${size}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`;
}

/** Read a chosen or dropped file as text, refusing anything too large to be a wallet. */
async function readSmallFile(file) {
  if (file.size > 64 * 1024) throw new Error('That file is too large to be a wallet or backup.');
  return file.text();
}

const IS_MAC = /Mac|iPhone|iPad/.test(navigator.platform);
const intakes = {};

/**
 * One place to take a wallet or backup in: pick a file, drop it anywhere on the
 * card, paste into the box, or press Cmd/Ctrl+V anywhere while this step is open.
 */
function wireIntake(prefix, onText, msgEl, isOpen) {
  const intake = $(`#${prefix}-intake`);
  const box = $(`#${prefix}-paste`);
  const handleFile = async (file) => {
    if (!file) return;
    try { onText(await readSmallFile(file), file.name); } catch (e) { setMessage(msgEl, e.message, 'bad'); }
  };
  const scanPanel = $(`#${prefix}-scan-panel`);
  const setMode = (mode, name) => {
    // Always stop the camera when the scanner closes, even if it is still
    // waiting for permission and has not started yet.
    if (scanPanel && mode !== 'scan') stopScan();
    intake.dataset.mode = mode;
    if (scanPanel) show(scanPanel, mode === 'scan');
    show($(`#${prefix}-paste-panel`), mode === 'paste');
    show($(`#${prefix}-chip`), mode === 'loaded');
    if (mode === 'loaded') $(`#${prefix}-chip-name`).textContent = name || '';
    if (mode === 'paste') box.focus();
    else box.value = '';
  };
  const input = $(`#${prefix}-file`);
  input.addEventListener('change', () => { const f = input.files?.[0]; input.value = ''; handleFile(f); });
  $(`#${prefix}-paste-open`).addEventListener('click', () => setMode('paste'));
  const scanOpen = $(`#${prefix}-scan-open`);
  if (scanOpen) {
    scanOpen.addEventListener('click', () => {
      setMessage(msgEl, '');
      setMode('scan');
      startScan((text) => onText(text, /^BRCKEY1/i.test(text.trim()) ? 'Scanned paper wallet' : 'Scanned paper backup'), $(`#${prefix}-scan-hint`));
    });
    $(`#${prefix}-scan-panel [data-scan-cancel]`).addEventListener('click', () => { setMode('file'); scanOpen.focus(); });
  }
  $(`[data-intake-back="${prefix}"]`).addEventListener('click', () => { setMode('file'); setMessage(msgEl, ''); $(`#${prefix}-paste-open`).focus(); });
  $(`#${prefix}-paste-go`).addEventListener('click', () => onText(box.value));
  $(`[data-intake-change="${prefix}"]`).addEventListener('click', () => { setMode('file'); $(`#${prefix}-paste-open`).focus(); });
  box.addEventListener('paste', (e) => {
    // A complete wallet or backup replaces whatever was already in the box,
    // so leftover text can't get mixed in with it.
    const text = e.clipboardData?.getData('text') ?? '';
    if (text.trim() && box.value.trim()) {
      try {
        const id = core.identifyInput(text);
        core.wipeWallet(id.wallet);
        e.preventDefault();
        box.value = text;
      } catch { /* a partial paste, such as one line of a paper code: insert it normally */ }
    }
    setTimeout(() => { if (box.value.trim()) onText(box.value); }, 0);
  });
  box.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); onText(box.value); } });
  intakes[prefix] = { setMode, handleFile, onText, isOpen, drop: $(`#${prefix}-drop`), mode: () => intake.dataset.mode };
}

function activeIntake() {
  const tab = $('#segmented').dataset.active === 'restore' ? 'r' : 'b';
  const it = intakes[tab];
  return it && it.isOpen() && $('#paper-preview').hidden ? it : null;
}

// Paste anywhere on the page while the first step is open.
document.addEventListener('paste', (e) => {
  const t = e.target;
  if (t instanceof HTMLElement && (t.matches('input, textarea') || t.isContentEditable)) return;
  const it = activeIntake();
  const text = e.clipboardData?.getData('text') ?? '';
  if (!it || !text.trim()) return;
  // Once a wallet or backup is loaded, a stray paste (say, a password pasted
  // while focus wasn't in the field) must not replace it.
  if ((it === intakes.b && backup.wallet) || (it === intakes.r && restore.pending)) return;
  e.preventDefault();
  it.onText(text);
});

// Dropping a file anywhere loads it, and never navigates away from the page.
let dragDepth = 0;
const hasFiles = (e) => [...(e.dataTransfer?.types || [])].includes('Files');
window.addEventListener('dragenter', (e) => {
  if (!hasFiles(e)) return;
  dragDepth++;
  const it = activeIntake();
  document.body.classList.toggle('is-dragging', Boolean(it));
  if (it) it.drop.classList.add('is-over');
});
window.addEventListener('dragleave', () => {
  if (--dragDepth > 0) return;
  dragDepth = 0;
  document.body.classList.remove('is-dragging');
  $$('.drop.is-over').forEach((d) => d.classList.remove('is-over'));
});
window.addEventListener('dragover', (e) => { e.preventDefault(); });
window.addEventListener('drop', (e) => {
  e.preventDefault();
  dragDepth = 0;
  document.body.classList.remove('is-dragging');
  $$('.drop.is-over').forEach((d) => d.classList.remove('is-over'));
  const it = activeIntake();
  if (it) it.handleFile(e.dataTransfer?.files?.[0]);
});

/** Show an address with its first 8 and last 4 characters emphasised, for easy comparison. */
function renderAddress(el, addr) {
  // Groups of 8, spaced with CSS so a copy still gives the plain 64 characters.
  const groups = addr.match(/.{1,8}/g).map((g, i, all) => {
    const span = document.createElement('span');
    span.className = 'g';
    if (i === 0) {
      const b = document.createElement('strong'); b.textContent = g; span.append(b);
    } else if (i === all.length - 1) {
      const b = document.createElement('strong'); b.textContent = g.slice(-4);
      span.append(document.createTextNode(g.slice(0, -4)), b);
    } else {
      span.textContent = g;
    }
    return span;
  });
  el.replaceChildren(...groups);
}

let toastTimer;
function toast(text) {
  const el = $('#toast');
  $('#toast-text').textContent = text;
  show(el, true);
  requestAnimationFrame(() => el.classList.add('is-in'));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.classList.remove('is-in'); setTimeout(() => show(el, false), 300); }, 2600);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const t = document.createElement('textarea');
    t.value = text;
    t.setAttribute('readonly', '');
    t.style.position = 'fixed';
    t.style.opacity = '0';
    document.body.appendChild(t);
    t.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    t.remove();
    return ok;
  }
}

$$('[data-copy]').forEach((btn) => btn.addEventListener('click', async () => {
  const text = $(`#${btn.dataset.copy}`).textContent;
  toast(await copyText(text) ? 'Address copied' : 'Couldn\'t copy. Select the address and copy it instead.');
}));

// ---------------------------------------------------------------------------
// Sound: a short mechanical lock and unlock, synthesised on the spot (no audio
// files, nothing fetched). Quiet by design, and easy to switch off.
// ---------------------------------------------------------------------------

const SOUND_KEY = 'brcvault:sound';
let audioCtx = null;

function soundOn() {
  try { return localStorage.getItem(SOUND_KEY) !== 'off'; } catch { return true; }
}

function renderSoundToggle() {
  const on = soundOn();
  $('#sound-toggle').setAttribute('aria-pressed', String(on));
  $('#sound-label').textContent = on ? 'Sound on' : 'Sound off';
}

$('#sound-toggle').addEventListener('click', () => {
  const next = !soundOn();
  try { localStorage.setItem(SOUND_KEY, next ? 'on' : 'off'); } catch { /* preference just won't be remembered */ }
  renderSoundToggle();
  if (next) { primeAudio(); playSound('unlock', 0.02); }
});

/** Browsers only allow sound that starts from a click, so get it ready during the click. */
function primeAudio() {
  if (!soundOn()) return;
  try {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return;
    audioCtx = audioCtx || new AC();
    if (audioCtx.state === 'suspended') audioCtx.resume();
  } catch { audioCtx = null; }
}

/**
 * The sounds themselves, scheduled from t0:
 *   lock   - a bright, positive "bing": a bell tone with a soft lower note under it
 *   unlock - a crisp, short mechanical click
 */
function lockSynth(ctx, out, kind, t0) {
  const env = (node, t, peak, attack, dur) => {
    const g = ctx.createGain();
    g.gain.setValueAtTime(0.0001, t);
    g.gain.exponentialRampToValueAtTime(peak, t + attack);
    g.gain.exponentialRampToValueAtTime(0.0001, t + dur);
    node.connect(g); g.connect(out);
  };
  const tone = (t, freq, peak, dur, type = 'sine') => {
    const o = ctx.createOscillator(); o.type = type; o.frequency.value = freq;
    env(o, t, peak, 0.004, dur);
    o.start(t); o.stop(t + dur + 0.05);
  };
  if (kind === 'lock') {
    // Bell partials on G6, a touch of shimmer above, and a warm G5 underneath.
    tone(t0, 1568, 0.55, 1.1);
    tone(t0, 3136, 0.16, 0.55);
    tone(t0, 4704, 0.05, 0.3);
    tone(t0, 784, 0.18, 0.7);
    tone(t0 + 0.004, 1572, 0.12, 0.9); // slight detune for a natural ring
  } else {
    const len = Math.floor(ctx.sampleRate * 0.05);
    const buf = ctx.createBuffer(1, len, ctx.sampleRate);
    const d = buf.getChannelData(0);
    for (let i = 0; i < len; i++) d[i] = Math.random() * 2 - 1;
    const click = (t, freq, q, peak, dur) => {
      const src = ctx.createBufferSource(); src.buffer = buf;
      const f = ctx.createBiquadFilter(); f.type = 'bandpass'; f.frequency.value = freq; f.Q.value = q;
      src.connect(f); env(f, t, peak, 0.001, dur);
      src.start(t); src.stop(t + dur + 0.02);
    };
    click(t0, 3800, 3.5, 1.8, 0.022);
    click(t0, 1600, 2, 0.7, 0.03);
    tone(t0, 260, 0.4, 0.04, 'triangle');
  }
}

function playSound(kind, delay = 0) {
  if (!soundOn() || !audioCtx) return;
  try {
    const out = audioCtx.createGain();
    out.gain.value = 0.42;
    out.connect(audioCtx.destination);
    lockSynth(audioCtx, out, kind, audioCtx.currentTime + delay);
  } catch { /* sound is a nicety; never let it break anything */ }
}

/** Play the lock or unlock moment: the animation, with the sound timed to the snap. */
function playLockMoment(el, kind) {
  el.classList.remove('is-in');
  requestAnimationFrame(() => requestAnimationFrame(() => {
    el.classList.add('is-in');
    if (!matchMedia('(prefers-reduced-motion: reduce)').matches) playSound(kind, kind === 'lock' ? 0.62 : 0.22); // the bing lands on the ball's impact; the click on its release
    else playSound(kind, 0);
  }));
}

/** Put a button into a busy state with a spinner, and restore it afterwards. */
function setBusy(btn, label) {
  if (label) {
    btn.dataset.idle = btn.innerHTML;
    btn.classList.add('is-busy');
    btn.disabled = true;
    btn.innerHTML = `<span class="spin" aria-hidden="true"></span>${escapeHtml(label)}`;
  } else if (btn.dataset.idle !== undefined) {
    btn.innerHTML = btn.dataset.idle;
    delete btn.dataset.idle;
    btn.classList.remove('is-busy');
  }
}

/**
 * Password stretching keeps the page busy for a moment. Show a moving bar first
 * and let the browser paint it before the work starts; the bar is animated on
 * the compositor, so it keeps moving while the work runs.
 */
async function startBusy(el) {
  show(el, true);
  await new Promise((resolve) => requestAnimationFrame(() => setTimeout(resolve, 40)));
}

/** Bumped whenever a flow is reset, so slow work that finishes late is ignored. One per flow. */
const gen = { backup: 0, restore: 0 };

// ---------------------------------------------------------------------------
// Belt and braces: the page's security policy blocks network requests, but it
// does not cover peer-to-peer connections, so remove those from this page.
// ---------------------------------------------------------------------------

for (const name of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel', 'RTCSessionDescription']) {
  try { Object.defineProperty(window, name, { value: undefined, writable: false, configurable: false }); } catch { /* already gone */ }
}

// ---------------------------------------------------------------------------
// Top bar: connection status and scroll edge
// ---------------------------------------------------------------------------

function renderConnection() {
  const el = $('#connection');
  const online = navigator.onLine;
  el.dataset.state = online ? 'online' : 'offline';
  el.querySelector('.connection-text').textContent = online ? 'Online' : 'Offline';
  el.title = online
    ? 'BRC Vault never sends anything. For extra safety you can turn off Wi‑Fi before loading a key.'
    : 'You are offline. Nothing can leave this page.';
}
window.addEventListener('online', renderConnection);
window.addEventListener('offline', renderConnection);
window.addEventListener('scroll', () => $('#topbar').classList.toggle('is-scrolled', window.scrollY > 8), { passive: true });

// ---------------------------------------------------------------------------
// Tabs (segmented control)
// ---------------------------------------------------------------------------

function selectTab(name) {
  if (name !== 'restore') {
    if (intakes.r && intakes.r.mode() === 'scan') intakes.r.setMode('file');
    stopScan();
    if ($('#r-words-wrap')) closeRestoreWords();
  }
  $('#segmented').dataset.active = name;
  $$('[role="tab"]').forEach((t) => {
    const on = t.dataset.tab === name;
    t.setAttribute('aria-selected', String(on));
    t.tabIndex = on ? 0 : -1;
  });
  $$('[role="tabpanel"]').forEach((p) => show(p, p.id === `panel-${name}`));
}

$$('[role="tab"]').forEach((t) => {
  t.addEventListener('click', () => selectTab(t.dataset.tab));
  t.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const tabs = $$('[role="tab"]');
    const next = tabs[(tabs.indexOf(t) + 1) % tabs.length];
    selectTab(next.dataset.tab);
    next.focus();
  });
});

// Show / hide password buttons
$$('[data-reveal]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const ids = btn.dataset.reveal.split(' ');
    const reveal = $(`#${ids[0]}`).type === 'password';
    ids.forEach((id) => { $(`#${id}`).type = reveal ? 'text' : 'password'; });
    btn.textContent = reveal ? 'Hide' : 'Show';
    btn.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
  });
});

/** Rough strength, 0–4, for the meter only. Length matters most. */
function strength(pw) {
  if (!pw) return 0;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  const words = pw.trim().split(/\s+/).length;
  if (pw.length < core.MIN_PASSWORD_LENGTH) return 1;
  if (pw.length >= 20 || (words >= 4 && pw.length >= 16)) return 4;
  if (pw.length >= 16 || classes >= 3) return 3;
  return 2;
}

// ---------------------------------------------------------------------------
// Camera scanner for paper backups. Frames are read in this tab only; nothing
// is recorded or sent anywhere, and the camera is switched off the moment a
// code is read, the scanner is closed, or the tab is hidden.
// ---------------------------------------------------------------------------

const scanner = { stream: null, raf: 0, onCode: null, canvas: null, token: 0 };

/** Codes the scanner accepts. Anything else is named and ignored, and scanning carries on. */
function scanProblem(text) {
  const t = String(text).trim();
  if (/^(BRCVAULT1|BRCKEY1)[:\s]/i.test(t)) return null;
  if (/^(0x)?[0-9a-fA-F]{64}$/.test(t)) return "That's the wallet address QR code, which can't restore anything. Hold up the larger locked backup QR code instead.";
  return "That QR code isn't from a BRC Vault paper backup. Hold up the locked backup QR code.";
}

function stopScan() {
  scanner.token++; // anything still starting up sees this and shuts itself down
  cancelAnimationFrame(scanner.raf);
  scanner.raf = 0;
  if (scanner.stream) scanner.stream.getTracks().forEach((t) => t.stop());
  scanner.stream = null;
  const video = $('#r-scan-video');
  if (video) { video.pause(); video.srcObject = null; }
}

function setScanState(state, text) {
  $('#r-scan-panel .scan-view').dataset.state = state;
  if (text) $('#r-scan-overlay-text').textContent = text;
}

async function startScan(onCode, hintEl) {
  stopScan();
  const my = scanner.token;
  const wanted = () => my === scanner.token && !document.hidden && intakes.r?.mode() === 'scan';
  scanner.onCode = onCode;
  setMessage(hintEl, 'Starting the camera…', 'info');
  setScanState('starting', 'Starting the camera…');
  const problem = (text) => { setScanState('problem', text); setMessage(hintEl, ''); };
  let framed = false;
  try { framed = window.self !== window.top; } catch { framed = true; }
  if (!navigator.mediaDevices?.getUserMedia) {
    problem(framed
      ? "The camera can't be used inside this preview. Save brc-vault.html and open it directly in Chrome or Safari."
      : "This browser can't use a camera here. Type the code instead.");
    return;
  }
  // If the browser is waiting on a permission prompt, say where to look.
  const slow = setTimeout(() => {
    if (my === scanner.token && !scanner.stream) setScanState('starting', 'Waiting for camera access. Look for a prompt near the address bar and choose Allow.');
  }, 2500);
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } },
      audio: false,
    });
  } catch (e) {
    clearTimeout(slow);
    if (my !== scanner.token) return; // the scanner was closed meanwhile
    const blocked = e && (e.name === 'NotAllowedError' || e.name === 'SecurityError');
    if (framed) problem("The camera can't be used inside this preview. Save brc-vault.html and open it directly in Chrome or Safari, then allow camera access.");
    else if (blocked) problem('Camera access is blocked for this page. Allow the camera in your browser settings, then try again, or type the code instead.');
    else problem('No camera was found on this device. Type the code instead.');
    return;
  }
  clearTimeout(slow);
  // Closed, hidden or restarted while waiting for permission: switch it straight off.
  if (!wanted()) { stream.getTracks().forEach((t) => t.stop()); return; }
  scanner.stream = stream;
  const video = $('#r-scan-video');
  video.srcObject = stream;
  try { await video.play(); } catch { /* autoplay with a live stream normally succeeds after a click */ }
  if (!wanted()) { if (my === scanner.token) stopScan(); return; }
  setScanState('live');
  setMessage(hintEl, 'Hold the locked backup QR code up to the camera.', 'info');
  let lastProblem = '';
  scanner.canvas = scanner.canvas || document.createElement('canvas');
  const ctx = scanner.canvas.getContext('2d', { willReadFrequently: true });
  let last = 0;
  const tick = (now) => {
    if (my !== scanner.token || !scanner.stream) return;
    scanner.raf = requestAnimationFrame(tick);
    if (now - last < 120 || video.readyState < 2 || !video.videoWidth) return;
    last = now;
    const scale = Math.min(1, 1280 / Math.max(video.videoWidth, video.videoHeight));
    const w = Math.round(video.videoWidth * scale);
    const h = Math.round(video.videoHeight * scale);
    scanner.canvas.width = w;
    scanner.canvas.height = h;
    ctx.drawImage(video, 0, 0, w, h);
    const found = jsQR(ctx.getImageData(0, 0, w, h).data, w, h, { inversionAttempts: 'attemptBoth' });
    if (found && found.data) {
      const problem = scanProblem(found.data);
      if (problem) {
        if (problem !== lastProblem) { lastProblem = problem; setMessage(hintEl, problem, 'warn'); }
        return;
      }
      stopScan();
      ctx.clearRect(0, 0, w, h);
      scanner.onCode(found.data);
    }
  };
  scanner.raf = requestAnimationFrame(tick);
}

$('#r-scan-to-type').addEventListener('click', () => { intakes.r.setMode('paste'); });

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) return;
  if (intakes.r && intakes.r.mode() === 'scan') intakes.r.setMode('file');
  stopScan();
});

// ---------------------------------------------------------------------------
// Back up
// ---------------------------------------------------------------------------

const backup = { wallet: null, result: null, kind: null, busy: false };

function resetBackupOutput() {
  backup.result = null;
  delete $('#b-step1').dataset.collapsed;
  delete $('#b-step2').dataset.collapsed;
  $('#b-step2 .step-sub').hidden = false;
  const done = $('#b-done');
  done.classList.remove('is-in');
  show(done, false);
  show($('#b-make').parentElement, true);
  setMessage($('#b-make-msg'), '');
  setMessage($('#b-saved-msg'), '');
}

/** A bare 64-character key needs a confirmation, because an address looks identical. */
function backupKeyConfirmed() {
  return !backup.confirm || $('#b-key-confirm').checked;
}

function loadWalletForBackup(text, source) {
  const msg = $('#b-load-msg');
  gen.backup++;
  core.wipeWallet(backup.wallet);
  backup.wallet = null;
  resetBackupOutput();
  $('#b-key-confirm').checked = false;
  try {
    const id = core.identifyInput(text);
    if (id.kind === 'vault-backup') throw new Error('That is already a BRC Vault backup. To open it, switch to Restore.');
    if (id.kind === 'desktop-backup') throw new Error('That file is password-protected by the BRC Wallet desktop app. Open it in Restore first; once it is unlocked you can back it up here.');
    backup.wallet = id.wallet;
    $('#b-check').textContent = 'The key matches this address';
    backup.kind = id.kind === 'private-key' ? (id.words ? 'words' : id.ambiguous ? 'ambiguous-key' : 'key') : 'file';
    // A bare key, an old key code with no check, or recovery words: ask the
    // person to compare the address before anything is locked.
    backup.confirm = Boolean(id.ambiguous || id.checked === false);
    $('#b-key-confirm-text').innerHTML = backup.kind === 'words'
      ? 'The address above is the one my wallet app shows. <strong>A mistyped or out-of-order word</strong> can, rarely, make a different, empty wallet.'
      : 'I pasted my <strong>private key</strong>, not my wallet address, and the address above is the one BrowserCoin shows for my wallet.';
    renderAddress($('#b-address'), id.wallet.address);
    show($('#b-loaded'), true);
    show($('#b-key-confirm-wrap'), backup.confirm);
    if (backup.kind === 'ambiguous-key') {
      setMessage(msg, 'Check the address below before going on. A wallet address looks exactly like a private key, and backing up an address protects nothing.', 'warn');
    } else if (backup.confirm) {
      setMessage(msg, 'Check the address below against the one your wallet shows before going on.', 'warn');
    } else if (id.rescued) {
      setMessage(msg, 'This file had been changed by another app, such as a text editor. BRC Vault recovered the key and confirmed it matches the address.', 'info');
    } else {
      setMessage(msg, '');
    }
    $('#b-tip-delete').textContent = {
      file: 'Your unlocked wallet file is still in your Downloads folder. Delete it once your backup is safe.',
      words: 'If you typed or pasted your recovery words anywhere else, delete them there once your backup is safe.',
    }[backup.kind] || 'Remove the private key from wherever you copied it once your backup is safe.';
    intakes.b.setMode('loaded', backup.kind === 'file' ? (source || 'Wallet file') : backup.kind === 'words' ? 'Recovery words' : (source || 'Pasted private key'));
  } catch (e) {
    backup.wallet = null;
    backup.kind = null;
    backup.confirm = false;
    show($('#b-loaded'), false);
    if (intakes.b.mode() === 'loaded') intakes.b.setMode('file');
    setMessage(msg, e.message, 'bad');
  }
  updatePasswordState();
  if (backup.wallet && backupKeyConfirmed()) $('#b-password').focus();
}

// A fresh wallet, made here, that goes straight into a locked backup. Its key
// is never shown or saved unlocked: the backup is the only copy.
function makeNewWalletForBackup() {
  if (backup.busy || backup.result) return;
  gen.backup++;
  core.wipeWallet(backup.wallet);
  resetBackupOutput();
  $('#b-key-confirm').checked = false;
  backup.wallet = core.newWallet();
  backup.kind = 'new';
  backup.confirm = false;
  renderAddress($('#b-address'), backup.wallet.address);
  $('#b-check').textContent = 'Made just now on this page. It holds no coins yet.';
  show($('#b-loaded'), true);
  show($('#b-key-confirm-wrap'), false);
  setMessage($('#b-load-msg'), 'This wallet exists only on this page until you lock it. Finish the backup before you close the tab.', 'info');
  $('#b-tip-delete').textContent = 'Nothing else holds this wallet\'s key. Without the backup and its password, the wallet and anything sent to it are gone.';
  intakes.b.setMode('loaded', 'New wallet');
  updatePasswordState();
  $('#b-password').focus();
}
$('#b-new').addEventListener('click', makeNewWalletForBackup);

wireIntake('b', loadWalletForBackup, $('#b-load-msg'), () => !backup.busy && !backup.result);
$('#b-key-confirm').addEventListener('change', () => { updatePasswordState(); if ($('#b-key-confirm').checked) $('#b-password').focus(); });

function updatePasswordState() {
  const pw = $('#b-password').value;
  const confirm = $('#b-confirm').value;
  const problems = core.passwordProblems(pw, confirm);
  const hint = $('#b-pw-hint');
  const level = strength(pw);
  $('#b-meter').dataset.level = String(level);
  const meterLabel = $('#b-meter-label');
  meterLabel.dataset.level = String(level);
  meterLabel.textContent = ['', 'Too weak', 'Fair', 'Good', 'Strong'][level];
  if (!pw && !confirm) setMessage(hint, `At least ${core.MIN_PASSWORD_LENGTH} characters. A short sentence you'll remember works well.`, 'info');
  else if (problems.length) setMessage(hint, problems[0], pw.length >= core.MIN_PASSWORD_LENGTH ? 'warn' : 'info');
  else setMessage(hint, 'Passwords match.', 'good');

  const loaded = Boolean(backup.wallet) && backupKeyConfirmed();
  const ready = loaded && problems.length === 0 && $('#b-understand').checked;
  if (!backup.result) {
    setStep('#b-step1', loaded ? 'done' : 'active');
    setStep('#b-step2', !loaded ? 'waiting' : ready ? 'done' : 'active');
    setStep('#b-step3', ready ? 'active' : 'waiting');
  }
  $('#b-make').disabled = !ready || backup.busy;
}

['#b-password', '#b-confirm'].forEach((s) => $(s).addEventListener('input', () => { resetBackupOutput(); updatePasswordState(); }));
$('#b-understand').addEventListener('change', updatePasswordState);
$('#b-confirm').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !$('#b-make').disabled) $('#b-make').click(); });

$('#b-make').addEventListener('click', async () => {
  primeAudio();
  const btn = $('#b-make');
  const msg = $('#b-make-msg');
  const myGen = gen.backup;
  const wallet = backup.wallet;
  backup.busy = true;
  btn.disabled = true;
  setBusy(btn, 'Locking…');
  setMessage(msg, 'This takes a few seconds on purpose. It makes password guessing slow.', 'info');
  await startBusy($('#b-progress'));
  try {
    const password = $('#b-password').value;
    const result = await core.encryptWallet(wallet, password);
    // Prove the backup opens before handing it over.
    const check = await core.decryptBackup(result, password);
    core.wipeWallet(check);
    if (myGen !== gen.backup) { setMessage(msg, ''); return; } // cleared, or another wallet loaded meanwhile
    if (check.address !== wallet.address) throw new Error('Self-check failed. No backup was made.');
    backup.result = result;
    $('#b-password').value = '';
    $('#b-confirm').value = '';
    $('#b-meter').dataset.level = '0';
    $('#b-meter-label').textContent = '';
    setMessage($('#b-pw-hint'), '');
    setMessage(msg, '');
    show(btn.parentElement, false);
    setStep('#b-step3', 'done');
    $('#b-sum-address').textContent = core.shortAddress(result.address);
    $('#b-step1').dataset.collapsed = '';
    $('#b-step2').dataset.collapsed = '';
    $('#b-step2 .step-sub').hidden = true;
    renderAddress($('#b-done-address'), result.address);
    show($('#b-new-note'), backup.kind === 'new');
    const done = $('#b-done');
    show(done, true);
    playLockMoment(done, 'lock');
    $('#b-download').focus({ preventScroll: true });
    done.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center' });
  } catch (e) {
    setMessage(msg, myGen === gen.backup ? e.message : '', 'bad');
  } finally {
    backup.busy = false;
    setBusy(btn, null);
    show($('#b-progress'), false);
    if (!backup.result) updatePasswordState();
  }
});

$('#b-download').addEventListener('click', () => {
  const r = backup.result;
  download(`brc-vault-backup-${r.address.slice(0, 8)}.json`, JSON.stringify(r, null, 2));
  setMessage($('#b-saved-msg'), 'Backup file downloaded. Keep a second copy somewhere else.', 'good');
});

$('#b-print').addEventListener('click', () => openPaperPreview(encryptedSheet(backup.result), 'encrypted'));

$('#b-plain-ok').addEventListener('change', () => { $('#b-print-plain').disabled = !$('#b-plain-ok').checked; });
$('#b-print-plain').addEventListener('click', () => {
  if (!$('#b-plain-ok').checked) return;
  if (!backup.wallet || !backupKeyConfirmed()) {
    setMessage($('#b-load-msg'), 'Load and confirm a wallet in step 1 first.', 'bad');
    $('#b-step1').scrollIntoView({ block: 'center' });
    return;
  }
  openPaperPreview(plainSheet(backup.wallet), 'plain');
});

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

const restore = { pending: null, wallet: null, busy: false, unverified: false, toBackup: false };

function resetRestore() {
  gen.restore++;
  closeRestoreWords();
  restore.unverified = false;
  restore.toBackup = false;
  show($('#r-reprint-row'), false);
  $('#r-success').classList.remove('is-in');
  delete $('#r-step1').dataset.collapsed;
  delete $('#r-step2').dataset.collapsed;
  core.wipeWallet(restore.wallet);
  restore.pending = null;
  restore.wallet = null;
  show($('#r-done'), false);
  show($('#r-loaded'), false);
  setMessage($('#r-unlock-msg'), '');
  $('#r-ok-address').checked = false;
  $('#r-ok-replace').checked = false;
  updateRestoreDownload();
  setStep('#r-step1', 'active');
  setStep('#r-step2', 'waiting');
  setStep('#r-step3', 'waiting');
}

function loadForRestore(text, source) {
  const msg = $('#r-load-msg');
  resetRestore();
  try {
    const id = core.identifyInput(text);
    const pasted = { 'vault-backup': 'Pasted backup code', 'desktop-backup': 'Pasted wallet file' }[id.kind] || (id.words ? 'Recovery words' : 'Pasted key');
    intakes.r.setMode('loaded', source || pasted);
    setStep('#r-step1', 'done');
    show($('#r-loaded'), true);
    if (id.kind === 'vault-backup' || id.kind === 'desktop-backup') {
      restore.pending = id.backup;
      $('#r-address-label').textContent = id.kind === 'vault-backup' ? 'In backup' : 'In wallet file';
      renderAddress($('#r-address'), id.backup.address);
      show($('#r-address-note'), true);
      setMessage(msg, id.kind === 'desktop-backup'
        ? 'This is a password-protected file from the BRC Wallet desktop app. Unlock it with the password you set in that app.'
        : id.rescued ? 'This file had been changed by another app, such as a text editor. BRC Vault recovered the backup from it; unlocking will confirm it.' : '', 'info');
      setStep('#r-step2', 'active');
      $('#r-password').focus();
    } else {
      // An unprotected key or BrowserCoin wallet file has nothing to unlock.
      $('#r-address-label').textContent = 'Address';
      renderAddress($('#r-address'), id.wallet.address);
      show($('#r-address-note'), false);
      setStep('#r-step2', 'done');
      finishRestore(id.wallet, id.ambiguous || id.checked === false, id.words ? 'words' : 'key');
    }
  } catch (e) {
    resetRestore();
    if (intakes.r.mode() === 'loaded' || intakes.r.mode() === 'scan') intakes.r.setMode('file');
    setMessage(msg, e.message, 'bad');
  }
}

wireIntake('r', loadForRestore, $('#r-load-msg'), () => !restore.busy && !restore.wallet);

// A new paper copy of a backup, offered once the password has unlocked it, so
// the address printed on it has been confirmed against the key.
$('#r-reprint').addEventListener('click', () => {
  if (!restore.pending || restore.pending.format || !restore.wallet || restore.wallet.address !== restore.pending.address) return;
  openPaperPreview(encryptedSheet({ ...restore.pending, created: `copy printed ${new Date().toISOString().slice(0, 10)}` }), 'encrypted');
});

$('#r-unlock').addEventListener('click', async () => {
  primeAudio();
  const btn = $('#r-unlock');
  const msg = $('#r-unlock-msg');
  if (!restore.pending || restore.busy) return;
  const myGen = gen.restore;
  const pending = restore.pending;
  restore.busy = true;
  btn.disabled = true;
  setBusy(btn, 'Unlocking…');
  setMessage(msg, '');
  await startBusy($('#r-progress'));
  try {
    const wallet = await core.unlockAny(pending, $('#r-password').value);
    if (myGen !== gen.restore) { core.wipeWallet(wallet); return; }
    $('#r-password').value = '';
    setStep('#r-step2', 'done');
    finishRestore(wallet, false);
  } catch (e) {
    if (myGen === gen.restore) setMessage(msg, e.message, 'bad');
  } finally {
    restore.busy = false;
    btn.disabled = false;
    setBusy(btn, null);
    show($('#r-progress'), false);
  }
});
$('#r-password').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#r-unlock').click(); });

function finishRestore(wallet, ambiguous, from = 'key') {
  restore.wallet = wallet;
  const unlocked = Boolean(restore.pending);
  const desktop = unlocked && restore.pending.format === core.DESKTOP_FORMAT;
  show($('#r-reprint-row'), unlocked && !desktop);
  restore.unverified = Boolean(ambiguous);
  restore.toBackup = !unlocked || desktop;
  $('#r-done-title').textContent = desktop ? 'Wallet file unlocked' : unlocked ? 'Backup unlocked' : 'Wallet ready';
  $('#r-done-check').textContent = desktop ? 'The key matches the address in the wallet file'
    : unlocked ? 'The key matches the address in the backup'
    : from === 'words' ? 'Address worked out from these words' : 'Address worked out from this key';
  $('#r-sum-unlock').textContent = unlocked ? 'Unlocked with your password' : 'No password needed';
  $('#r-step1').dataset.collapsed = '';
  $('#r-step2').dataset.collapsed = '';
  setMessage($('#r-load-msg'), '');
  setMessage($('#r-done-msg'), ambiguous && from === 'words'
    ? 'Check this address against the one your wallet app shows. A mistyped or out-of-order word can, rarely, still pass the words\' built-in check and open a different, empty wallet.'
    : ambiguous
    ? 'Check this address carefully. A typo in a key, or a wallet address entered instead of a key, opens a different, empty wallet with no error. If this isn\'t your address, use your locked backup code or the full BRCKEY1 code from your paper wallet.'
    : '', 'warn');
  renderAddress($('#r-done-address'), wallet.address);
  if (restore.pending) playLockMoment($('#r-success'), 'unlock');
  else $('#r-success').classList.add('is-in');
  setStep('#r-step3', 'active');
  show($('#r-done'), true);
  updateRestoreDownload();
  $('#r-ok-address').focus();
}

// Words, a key or a desktop wallet file can be turned straight into a BRC Vault backup.
$('#r-to-backup').addEventListener('click', () => {
  const w = restore.wallet;
  if (!w || (restore.unverified && !$('#r-ok-address').checked)) return;
  closeRestoreWords();
  selectTab('backup');
  restartBackup();
  loadWalletForBackup(core.browserCoinWalletJson(w), 'Wallet from Restore');
  $('#b-tip-delete').textContent = 'Once your backup is safe, delete any other copies of the words, key or wallet file you restored from.';
});

// The recovery words are only put on screen when asked for, and removed again when closed.
$('#r-words-wrap').addEventListener('toggle', () => {
  const list = $('#r-words');
  list.innerHTML = '';
  if (!$('#r-words-wrap').open || !restore.wallet) return;
  list.innerHTML = core.walletToWords(restore.wallet)
    .map((w, i) => `<li><span class="n">${i + 1}</span>${escapeHtml(w)}</li>`).join('');
});

function closeRestoreWords() {
  $('#r-words-wrap').open = false;
  $('#r-words').innerHTML = '';
}

function updateRestoreDownload() {
  $('#r-download').disabled = !(restore.wallet && $('#r-ok-address').checked && $('#r-ok-replace').checked);
  // Until an unchecked address has been confirmed, don't offer to back it up
  // or show its words: they might belong to the wrong wallet.
  const confirmed = Boolean(restore.wallet) && (!restore.unverified || $('#r-ok-address').checked);
  show($('#r-to-backup-row'), confirmed && Boolean(restore.toBackup));
  show($('#r-words-wrap'), confirmed);
  if (!confirmed) closeRestoreWords();
}
['#r-ok-address', '#r-ok-replace'].forEach((s) => $(s).addEventListener('change', updateRestoreDownload));

$('#r-download').addEventListener('click', () => {
  const w = restore.wallet;
  if (!w || $('#r-download').disabled) return;
  download(core.browserCoinWalletFilename(w), core.browserCoinWalletJson(w));
  toast('Wallet file saved to your Downloads');
  setStep('#r-step3', 'done');
});

// ---------------------------------------------------------------------------
// Paper sheets
// ---------------------------------------------------------------------------

// The logo is defined once in the page; the paper sheets reuse it.
/** A 64-character value printed as two even lines of four groups. */
const twoLines = (hex) => `${escapeHtml(core.chunkForPaper(hex.slice(0, 32), 8))}<br>${escapeHtml(core.chunkForPaper(hex.slice(32), 8))}`;

const LOGO = () => `${$('.brand .mark').outerHTML}<span class="wordmark"><span class="wm-light">BRC</span><span class="wm-bold">Vault</span></span>`;

function sheetHead(kind, sub) {
  return `<header class="ps-head"><div class="ps-brand" aria-label="BRC Vault">${LOGO()}</div><div class="ps-kind"><strong>${escapeHtml(kind)}</strong>${escapeHtml(sub)}</div></header>`;
}

function sheetFoot(created, withPassword = true) {
  const pw = withPassword ? '<div>Password kept by<span class="ps-line"></span></div>' : '<div></div>';
  return `<footer class="ps-foot"><div>Made ${escapeHtml(created)}</div><div>Stored at<span class="ps-line"></span></div>${pw}</footer>`;
}

function encryptedSheet(result) {
  const code = core.backupToCompact(result);
  const lines = core.paperCodeLines(code)
    .map((l) => `<span class="ps-codeline">${escapeHtml(l.text)} <span class="ps-check">[${escapeHtml(l.check)}]</span></span>`)
    .join('<br>');
  return `
    ${sheetHead('Paper backup', 'Password-protected BrowserCoin wallet')}
    <section class="ps-panel">
      <div class="ps-qr">${qrSvg(result.address, { label: 'Wallet address QR code' })}</div>
      <div>
        <div class="ps-label">Safe to share</div>
        <h2>Wallet address</h2>
        <p class="ps-note">Use it to receive coins or look up the balance. This is not a key and can't restore the wallet.</p>
        <p class="ps-mono">${twoLines(result.address)}</p>
      </div>
    </section>
    <section class="ps-panel is-key">
      <div class="ps-qr">${qrSvg(core.qrPayload(code), { mode: 'Alphanumeric', ecc: 'M', label: 'Locked backup QR code' })}</div>
      <div>
        <div class="ps-label">Keep private</div>
        <h2>Locked backup code</h2>
        <p class="ps-note">Useless without your password. Scan it with BRC Vault, or type each line with its check in brackets. Phone camera apps can't read it, on purpose.</p>
        <p class="ps-mono sheet-code">${lines}</p>
      </div>
    </section>
    <section class="ps-steps">
      <div>
        <h3>To get your coins back</h3>
        <ol>
          <li>Open BRC Vault and choose Restore.</li>
          <li>Choose Scan paper backup and hold this sheet up to the camera, or type the code exactly as printed.</li>
          <li>Enter your password and download the wallet file.</li>
          <li>At browsercoin.org/app, open Settings and choose Import key…</li>
        </ol>
      </div>
      <div>
        <h3>About the password</h3>
        <p class="ps-warn">It is not on this page and cannot be recovered. If it is forgotten, these coins are gone. Store it separately from this sheet.</p>
      </div>
    </section>
    ${sheetFoot(result.created)}`;
}

function plainSheet(wallet) {
  const keyCode = core.keyToCode(wallet);
  const keyLines = core.keyCodeLines(keyCode)
    .map((l) => `<span class="ps-codeline">${escapeHtml(l.text)} <span class="ps-check">[${escapeHtml(l.check)}]</span></span>`)
    .join('<br>');
  return `
    ${sheetHead('Paper wallet', 'Not password-protected')}
    <p class="ps-alarm">Anyone who sees or photographs this page can take every coin in this wallet.</p>
    <section class="ps-panel">
      <div class="ps-qr">${qrSvg(wallet.address, { label: 'Wallet address QR code' })}</div>
      <div>
        <div class="ps-label">Safe to share</div>
        <h2>Wallet address</h2>
        <p class="ps-note">Use it to receive coins. This is not a key and can't restore the wallet.</p>
        <p class="ps-mono">${twoLines(wallet.address)}</p>
      </div>
    </section>
    <section class="ps-panel is-key">
      <div class="ps-qr">${qrSvg(core.qrPayload(keyCode), { mode: 'Alphanumeric', ecc: 'M', label: 'Private key QR code' })}</div>
      <div>
        <div class="ps-label">Never share</div>
        <h2>Private key</h2>
        <p class="ps-note">This is the wallet itself. Type every line with its check in brackets; the last line checks the key against the address.</p>
        <p class="ps-mono sheet-code">${keyLines}</p>
      </div>
    </section>
    <section class="ps-panel ps-words is-key">
      <div class="ps-label">Never share</div>
      <h2>24 recovery words</h2>
      <p class="ps-note">The same wallet as standard recovery words. They restore in BRC Vault and in the BRC Wallet Android app.</p>
      <ol class="ps-wordgrid">${core.walletToWords(wallet).map((w, i) => `<li><span class="n">${i + 1}</span>${escapeHtml(w)}</li>`).join('')}</ol>
    </section>
    <section class="ps-steps">
      <div>
        <h3>To get your coins back</h3>
        <ol>
          <li>Open BRC Vault and choose Restore.</li>
          <li>Choose Scan paper backup and hold this sheet up to the camera. Or type every line of the private key code, with BRCKEY1: and the checks in brackets, or the 24 recovery words.</li>
          <li>Download the wallet file. At browsercoin.org/app, open Settings and choose Import key…</li>
        </ol>
        <p class="ps-warn">In the BRC Wallet Android app, import the 24 recovery words instead.</p>
      </div>
    </section>
    ${sheetFoot(new Date().toISOString().slice(0, 10), false)}`;
}

// The sheet opens as an on-screen preview with its own Print button. If the
// browser never starts printing (some app previews block it), say so plainly.
let previewReturnFocus = null;
let printWatch = null;

function openPaperPreview(html, kind) {
  const sheet = $('#print-sheet');
  sheet.innerHTML = html;
  $('#pp-title').textContent = kind === 'plain' ? 'Unprotected paper wallet preview' : 'Paper backup preview';
  setMessage($('#pp-hint'), 'Check it looks right, then print.', 'info');
  previewReturnFocus = document.activeElement;
  document.body.classList.add('is-previewing');
  show($('#paper-preview'), true);
  $('.pp-scroll').scrollTop = 0;
  $('#pp-print').focus();
}

function closePaperPreview() {
  clearTimeout(printWatch);
  show($('#paper-preview'), false);
  document.body.classList.remove('is-previewing');
  $('#print-sheet').innerHTML = '';
  if (previewReturnFocus && document.contains(previewReturnFocus)) previewReturnFocus.focus();
  previewReturnFocus = null;
}

let printStarted = false;
window.addEventListener('beforeprint', () => { printStarted = true; });

$('#pp-print').addEventListener('click', () => {
  printStarted = false;
  clearTimeout(printWatch);
  try { window.print(); } catch { /* reported below */ }
  printWatch = setTimeout(() => {
    if (printStarted) {
      setMessage($('#pp-hint'), 'Printed? Close this preview when you\'re done.', 'info');
    } else {
      const key = IS_MAC ? '⌘P' : 'Ctrl+P';
      setMessage($('#pp-hint'), `The print window didn't open. Press ${key} to print this sheet. If that doesn't work either, open brc-vault.html directly in your browser, not in an app's preview.`, 'warn');
    }
  }, 1500);
});
$('#pp-close').addEventListener('click', closePaperPreview);
document.addEventListener('keydown', (e) => {
  if ($('#paper-preview').hidden) return;
  if (e.key === 'Escape') { e.preventDefault(); closePaperPreview(); return; }
  if (e.key !== 'Tab') return;
  // Keep keyboard focus inside the preview while it is open.
  const items = [$('#pp-close'), $('#pp-print')];
  const i = items.indexOf(document.activeElement);
  if (i === -1) { e.preventDefault(); items[e.shiftKey ? items.length - 1 : 0].focus(); return; }
  if (e.shiftKey && i <= 0) { e.preventDefault(); items[items.length - 1].focus(); }
  else if (!e.shiftKey && i === items.length - 1) { e.preventDefault(); items[0].focus(); }
});

// ---------------------------------------------------------------------------
// Start a step over: load a different wallet or backup after finishing one.
// ---------------------------------------------------------------------------

function restartBackup() {
  gen.backup++;
  core.wipeWallet(backup.wallet);
  backup.wallet = null;
  backup.result = null;
  backup.kind = null;
  backup.confirm = false;
  ['#b-password', '#b-confirm'].forEach((s) => { $(s).value = ''; });
  $('#b-understand').checked = false;
  $('#b-key-confirm').checked = false;
  show($('#b-loaded'), false);
  show($('#b-key-confirm-wrap'), false);
  resetBackupOutput();
  intakes.b.setMode('file');
  setMessage($('#b-load-msg'), '');
  updatePasswordState();
  setMessage($('#b-pw-hint'), '');
  $('#b-meter-label').textContent = '';
  $('#b-step1').scrollIntoView({ block: 'nearest' });
  $('#b-paste-open').focus({ preventScroll: true });
}

function restartRestore() {
  resetRestore();
  intakes.r.setMode('file');
  setMessage($('#r-load-msg'), '');
  $('#r-password').value = '';
  $('#r-step1').scrollIntoView({ block: 'nearest' });
  $('#r-paste-open').focus({ preventScroll: true });
}

$$('[data-restart]').forEach((btn) => btn.addEventListener('click', () => {
  if (btn.dataset.restart === 'b') restartBackup(); else restartRestore();
}));

// ---------------------------------------------------------------------------
// Clear everything
// ---------------------------------------------------------------------------

$('#clear-all').addEventListener('click', () => {
  gen.backup++;
  stopScan();
  core.wipeWallet(backup.wallet);
  backup.wallet = null;
  backup.result = null;
  backup.kind = null;
  backup.confirm = false;
  $$('input[type="password"], input[type="text"], textarea').forEach((i) => { i.value = ''; });
  $$('input[type="checkbox"]').forEach((c) => { c.checked = false; });
  $$('[data-reveal]').forEach((b) => {
    b.dataset.reveal.split(' ').forEach((id) => { $(`#${id}`).type = 'password'; });
    b.textContent = 'Show';
    b.setAttribute('aria-label', 'Show password');
  });
  $$('.msg').forEach((m) => setMessage(m, ''));
  show($('#b-loaded'), false);
  resetBackupOutput();
  $('#b-print-plain').disabled = true;
  resetRestore();
  if (!$('#paper-preview').hidden) closePaperPreview();
  updatePasswordState();
  setMessage($('#b-pw-hint'), '');
  intakes.b.setMode('file');
  intakes.r.setMode('file');
  $('#b-meter-label').textContent = '';
  toast('Page cleared. Close this tab when you\'re done.');
});

// Some apps show HTML files in a locked-down preview frame that blocks printing and downloads.
try { if (window.self !== window.top) show($('#frame-warning'), true); } catch { show($('#frame-warning'), true); }

$$('.kbd-mod').forEach((k) => { k.textContent = IS_MAC ? '⌘' : 'Ctrl'; });

renderSoundToggle();
renderConnection();
selectTab('backup');
updatePasswordState();
setMessage($('#b-pw-hint'), '');
