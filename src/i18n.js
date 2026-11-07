// BRC Works language switch: English / 简体中文.
//
// Presentation only. It swaps the words this page shows for their Chinese versions and back.
// It never touches what you type or paste, and never touches keys, addresses, codes, signed
// messages, letters, file contents, or anything the page saves, copies, signs or sends:
//   - form fields (input, textarea, select values) are never changed;
//   - code-like text (code, pre, kbd, samp, .mono, .addr) and anything marked translate="no" is skipped;
//   - only text that exactly matches a known English phrase is changed. Anything else stays as it is.
// The choice is remembered on this device only (localStorage), like the page's other settings.
//
// Shared by BRC Vault, BRC Post and BRC Pulse. Same file in each repository.

const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT', 'SELECT', 'CODE', 'PRE', 'KBD', 'SAMP', 'NOSCRIPT', 'TEMPLATE']);
const INLINE = new Set(['BUTTON', 'A', 'B', 'STRONG', 'EM', 'I', 'SPAN', 'CODE', 'KBD', 'BR', 'SMALL', 'ABBR', 'MARK', 'U', 'S', 'SUB', 'SUP', 'TIME', 'Q', 'CITE', 'DFN', 'VAR', 'SAMP', 'WBR', 'BDI', 'BDO']);
const ATTRS = ['placeholder', 'title', 'aria-label', 'alt', 'data-tip'];
const SKIP_CLASS = /(^|\s)(mono|ps-mono|addr|no-i18n|message-box|signed-box|unsigned-box|signed-msg|words|ps-wordgrid|ps-codeline|ps-check|wordmark)(\s|$)/;
const LETTER = /[A-Za-z]/;
const KEY = 'brcworks:lang';

const norm = (s) => s.replace(/\s+/g, ' ').trim();

export function createI18n({ dict } = {}) {
  // Test runs only: a page test may set window.__brcI18nCollect to list phrases that have no
  // translation yet. Nothing on the live page sets it.
  const C = typeof window !== 'undefined' && typeof window.__brcI18nCollect === 'function' ? window.__brcI18nCollect : null;
  const T = new Map(Object.entries(dict.t || {}));      // English -> Chinese, exact phrases
  const R = new Map();                                   // Chinese -> English (to undo text the page itself copied around)
  for (const [en, zh] of T) if (!R.has(zh)) R.set(zh, en);
  // Phrases with numbers or names in them: "Block #%1 found" -> "已找到区块 #%1".
  const P = (dict.p || []).map(([src, zh]) => {
    // %1 stands for any text; %N1 for a number (12, 1,280, 0.5).
    const parts = src.split(/(%N?\d)/);
    let re = '^', lit = '';
    const order = [];
    for (const part of parts) {
      const m = /^%(N?\d)$/.exec(part);
      if (m) { re += m[1][0] === 'N' ? '(-?\\d[\\d,.]*)' : '([\\s\\S]*?)'; order.push(m[1]); } else { re += part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); if (part.length > lit.length) lit = part; }
    }
    return { re: new RegExp(re + '$'), zh, order, lit };
  });

  let lang = 'en';
  const orig = new WeakMap();      // text node / element -> its English, as the page wrote it
  const mine = new WeakMap();      // text node -> the Chinese we wrote (so a later change by the page is noticed)
  const tplKids = new WeakMap();   // element -> its original child nodes, when translated as a whole sentence
  const tplMade = new WeakMap();   // element -> the child nodes we put in
  const attrOrig = new WeakMap();  // element -> {attr: English}
  let observer = null, busy = false;

  function lookup(s, depth = 0) {
    const k = norm(s);
    if (!k || !LETTER.test(k)) return null;
    const hit = T.get(k);
    if (hit !== undefined) return hit;
    const r = match(k, depth);
    if (r == null && C && depth === 0) C(k);
    return r;
  }
  function match(k, depth) {
    if (depth > 2) return null;
    for (const p of P) {
      if (p.lit && !k.includes(p.lit)) continue;
      const m = p.re.exec(k);
      if (!m) continue;
      return p.zh.replace(/%(N?\d)/g, (_, n) => {
        const v = m[p.order.indexOf(n) + 1] ?? '';
        return lookup(v, depth + 1) ?? v;
      });
    }
    return null;
  }
  const back = (s) => R.get(norm(s)) ?? null;

  function skipped(el) {
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
      if (SKIP_TAGS.has(e.tagName)) return true;
      if (e.getAttribute('translate') === 'no' || e.isContentEditable) return true;
      const c = e.getAttribute('class');
      if (c && SKIP_CLASS.test(c)) return true;
    }
    return false;
  }

  function setText(node, value) {
    const lead = /^\s*/.exec(node.data)[0], trail = /\s*$/.exec(node.data)[0];
    node.data = lead + value + trail;
  }

  function doText(node) {
    const cur = node.data;
    if (lang === 'zh') {
      if (mine.get(node) === cur) return;
      const zh = lookup(cur);
      if (zh == null) return;
      orig.set(node, cur);
      setText(node, zh);
      mine.set(node, node.data);
    } else {
      if (C) lookup(cur);
      if (mine.get(node) === cur && orig.has(node)) { node.data = orig.get(node); mine.delete(node); return; }
      const en = back(cur);
      if (en != null) setText(node, en);
    }
  }

  // A sentence with links or bold words in it: "Open <b>Settings</b> first" is one phrase,
  // "Open {0} first", so the words can move around the bold part in Chinese. The bold part
  // itself is the same element, moved, never rebuilt.
  function sentence(el) {
    let text = false;
    const kids = [];
    for (const n of el.childNodes) {
      if (n.nodeType === 3) { if (LETTER.test(n.data)) text = true; }
      else if (n.nodeType === 1) {
        if (!INLINE.has(n.tagName)) return null;
        if (n.tagName !== 'BR' && !norm(n.textContent)) continue;
        kids.push(n);
      }
    }
    if (!text || !kids.length) return null;
    let key = '';
    for (const n of el.childNodes) {
      if (n.nodeType === 3) key += n.data;
      else if (n.nodeType === 1 && kids.includes(n)) key += `{${kids.indexOf(n)}}`;
    }
    return { key: norm(key), kids };
  }

  function doSentence(el) {
    const made = tplMade.get(el);
    if (made) {
      const same = made.length === el.childNodes.length && made.every((n, i) => n === el.childNodes[i]);
      if (!same) { tplMade.delete(el); tplKids.delete(el); }
      else if (lang === 'zh') return true;
      else { el.replaceChildren(...tplKids.get(el)); tplMade.delete(el); tplKids.delete(el); return false; }
    }
    if (lang !== 'zh') { if (C) { const c = sentence(el); if (c) { lookup(c.key); return true; } } return false; }
    const s = sentence(el);
    if (!s) return false;
    const zh = lookup(s.key);
    if (zh == null) return false;
    const before = [...el.childNodes];
    const out = [];
    for (const part of zh.split(/(\{\d+\})/)) {
      const m = /^\{(\d+)\}$/.exec(part);
      if (m && s.kids[+m[1]]) out.push(s.kids[+m[1]]);
      else if (part) out.push(document.createTextNode(part));
    }
    for (const k of s.kids) if (!out.includes(k)) out.push(k); // never lose a part of the page
    for (const n of before) if (n.nodeType === 1 && !s.kids.includes(n)) out.push(n);
    el.replaceChildren(...out);
    tplKids.set(el, before);
    tplMade.set(el, out);
    return true;
  }

  function doAttrs(el) {
    for (const a of ATTRS) {
      if (!el.hasAttribute(a)) continue;
      const v = el.getAttribute(a);
      let store = attrOrig.get(el);
      if (lang === 'zh') {
        if (store && store[a] && store[a].zh === v) continue;
        const zh = lookup(v);
        if (zh == null) continue;
        if (!store) attrOrig.set(el, (store = {}));
        store[a] = { en: v, zh };
        el.setAttribute(a, zh);
      } else if (C && !(store && store[a])) {
        lookup(v);
      } else if (store && store[a]) {
        if (store[a].zh === v) el.setAttribute(a, store[a].en);
        delete store[a];
      } else {
        const en = back(v);
        if (en != null) el.setAttribute(a, en);
      }
    }
    if (el.tagName === 'INPUT' && (el.type === 'button' || el.type === 'submit') && el.value) {
      const zh = lang === 'zh' ? lookup(el.value) : back(el.value);
      if (zh != null) el.value = zh;
    }
  }

  function walk(root) {
    if (root.nodeType === 3) { if (root.parentElement && !skipped(root.parentElement)) doText(root); return; }
    if (root.nodeType === 1 && fieldHint(root)) { if (!skipped(root.parentElement)) doAttrs(root); return; }
    if (root.nodeType !== 1 || skipped(root)) return;
    const stack = [root];
    while (stack.length) {
      const el = stack.pop();
      doAttrs(el);
      if (doSentence(el)) {
        for (const n of el.childNodes) if (n.nodeType === 1 && !skipped(n)) stack.push(n);
        continue;
      }
      for (const n of el.childNodes) {
        if (n.nodeType === 3) doText(n);
        else if (n.nodeType === 1 && fieldHint(n)) doAttrs(n);
        else if (n.nodeType === 1 && !SKIP_TAGS.has(n.tagName) && n.getAttribute('translate') !== 'no' && !SKIP_CLASS.test(n.getAttribute('class') || '')) stack.push(n);
      }
    }
  }
  // A form field's hint (placeholder, title, label) is page text; what is typed in it never is.
  function fieldHint(el) {
    return (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') && el.getAttribute('translate') !== 'no' && !el.isContentEditable;
  }

  function run(fn) {
    busy = true;
    try { fn(); } finally { if (observer) observer.takeRecords(); busy = false; }
  }

  function onMutations(list) {
    if (busy || (lang === 'en' && !hasZh && !C)) return;
    run(() => {
      const seen = new Set();
      for (const m of list) {
        if (m.type === 'characterData') { if (!seen.has(m.target)) { seen.add(m.target); walk(m.target); } continue; }
        const t = m.target;
        if (m.type === 'attributes') { if (t.nodeType === 1 && (fieldHint(t) ? !skipped(t.parentElement) : !skipped(t))) doAttrs(t); continue; }
        if (t.nodeType === 1 && !seen.has(t) && !skipped(t)) { seen.add(t); doSentence(t) || null; }
        for (const n of m.addedNodes) if (!seen.has(n)) { seen.add(n); walk(n); }
      }
      if (document.title !== lastTitle) title();
    });
  }

  let titleEn = document.title, lastTitle = document.title, hasZh = false;
  function title() {
    if (document.title !== lastTitle) titleEn = document.title; // the page changed it itself
    const t = lang === 'zh' ? (lookup(titleEn) ?? titleEn) : titleEn;
    if (document.title !== t) document.title = t;
    lastTitle = document.title;
  }

  function paintToggle() {
    for (const b of document.querySelectorAll('[data-lang-toggle]')) {
      b.textContent = lang === 'zh' ? 'EN' : '中文';
      b.setAttribute('lang', lang === 'zh' ? 'en' : 'zh-CN');
      b.setAttribute('aria-label', lang === 'zh' ? 'Switch to English' : '切换到中文');
      b.title = lang === 'zh' ? 'English' : '中文（简体）';
    }
  }

  function set(next, { save = true } = {}) {
    lang = next === 'zh' ? 'zh' : 'en';
    if (lang === 'zh') hasZh = true;
    document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
    document.documentElement.dataset.lang = lang;
    if (save) { try { localStorage.setItem(KEY, lang); } catch { /* storage blocked: the choice lasts for this visit */ } }
    run(() => { walk(document.body); title(); paintToggle(); });
    for (const fn of listeners) { try { fn(lang); } catch { /* a listener's problem stays its own */ } }
  }

  function initial() {
    try {
      const q = new URLSearchParams(location.search).get('lang');
      if (q === 'zh' || q === 'en') return q;
    } catch { /* no search part */ }
    try { const s = localStorage.getItem(KEY); if (s === 'zh' || s === 'en') return s; } catch { /* storage blocked */ }
    const langs = (navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || '']);
    return /^zh\b/i.test(langs[0] || '') ? 'zh' : 'en';
  }

  const listeners = [];
  function start() {
    observer = new MutationObserver(onMutations);
    observer.observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRS });
    document.addEventListener('click', (e) => {
      const b = e.target.closest && e.target.closest('[data-lang-toggle]');
      if (b) { e.preventDefault(); set(lang === 'zh' ? 'en' : 'zh'); }
    });
    const first = initial();
    if (first === 'zh') set('zh', { save: false }); else { paintToggle(); if (C) run(() => walk(document.body)); }
  }

  return {
    start,
    set,
    get lang() { return lang; },
    /** Translate a phrase for code that shows text outside the page (alerts, share sheets). */
    t: (s) => (lang === 'zh' ? (lookup(s) ?? s) : s),
    onChange: (fn) => listeners.push(fn),
  };
}
