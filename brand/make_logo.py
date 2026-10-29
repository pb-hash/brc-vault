"""Rebuild the BRC Vault logo as clean vector artwork.

The mark (rounded box, V with a location-pin cutout, indigo dot) is drawn from
measured geometry. The wordmark is set in Geist (Vercel, SIL OFL 1.1) and
converted to outlines so the SVG renders identically everywhere.
Usage: python3 brand/make_logo.py <out-dir>
"""
import math, sys, io, pathlib
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.boundsPen import BoundsPen

OUT = pathlib.Path(sys.argv[1]); OUT.mkdir(parents=True, exist_ok=True)
INK = "#353535"
DOT = "#5956FD"
VAR = "node_modules/geist/dist/fonts/geist-sans/Geist-Variable.ttf"

# ---------------- Mark (coordinates measured from the original artwork) ----------------
BOX_X, BOX_Y, BOX_W, STROKE, R_OUT = 307.6, 90.0, 1316.0, 107.8, 252.6
CX = BOX_X + BOX_W / 2           # 965.6, the vertical axis of symmetry
DOT_CY, DOT_R = 516.6, 114.0
PIN_R = 185.7                    # gap ring around the dot
V_TOP, V_BOTTOM, APEX_Y = 415.0, 1150.0, 958.7
V_OUT_HALF_TOP, V_OUT_HALF_BOTTOM = 420.8, 97.4

def mark_paths():
    half = STROKE / 2
    r_mid = R_OUT - half
    box = (f'<rect x="{BOX_X + half:.1f}" y="{BOX_Y + half:.1f}" width="{BOX_W - STROKE:.1f}" '
           f'height="{BOX_W - STROKE:.1f}" rx="{r_mid:.1f}" fill="none" stroke="{{ink}}" stroke-width="{STROKE:.1f}"/>')
    d = APEX_Y - DOT_CY
    theta = math.acos(PIN_R / d)
    tx, ty = PIN_R * math.sin(theta), DOT_CY + PIN_R * math.cos(theta)
    top_dx = math.sqrt(PIN_R ** 2 - (DOT_CY - V_TOP) ** 2)
    v = (f'<path fill="{{ink}}" d="M{CX - V_OUT_HALF_TOP:.1f} {V_TOP}'
         f'L{CX - V_OUT_HALF_BOTTOM:.1f} {V_BOTTOM}L{CX + V_OUT_HALF_BOTTOM:.1f} {V_BOTTOM}'
         f'L{CX + V_OUT_HALF_TOP:.1f} {V_TOP}L{CX + top_dx:.1f} {V_TOP}'
         f'A{PIN_R} {PIN_R} 0 0 1 {CX + tx:.1f} {ty:.1f}L{CX:.1f} {APEX_Y}L{CX - tx:.1f} {ty:.1f}'
         f'A{PIN_R} {PIN_R} 0 0 1 {CX - top_dx:.1f} {V_TOP}Z"/>')
    dot = f'<circle cx="{CX:.1f}" cy="{DOT_CY}" r="{DOT_R}" fill="{{dot}}"/>'
    return box, v, dot

# ---------------- Wordmark ----------------
# The original wordmark sat about 20 units right of centre. It is now set flush
# with the box's outer edges, so it is centred and exactly as wide as the mark.
GAP = 52.0                                  # space between box and wordmark, as in the original
LEFT, RIGHT = BOX_X, BOX_X + BOX_W
CAP_TOP = BOX_Y + BOX_W + GAP

def instance(wght):
    f = TTFont(VAR)
    return instantiateVariableFont(f, {"wght": wght}, inplace=False)

def word_glyphs(font, text):
    cmap = font.getBestCmap(); gs = font.getGlyphSet(); hmtx = font["hmtx"]
    return [(cmap[ord(ch)], gs[cmap[ord(ch)]], hmtx[cmap[ord(ch)]][0]) for ch in text]

def set_word(font, text, x, scale, tracking, baseline):
    out = []
    for name, glyph, adv in word_glyphs(font, text):
        pen = SVGPathPen(font.getGlyphSet())
        glyph.draw(TransformPen(pen, (scale, 0, 0, -scale, x, baseline)))
        out.append(pen.getCommands())
        x += adv * scale + tracking
    return " ".join(out), x

def stem_ratio(font):
    gs = font.getGlyphSet(); bp = BoundsPen(gs); gs["I"].draw(bp)
    cap = font["OS/2"].sCapHeight
    return (bp.bounds[2] - bp.bounds[0]) / cap

def weight_for(target):
    lo, hi = 100, 900
    for _ in range(14):
        mid = (lo + hi) / 2
        if stem_ratio(instance(mid)) < target: lo = mid
        else: hi = mid
    return round((lo + hi) / 2)

light_w = weight_for(22.0 / 178.0)          # stem/cap-height ratios measured from the original
bold_w = weight_for(36.0 / 178.0)
light, bold = instance(light_w), instance(bold_w)

def ink_bounds(font, text, x0, scale, tracking):
    """Left and right edges of the actual letter shapes (not their side bearings)."""
    gs = font.getGlyphSet(); x = x0; lefts = []; rights = []
    for name, glyph, adv in word_glyphs(font, text):
        bp = BoundsPen(gs); glyph.draw(bp)
        if bp.bounds:
            lefts.append(x + bp.bounds[0] * scale); rights.append(x + bp.bounds[2] * scale)
        x += adv * scale + tracking
    return min(lefts), max(rights), x

# Same proportions as the original: cap height 178 for an ink width of 1208, tracking -20.3 at that size.
CAP = 178.0 * (RIGHT - LEFT) / 1208.0
scale = CAP / light["OS/2"].sCapHeight
CAP_BOTTOM = CAP_TOP + CAP

def measure(tracking, x0=0.0):
    l1, r1, x = ink_bounds(light, "BRC", x0, scale, tracking)
    l2, r2, _ = ink_bounds(bold, "VAULT", x, scale, tracking)
    return l1, r2

def wordmark_d(tracking, x0):
    d1, x = set_word(light, "BRC", x0, scale, tracking, CAP_BOTTOM)
    d2, _ = set_word(bold, "VAULT", x, scale, tracking, CAP_BOTTOM)
    return d1 + " " + d2

# Fit tracking so the ink spans exactly the box width, then shift so it starts at the box edge.
lo, hi = -80.0, 80.0
for _ in range(40):
    mid = (lo + hi) / 2
    l, r = measure(mid)
    if r - l > RIGHT - LEFT: hi = mid
    else: lo = mid
tracking = (lo + hi) / 2
l, r = measure(tracking)
x0 = LEFT - l
word_d = wordmark_d(tracking, x0)
l, r = measure(tracking, x0)
print(f"wordmark ink {l:.2f} to {r:.2f} (box {LEFT:.2f} to {RIGHT:.2f}), cap height {CAP:.1f}")
print(f"wordmark: BRC wght {light_w}, VAULT wght {bold_w}, tracking {tracking:.1f}")

def svg(view, body):
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}">{body}</svg>\n'

def colored(parts, ink=INK, dot=DOT):
    return "".join(p.replace("{ink}", ink).replace("{dot}", dot) for p in parts)

box, v, dot = mark_paths()
mark_view = f"{BOX_X:.1f} {BOX_Y:.1f} {BOX_W:.1f} {BOX_W:.1f}"
lockup_view = f"{BOX_X - 80:.1f} {BOX_Y - 80:.1f} {BOX_W + 160:.1f} {CAP_BOTTOM - BOX_Y + 160:.1f}"
word = f'<path fill="{{ink}}" d="{word_d}"/>'

files = {
    "brc-vault-mark.svg": svg(mark_view, colored([box, v, dot])),
    "brc-vault-mark-white.svg": svg(mark_view, colored([f'<rect x="{BOX_X}" y="{BOX_Y}" width="{BOX_W}" height="{BOX_W}" rx="{R_OUT}" fill="#fff"/>', box, v, dot])),
    "brc-vault-logo.svg": svg(lockup_view, colored([box, v, dot, word])),
    "brc-vault-logo-mono.svg": svg(lockup_view, colored([box, v, dot, word], ink="#000", dot="#000")),
}
for name, text in files.items():
    (OUT / name).write_text(text)
    print(name, len(text), "bytes")

# Small pieces the page build inlines.
(OUT / "mark-inner.txt").write_text(colored([box, v, dot], ink="currentColor", dot="var(--brand)"))
(OUT / "mark-print.txt").write_text(colored([box, v, dot], ink="#000", dot="#000"))
