"""
Regenerate PCAP Sentry icon assets from scratch.

Design: pointy-top hexagon (cyan outline, black fill) on transparent bg,
DNA double helix in centre.  The hexagon fills ~94 % of the canvas so the
icon appears the same visual weight as other taskbar icons.

Run:  python tools/make_icons.py
"""

import io
import math
import os
import struct

from PIL import Image, ImageDraw, ImageFilter

# ── colour palette ───────────────────────────────────────────────
DARK_BG      = (10,  12,  17,  255)
HEX_CYAN     = (63,  169, 245, 255)
CONN_MAGENTA = (194,  53, 168, 255)
HELIX_BRIGHT = (140, 220, 255, 255)
HELIX_ACCENT = (220,  80, 200, 255)

# ── geometry constants ───────────────────────────────────────────
# Circumradius as fraction of canvas half-size.
# 0.470 ≈ 94 % fill — comparable to Wireshark/other app icons.
HEX_RADIUS_FRAC = 0.470


def _hex_vertices(cx, cy, r):
    """6 vertices of a regular pointy-top hexagon."""
    return [
        (cx + r * math.cos(math.radians(60 * i - 90)),
         cy + r * math.sin(math.radians(60 * i - 90)))
        for i in range(6)
    ]


def _draw_aa(size, draw_fn, blur=0):
    """Adaptive supersampling: 8x for large frames (≥128px), 4x for small."""
    s = 8 if size >= 128 else 4
    big = Image.new("RGBA", (size * s, size * s), (0, 0, 0, 0))
    draw_fn(ImageDraw.Draw(big), s)
    if blur:
        big = big.filter(ImageFilter.GaussianBlur(radius=blur * s))
    return big.resize((size, size), Image.LANCZOS)


def generate_logo(size: int = 512) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    cx, cy = size / 2, size / 2
    r = size * HEX_RADIUS_FRAC
    draw_helix = size >= 48
    hex_pts = _hex_vertices(cx, cy, r)

    # 1. Outer glow
    def _glow(d, s):
        pts = [(x * s, y * s) for x, y in _hex_vertices(cx, cy, r + size * 0.008)]
        d.polygon(pts, outline=(*HEX_CYAN[:3], 40),
                  width=max(2, int(size * 0.035 * s)), fill=None)
    img.alpha_composite(_draw_aa(size, _glow, blur=size // 30))

    # 2. Hex black fill
    def _fill(d, s):
        d.polygon([(x * s, y * s) for x, y in hex_pts], fill=(0, 0, 0, 255))
    img.alpha_composite(_draw_aa(size, _fill))

    # 3. Hex outline
    lw = max(1, int(size * 0.022))
    def _outline(d, s):
        d.polygon([(x * s, y * s) for x, y in hex_pts],
                  outline=HEX_CYAN, width=int(lw * s), fill=None)
    img.alpha_composite(_draw_aa(size, _outline))

    # 4. DNA double helix
    if draw_helix:
        helix_h   = r * 1.3
        helix_w   = r * 0.26
        top_y     = cy - helix_h * 0.55
        bottom_y  = cy + helix_h * 0.55
        turns     = 2.0
        segs      = max(120, size * 2)  # scale with size for smooth curves

        def _helix(d, s):
            sw = max(2, int(size * 0.008 * s))
            cw = max(1, int(size * 0.004 * s))
            s1, s2, conns = [], [], []
            for i in range(segs + 1):
                t = i / segs
                y = top_y + t * (bottom_y - top_y)
                a = t * turns * 2 * math.pi
                x1 = cx + helix_w * math.sin(a)
                x2 = cx + helix_w * math.sin(a + math.pi)
                s1.append((x1 * s, y * s))
                s2.append((x2 * s, y * s))
                if i % 8 == 0 and i > 0:
                    conns.append(((x1 * s, y * s), (x2 * s, y * s)))
            for p1, p2 in conns:
                d.line([p1, p2], fill=(*CONN_MAGENTA[:3], 120), width=cw)
            d.line(s1, fill=HELIX_BRIGHT, width=sw, joint="curve")
            d.line(s2, fill=HELIX_ACCENT, width=sw, joint="curve")
            sr = max(2, int(size * 0.01 * s))
            for i in range(0, len(s1), 10):
                x1, y1 = s1[i]; x2, y2 = s2[i]
                d.ellipse([x1-sr, y1-sr, x1+sr, y1+sr], fill=HELIX_BRIGHT)
                d.ellipse([x2-sr, y2-sr, x2+sr, y2+sr], fill=HELIX_ACCENT)

        img.alpha_composite(_draw_aa(size, _helix))
        img.alpha_composite(_draw_aa(size, _helix, blur=size // 100))

    return img


def build_ico(ico_path: str,
              sizes=None) -> None:
    """Build a multi-size ICO; each frame rendered natively (no downscale)."""
    if sizes is None:
        sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]

    frames = [(s, generate_logo(s)) for s in sizes]
    image_data = []
    for _, frame in frames:
        buf = io.BytesIO()
        frame.save(buf, format="PNG", optimize=True)
        image_data.append(buf.getvalue())

    header      = struct.pack("<HHH", 0, 1, len(frames))
    dir_entries = b""
    offset      = 6 + len(frames) * 16
    for i, (s, _) in enumerate(frames):
        w = 0 if s >= 256 else s
        h = 0 if s >= 256 else s
        dir_entries += struct.pack("<BBBBHHII",
                                   w, h, 0, 0, 1, 32,
                                   len(image_data[i]), offset)
        offset += len(image_data[i])

    with open(ico_path, "wb") as f:
        f.write(header + dir_entries)
        for data in image_data:
            f.write(data)


if __name__ == "__main__":
    assets = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
    os.makedirs(assets, exist_ok=True)

    for px, name in [(512, "pcap_sentry_512.png"),
                     (256, "pcap_sentry_256.png"),
                     (128, "pcap_sentry_128.png"),
                     (48,  "pcap_sentry_48.png")]:
        print(f"Rendering {px}×{px} …")
        img = generate_logo(px)
        path = os.path.join(assets, name)
        img.save(path, format="PNG", optimize=True)
        print(f"  → {path}  ({os.path.getsize(path):,} bytes)")

    ico_path = os.path.join(assets, "pcap_sentry.ico")
    print("Building ICO (all sizes natively rendered) …")
    build_ico(ico_path)
    from PIL import Image as _I
    sizes = sorted(_I.open(ico_path).info.get("sizes", set()))
    print(f"  → {ico_path}  ({os.path.getsize(ico_path):,} bytes)")
    print(f"  frames: {sizes}")
    print("Done!")
