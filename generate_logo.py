"""
Regenerate the PCAP Sentry logo at high resolution (512x512).

Design: Pointy-top hexagon outline in cyan on a dark navy background,
with three network nodes (cyan circles) connected by magenta lines
forming a triangle inside the hexagon – the original "network shield"
icon from the initial release.
"""

from PIL import Image, ImageDraw, ImageFilter
import math, struct, io, os


# ── colour palette (matched to the original 48px icon) ──────────
DARK_BG      = (10, 12, 17, 255)        # dark navy background
HEX_CYAN     = (63, 169, 245, 255)      # hexagon outline & nodes
CONN_MAGENTA = (194, 53, 168, 255)      # connection lines


def _hex_vertices(cx, cy, r):
    """Return 6 vertices of a regular *pointy-top* hexagon."""
    verts = []
    for i in range(6):
        angle = math.radians(60 * i - 90)          # start at top
        verts.append((cx + r * math.cos(angle),
                      cy + r * math.sin(angle)))
    return verts


def _draw_aa(size, draw_fn, blur=0):
    """Render *draw_fn* at 2x resolution and down-sample for AA."""
    scale = 2
    big = Image.new("RGBA", (size * scale, size * scale), (0, 0, 0, 0))
    d = ImageDraw.Draw(big)
    draw_fn(d, scale)
    if blur:
        big = big.filter(ImageFilter.GaussianBlur(radius=blur * scale))
    return big.resize((size, size), Image.LANCZOS)


def generate_logo(size=512):
    img = Image.new("RGBA", (size, size), DARK_BG)
    cx, cy = size / 2, size / 2
    r = size * 0.415                         # hexagon circumradius

    hex_pts = _hex_vertices(cx, cy, r)

    # ── 1. Subtle outer glow behind the hexagon ────────────────
    def draw_glow(d, s):
        pts = [(x * s, y * s) for x, y in _hex_vertices(cx, cy, r + size * 0.012)]
        d.line(pts + [pts[0]], fill=(*HEX_CYAN[:3], 40),
               width=max(2, int(size * 0.04 * s)), joint="curve")

    glow = _draw_aa(size, draw_glow, blur=size // 30)
    img.alpha_composite(glow)

    # ── 2. Hexagon outline ─────────────────────────────────────
    lw_hex = max(4, int(size * 0.02))       # ~10px at 512

    def draw_hex(d, s):
        pts = [(x * s, y * s) for x, y in hex_pts]
        d.line(pts + [pts[0]], fill=HEX_CYAN,
               width=int(lw_hex * s), joint="curve")

    hex_layer = _draw_aa(size, draw_hex)
    img.alpha_composite(hex_layer)

    # ── 3. Network nodes & connections ─────────────────────────
    # Three nodes proportionally placed from the original 48/64px icon.
    # Offsets are fractions of the hex circumradius, measured from centre.
    node_offsets = [
        (+0.33,  -0.07),       # upper-right  node
        (-0.48,  +0.04),       # left          node
        (-0.15,  +0.30),       # lower-centre  node
    ]
    nodes = [(cx + dx * r, cy + dy * r) for dx, dy in node_offsets]

    node_r = max(4, int(size * 0.028))      # ~14px at 512
    lw_conn = max(3, int(size * 0.013))     # ~6-7px at 512

    # -- connection lines (magenta) --
    def draw_connections(d, s):
        for i in range(3):
            j = (i + 1) % 3
            d.line([(nodes[i][0] * s, nodes[i][1] * s),
                    (nodes[j][0] * s, nodes[j][1] * s)],
                   fill=CONN_MAGENTA, width=int(lw_conn * s))

    conn_layer = _draw_aa(size, draw_connections)
    img.alpha_composite(conn_layer)

    # Soft glow on connections
    conn_glow = _draw_aa(size, draw_connections, blur=size // 80)
    img.alpha_composite(conn_glow)

    # -- node circles (cyan, drawn on top of lines) --
    def draw_nodes(d, s):
        for nx, ny in nodes:
            d.ellipse([
                (nx - node_r) * s, (ny - node_r) * s,
                (nx + node_r) * s, (ny + node_r) * s
            ], fill=HEX_CYAN, outline=(*HEX_CYAN[:3], 200))

    node_layer = _draw_aa(size, draw_nodes)
    img.alpha_composite(node_layer)

    # Small bright highlight at node centres
    def draw_highlights(d, s):
        hr = max(2, node_r // 3)
        for nx, ny in nodes:
            d.ellipse([
                (nx - hr) * s, (ny - hr) * s,
                (nx + hr) * s, (ny + hr) * s
            ], fill=(180, 220, 255, 220))

    hl_layer = _draw_aa(size, draw_highlights)
    img.alpha_composite(hl_layer)

    return img


# ── ICO builder (multi-size, PNG-compressed frames) ─────────────

def build_ico(source_img, ico_path, sizes=None):
    """Build a multi-size ICO from a high-res RGBA source image."""
    if sizes is None:
        sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]

    frames = []
    for s in sizes:
        frame = source_img.resize((s, s), Image.LANCZOS)
        frames.append((s, frame))

    # Build ICO binary – all frames stored as PNG for best quality
    image_data_list = []
    for _, frame in frames:
        buf = io.BytesIO()
        frame.save(buf, format="PNG")
        image_data_list.append(buf.getvalue())

    header = struct.pack("<HHH", 0, 1, len(frames))
    dir_entries = b""
    offset = 6 + len(frames) * 16

    for i, (s, _) in enumerate(frames):
        data = image_data_list[i]
        w = 0 if s >= 256 else s
        h = 0 if s >= 256 else s
        dir_entries += struct.pack(
            "<BBBBHHII", w, h, 0, 0, 1, 32, len(data), offset
        )
        offset += len(data)

    with open(ico_path, "wb") as f:
        f.write(header)
        f.write(dir_entries)
        for data in image_data_list:
            f.write(data)


# ── CLI entry point ─────────────────────────────────────────────

if __name__ == "__main__":
    assets = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
    os.makedirs(assets, exist_ok=True)

    print("Generating 512x512 logo ...")
    logo = generate_logo(512)

    # Master PNG
    master_path = os.path.join(assets, "pcap_sentry_512.png")
    logo.save(master_path, format="PNG")
    print(f"  Saved {master_path}  ({os.path.getsize(master_path):,} bytes)")

    # 256px PNG (GUI header)
    png256 = logo.resize((256, 256), Image.LANCZOS)
    png256_path = os.path.join(assets, "pcap_sentry_256.png")
    png256.save(png256_path, format="PNG")
    print(f"  Saved {png256_path}  ({os.path.getsize(png256_path):,} bytes)")

    # 48px PNG (legacy)
    png48 = logo.resize((48, 48), Image.LANCZOS)
    png48_path = os.path.join(assets, "pcap_sentry_48.png")
    png48.save(png48_path, format="PNG")
    print(f"  Saved {png48_path}  ({os.path.getsize(png48_path):,} bytes)")

    # Multi-size ICO for Windows desktop / taskbar
    ico_path = os.path.join(assets, "pcap_sentry.ico")
    build_ico(logo, ico_path)
    print(f"  Saved {ico_path}  ({os.path.getsize(ico_path):,} bytes)")

    # Verify
    from PIL import Image as PILImage
    check = PILImage.open(ico_path)
    print(f"  ICO sizes: {sorted(check.info.get('sizes', set()))}")
    print("Done!")
