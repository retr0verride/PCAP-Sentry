"""
Regenerate the PCAP Sentry logo at high resolution (512x512).

Design: Pointy-top hexagon outline in cyan on a dark navy background,
with a DNA double helix in the center (cyan/magenta strands with connecting rungs),
representing genetic-level packet inspection and deep analysis capabilities.
"""

from PIL import Image, ImageDraw, ImageFilter
import math, struct, io, os


# ── colour palette (matched to the original 48px icon) ──────────
DARK_BG      = (10, 12, 17, 255)        # dark navy background
HEX_CYAN     = (63, 169, 245, 255)      # hexagon outline & nodes
CONN_MAGENTA = (194, 53, 168, 255)      # connection lines
HELIX_BRIGHT = (140, 220, 255, 255)     # bright cyan for helix strand
HELIX_ACCENT = (220, 80, 200, 255)      # bright magenta for helix strand


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
        d.polygon(pts, outline=(*HEX_CYAN[:3], 40),
               width=max(2, int(size * 0.04 * s)), fill=None)

    glow = _draw_aa(size, draw_glow, blur=size // 30)
    img.alpha_composite(glow)

    # ── 2. Hexagon outline ─────────────────────────────────────
    lw_hex = max(4, int(size * 0.02))       # ~10px at 512

    def draw_hex(d, s):
        pts = [(x * s, y * s) for x, y in hex_pts]
        # Draw as polygon with outline to ensure clean closed border
        d.polygon(pts, outline=HEX_CYAN, width=int(lw_hex * s), fill=None)

    hex_layer = _draw_aa(size, draw_hex)
    img.alpha_composite(hex_layer)

    # ── 2.5. Double Helix (DNA strand) in center ───────────────
    # Draw a vertical DNA double helix through the center
    helix_height = r * 1.4                   # height of helix
    helix_width = r * 0.28                   # horizontal spread
    helix_top = cy - helix_height * 0.55     # centered vertically
    helix_bottom = cy + helix_height * 0.55  # centered vertically
    turns = 2.0                              # complete cycles for clean end
    segments = 60                            # smoothness of curve
    
    def draw_helix(d, s):
        strand_width = max(2, int(size * 0.008 * s))
        connector_width = max(1, int(size * 0.004 * s))
        
        # Calculate helix points for both strands
        strand1_points = []
        strand2_points = []
        connector_pairs = []
        
        for i in range(segments + 1):
            t = i / segments
            y = helix_top + t * (helix_bottom - helix_top)
            angle = t * turns * 2 * math.pi
            
            # Strand 1 (cyan)
            x1 = cx + helix_width * math.sin(angle)
            strand1_points.append((x1 * s, y * s))
            
            # Strand 2 (magenta) - 180 degrees out of phase
            x2 = cx + helix_width * math.sin(angle + math.pi)
            strand2_points.append((x2 * s, y * s))
            
            # Draw connectors at crossover points (every ~15 segments)
            if i % 8 == 0 and i > 0:
                connector_pairs.append(((x1 * s, y * s), (x2 * s, y * s)))
        
        # Draw connecting bars (rungs of the DNA ladder)
        for p1, p2 in connector_pairs:
            d.line([p1, p2], fill=(*CONN_MAGENTA[:3], 120), width=connector_width)
        
        # Draw the two strands with gradient effect
        # Strand 1 (cyan with subtle glow)
        d.line(strand1_points, fill=HELIX_BRIGHT, width=strand_width, joint="curve")
        
        # Strand 2 (magenta with subtle glow)
        d.line(strand2_points, fill=HELIX_ACCENT, width=strand_width, joint="curve")
        
        # Add small spheres at key points for depth
        sphere_r = max(2, int(size * 0.01 * s))
        for i in range(0, len(strand1_points), 10):
            x1, y1 = strand1_points[i]
            d.ellipse([x1 - sphere_r, y1 - sphere_r, 
                      x1 + sphere_r, y1 + sphere_r], 
                     fill=HELIX_BRIGHT)
            
            x2, y2 = strand2_points[i]
            d.ellipse([x2 - sphere_r, y2 - sphere_r, 
                      x2 + sphere_r, y2 + sphere_r], 
                     fill=HELIX_ACCENT)
    
    helix_layer = _draw_aa(size, draw_helix)
    img.alpha_composite(helix_layer)
    
    # Add soft glow to helix
    helix_glow = _draw_aa(size, draw_helix, blur=size // 100)
    img.alpha_composite(helix_glow)

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
