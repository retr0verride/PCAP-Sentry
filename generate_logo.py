"""
Regenerate the PCAP Sentry logo at high resolution (512x512).

Design: Diamond/shield shape with dark navy body, glowing cyan/teal
border edges, and a double-helix (infinity / figure-8) network motif
through the center.
"""

from PIL import Image, ImageDraw, ImageFilter, ImageEnhance
import math, struct, io, os

SIZE = 512
CENTER = SIZE // 2

# ── colour palette (taken from original 48px icon) ──────────────
DARK_BG    = (15, 19, 28, 255)       # dark navy body fill
EDGE_CYAN  = (80, 180, 240, 255)     # bright cyan diamond edge
EDGE_INNER = (35, 95, 140, 255)      # darker teal inner edge
HELIX_CYAN = (70, 170, 230, 255)     # helix strand colour
HELIX_GLOW = (100, 200, 255, 120)    # soft glow around helix


def draw_diamond(draw, cx, cy, radius, fill, outline=None, width=1):
    """Draw a diamond (rotated square) centred at (cx, cy)."""
    pts = [
        (cx, cy - radius),       # top
        (cx + radius, cy),       # right
        (cx, cy + radius),       # bottom
        (cx - radius, cy),       # left
    ]
    draw.polygon(pts, fill=fill, outline=outline, width=width)
    return pts


def helix_point(t, cx, cy, rx, ry):
    """Return (x, y) for one strand of the double-helix at parameter t.
    t in [0, 2π] traces one full cycle."""
    x = cx + rx * math.cos(t)
    y = cy + ry * math.sin(t)      # vertical sinusoidal wave
    return x, y


def draw_thick_line_aa(img, pts, color, width):
    """Draw an anti-aliased thick poly-line by drawing on a 2x canvas."""
    scale = 2
    big = Image.new("RGBA", (img.width * scale, img.height * scale), (0, 0, 0, 0))
    d = ImageDraw.Draw(big)
    scaled_pts = [(x * scale, y * scale) for x, y in pts]
    d.line(scaled_pts, fill=color, width=int(width * scale), joint="curve")
    big = big.resize(img.size, Image.LANCZOS)
    img.alpha_composite(big)


def generate_logo(size=512):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    cx, cy = size // 2, size // 2

    # Diamond radius – leave a small margin for glow
    margin = int(size * 0.06)
    r = cx - margin

    # ── 1. Outer glow layer ─────────────────────────────────────
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    draw_diamond(gd, cx, cy, r + int(size * 0.01),
                 fill=(60, 160, 220, 50), outline=(80, 200, 255, 80),
                 width=max(2, size // 64))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=size // 40))
    img.alpha_composite(glow)

    # ── 2. Main diamond body ────────────────────────────────────
    body = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    bd = ImageDraw.Draw(body)
    draw_diamond(bd, cx, cy, r, fill=DARK_BG)
    img.alpha_composite(body)

    # ── 3. Inner border – double cyan lines ─────────────────────
    border = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    brd = ImageDraw.Draw(border)
    bw = max(3, size // 80)       # border line width

    # Outer edge line
    draw_diamond(brd, cx, cy, r, fill=None, outline=EDGE_CYAN, width=bw)
    # Inner edge line (slightly smaller, darker teal)
    inner_r = r - int(size * 0.030)
    draw_diamond(brd, cx, cy, inner_r, fill=None, outline=EDGE_INNER, width=max(2, bw // 2))

    img.alpha_composite(border)

    # ── 4. Double-helix / infinity pattern ──────────────────────
    # The helix runs vertically through the diamond centre.
    # Two strands weave around each other forming a figure-8 shape.
    helix_layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    num_pts = 300
    strand_a = []
    strand_b = []

    # The helix spans vertically across ~70 % of the diamond
    helix_height = int(r * 0.70)           # half-height of helix
    helix_width  = int(r * 0.28)           # horizontal amplitude

    # Two full twists
    num_twists = 2.0

    for i in range(num_pts + 1):
        t = i / num_pts                      # 0 → 1
        angle = t * num_twists * 2 * math.pi

        # Vertical position (top to bottom of helix region)
        y = cy - helix_height + t * 2 * helix_height

        # Horizontal sinusoidal offset
        x_off = helix_width * math.sin(angle)

        strand_a.append((cx + x_off, y))
        strand_b.append((cx - x_off, y))

    lw = max(4, size // 80)   # line width

    # Glow behind strands
    glow_layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw_thick_line_aa(glow_layer, strand_a, HELIX_GLOW, lw + 6)
    draw_thick_line_aa(glow_layer, strand_b, HELIX_GLOW, lw + 6)
    glow_layer = glow_layer.filter(ImageFilter.GaussianBlur(radius=size // 60))
    helix_layer.alpha_composite(glow_layer)

    # Draw the actual strands with crossing logic
    # Split each strand into segments; alternate which is "in front"
    seg_len = num_pts // (int(num_twists) * 2)
    for seg_start in range(0, num_pts, seg_len):
        seg_end = min(seg_start + seg_len, num_pts)
        seg_a = strand_a[seg_start:seg_end + 1]
        seg_b = strand_b[seg_start:seg_end + 1]

        # Determine which strand is in front at this segment
        # At segment midpoint, front strand is the one with positive x offset
        mid_idx = (seg_start + seg_end) // 2
        a_in_front = strand_a[mid_idx][0] > strand_b[mid_idx][0]

        if a_in_front:
            draw_thick_line_aa(helix_layer, seg_b, EDGE_INNER, lw)
            draw_thick_line_aa(helix_layer, seg_a, HELIX_CYAN, lw)
        else:
            draw_thick_line_aa(helix_layer, seg_a, EDGE_INNER, lw)
            draw_thick_line_aa(helix_layer, seg_b, HELIX_CYAN, lw)

    # Draw cross-rungs between the strands (like DNA rungs)
    rung_layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    num_rungs = int(num_twists * 4) + 1  # rungs at regular intervals
    for j in range(num_rungs):
        t = j / (num_rungs - 1)
        idx = int(t * num_pts)
        ax, ay = strand_a[min(idx, num_pts)]
        bx, by = strand_b[min(idx, num_pts)]
        # Only draw when strands are far enough apart
        dist = abs(ax - bx)
        if dist > size * 0.04:
            rung_color = (50, 140, 200, int(180 * (dist / (helix_width * 2))))
            draw_thick_line_aa(rung_layer, [(ax, ay), (bx, by)],
                               rung_color, max(2, lw // 2))
    helix_layer.alpha_composite(rung_layer)

    # Mask helix to diamond shape
    mask = Image.new("L", (size, size), 0)
    md = ImageDraw.Draw(mask)
    mask_r = inner_r - int(size * 0.015)
    pts = [
        (cx, cy - mask_r),
        (cx + mask_r, cy),
        (cx, cy + mask_r),
        (cx - mask_r, cy),
    ]
    md.polygon(pts, fill=255)
    helix_layer.putalpha(Image.composite(
        helix_layer.split()[3], Image.new("L", (size, size), 0), mask))

    img.alpha_composite(helix_layer)

    # ── 5. Subtle node dots at helix crossings ──────────────────
    dots = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    dd = ImageDraw.Draw(dots)
    dot_r = max(3, size // 100)
    crossings_at = []                       # t values where strands cross
    for i in range(1, num_pts):
        # Crossing when sin changes sign
        a_prev = strand_a[i-1][0] - cx
        a_curr = strand_a[i][0] - cx
        if a_prev * a_curr < 0:
            crossings_at.append(i)
    for idx in crossings_at:
        x = cx
        y = int(strand_a[idx][1])
        # Check the dot is inside the diamond mask
        if mask.getpixel((min(x, size-1), min(y, size-1))) > 0:
            dd.ellipse(
                [x - dot_r, y - dot_r, x + dot_r, y + dot_r],
                fill=(150, 240, 255, 220),
                outline=(200, 255, 255, 255),
            )
    dots_glow = dots.copy().filter(ImageFilter.GaussianBlur(radius=dot_r))
    img.alpha_composite(dots_glow)
    img.alpha_composite(dots)

    return img


def build_ico(source_img, ico_path, sizes=None):
    """Build a multi-size ICO from a high-res RGBA source image."""
    if sizes is None:
        sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]

    frames = []
    for s in sizes:
        frame = source_img.resize((s, s), Image.LANCZOS)
        frames.append((s, frame))

    # Build ICO binary (all frames stored as PNG for best quality)
    image_data_list = []
    for s, frame in frames:
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


if __name__ == "__main__":
    assets = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")

    print("Generating 512x512 logo...")
    logo = generate_logo(512)

    # Save master PNG
    master_path = os.path.join(assets, "pcap_sentry_512.png")
    logo.save(master_path, format="PNG")
    print(f"  Saved {master_path}  ({os.path.getsize(master_path):,} bytes)")

    # Save 256px PNG (used by the GUI header)
    png256 = logo.resize((256, 256), Image.LANCZOS)
    png256_path = os.path.join(assets, "pcap_sentry_256.png")
    png256.save(png256_path, format="PNG")
    print(f"  Saved {png256_path}  ({os.path.getsize(png256_path):,} bytes)")

    # Save 48px PNG (legacy)
    png48 = logo.resize((48, 48), Image.LANCZOS)
    png48_path = os.path.join(assets, "pcap_sentry_48.png")
    png48.save(png48_path, format="PNG")
    print(f"  Saved {png48_path}  ({os.path.getsize(png48_path):,} bytes)")

    # Build ICO with all standard Windows sizes
    ico_path = os.path.join(assets, "pcap_sentry.ico")
    build_ico(logo, ico_path)
    print(f"  Saved {ico_path}  ({os.path.getsize(ico_path):,} bytes)")

    # Verify ICO
    from PIL import Image as PILImage
    check = PILImage.open(ico_path)
    print(f"  ICO sizes: {sorted(check.info.get('sizes', set()))}")
    print("Done!")
