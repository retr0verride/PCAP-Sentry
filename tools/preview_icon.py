"""Render a side-by-side preview: current icon vs proposed new design."""
import base64, io, math, os
from PIL import Image, ImageDraw, ImageFilter

ASSETS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")

# ── colours ──────────────────────────────────────────────────────
BG_DARK      = (10,  12,  17,  255)
BG_NAVY      = (13,  17,  25,  255)
HEX_CYAN     = (63,  169, 245, 255)
CONN_MAG     = (194,  53, 168, 255)
HELIX_B      = (140, 220, 255, 255)
HELIX_A      = (220,  80, 200, 255)

def _hex_pts(cx, cy, r):
    return [(cx + r*math.cos(math.radians(60*i-90)),
             cy + r*math.sin(math.radians(60*i-90))) for i in range(6)]

def _aa(size, fn, blur=0):
    # Adaptive supersampling: 8x for large frames, 4x for small
    s = 8 if size >= 128 else 4
    big=Image.new("RGBA",(size*s,size*s),(0,0,0,0))
    fn(ImageDraw.Draw(big),s)
    if blur: big=big.filter(ImageFilter.GaussianBlur(radius=blur*s))
    return big.resize((size,size),Image.LANCZOS)

def _helix_layer(img, cx, cy, r, size):
    h=r*1.3; w=r*0.26; ty=cy-h*0.55; by=cy+h*0.55
    segs=max(120, size*2)  # more segments = smoother curves at all sizes
    def _draw(d,s):
        sw=max(2,int(size*0.008*s)); cw=max(1,int(size*0.004*s))
        s1,s2,cc=[],[],[]
        for i in range(segs+1):
            t=i/segs; y=ty+t*(by-ty); a=t*2*2*math.pi
            x1=cx+w*math.sin(a); x2=cx+w*math.sin(a+math.pi)
            s1.append((x1*s,y*s)); s2.append((x2*s,y*s))
            if i%8==0 and i>0: cc.append(((x1*s,y*s),(x2*s,y*s)))
        for p1,p2 in cc: d.line([p1,p2],fill=(*CONN_MAG[:3],120),width=cw)
        d.line(s1,fill=HELIX_B,width=sw,joint="curve")
        d.line(s2,fill=HELIX_A,width=sw,joint="curve")
        sr=max(2,int(size*0.01*s))
        for i in range(0,len(s1),10):
            x1,y1=s1[i]; x2,y2=s2[i]
            d.ellipse([x1-sr,y1-sr,x1+sr,y1+sr],fill=HELIX_B)
            d.ellipse([x2-sr,y2-sr,x2+sr,y2+sr],fill=HELIX_A)
    img.alpha_composite(_aa(size,_draw))
    img.alpha_composite(_aa(size,_draw,blur=size//100))

# ── CURRENT design (transparent bg, hex outline only) ────────────
def current(size=256):
    img=Image.new("RGBA",(size,size),(0,0,0,0))
    cx=cy=size/2; r=size*0.475
    pts=_hex_pts(cx,cy,r)
    def g(d,s): d.polygon([(x*s,y*s) for x,y in _hex_pts(cx,cy,r+size*0.012)],outline=(*HEX_CYAN[:3],40),width=max(2,int(size*0.04*s)))
    img.alpha_composite(_aa(size,g,blur=size//30))
    def f(d,s): d.polygon([(x*s,y*s) for x,y in pts],fill=(0,0,0,255))
    img.alpha_composite(_aa(size,f))
    # Proportional outline — no hard floor so 48px stays thin
    lw=max(1, round(size * 0.016))
    def o(d,s): d.polygon([(x*s,y*s) for x,y in pts],outline=HEX_CYAN,width=max(1,int(lw*s)))
    img.alpha_composite(_aa(size,o))
    _helix_layer(img,cx,cy,r,size)
    return img

# ── PROPOSED design (dark rounded-square bg, hex + helix on top) ─
def proposed(size=256):
    img=Image.new("RGBA",(size,size),(0,0,0,0))
    cx=cy=size/2

    # Rounded-square background (corner radius ~22%)
    corner=int(size*0.22)
    def _bg(d,s):
        d.rounded_rectangle([2*s,2*s,(size-2)*s,(size-2)*s],
                             radius=corner*s, fill=BG_NAVY)
    img.alpha_composite(_aa(size,_bg))

    # Subtle edge glow on the bg card
    def _bg_glow(d,s):
        d.rounded_rectangle([2*s,2*s,(size-2)*s,(size-2)*s],
                             radius=corner*s,
                             outline=(*HEX_CYAN[:3],35),
                             width=max(1,int(size*0.012*s)))
    img.alpha_composite(_aa(size,_bg_glow))

    # Hex — fills most of the card with a small inset margin
    r=size*0.430
    pts=_hex_pts(cx,cy,r)
    def _glow(d,s):
        d.polygon([(x*s,y*s) for x,y in _hex_pts(cx,cy,r+size*0.01)],
                  outline=(*HEX_CYAN[:3],50),width=max(2,int(size*0.04*s)))
    img.alpha_composite(_aa(size,_glow,blur=size//25))
    def _fill(d,s):
        d.polygon([(x*s,y*s) for x,y in pts],fill=(5,7,12,255))
    img.alpha_composite(_aa(size,_fill))
    # Proportional outline — no hard floor so it stays thin at 48px
    lw=max(1, round(size * 0.014))
    def _out(d,s):
        d.polygon([(x*s,y*s) for x,y in pts],outline=HEX_CYAN,width=max(1,int(lw*s)))
    img.alpha_composite(_aa(size,_out))
    _helix_layer(img,cx,cy,r,size)
    return img

# ── build side-by-side HTML preview ──────────────────────────────
def _png_b64(img):
    buf=io.BytesIO(); img.save(buf,format="PNG"); return base64.b64encode(buf.getvalue()).decode()

# Checkerboard background to show transparency
size=256
checker=Image.new("RGB",(size,size))
d=ImageDraw.Draw(checker)
sq=16
for r in range(size//sq):
    for c in range(size//sq):
        col=(200,200,200) if (r+c)%2==0 else (255,255,255)
        d.rectangle([c*sq,r*sq,(c+1)*sq,(r+1)*sq],fill=col)

def composite_on_checker(icon):
    bg=checker.copy()
    bg.paste(icon,mask=icon.split()[3])
    return bg

cur=current(size); prop=proposed(size)
cur_check=composite_on_checker(cur)
prop_check=composite_on_checker(prop)

# Also show at 48px (taskbar-ish size) scaled up 4x for clarity
cur48=current(48).resize((192,192),Image.NEAREST)
prop48=proposed(48).resize((192,192),Image.NEAREST)
cur48_check=composite_on_checker(cur48.resize((size,size),Image.LANCZOS))
prop48_check=composite_on_checker(prop48.resize((size,size),Image.LANCZOS))

html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Icon Preview</title>
<style>
  body{{background:#1a1a2e;color:#e0e0e0;font-family:Segoe UI,sans-serif;padding:32px}}
  h1{{color:#3fa9f5;margin-bottom:8px}} h2{{color:#aaa;font-size:14px;margin:0 0 20px}}
  .row{{display:flex;gap:40px;align-items:flex-end;margin-bottom:40px}}
  .col{{text-align:center}} .col p{{margin:8px 0 0;font-size:13px;color:#aaa}}
  img{{image-rendering:pixelated;border:1px solid #333;border-radius:8px}}
  .label{{background:#0d1117;color:#3fa9f5;font-size:12px;padding:4px 10px;
          border-radius:4px;display:inline-block;margin-bottom:8px}}
</style></head><body>
<h1>PCAP Sentry — Icon Preview</h1>
<h2>Left = current &nbsp;|&nbsp; Right = proposed (dark card background)</h2>

<div class="row">
  <div class="col">
    <div class="label">Current — 256px</div><br>
    <img src="data:image/png;base64,{_png_b64(cur_check)}" width="256" height="256">
    <p>Transparent bg — floats on taskbar</p>
  </div>
  <div class="col">
    <div class="label">Proposed — 256px</div><br>
    <img src="data:image/png;base64,{_png_b64(prop_check)}" width="256" height="256">
    <p>Dark rounded-square card — fills full canvas</p>
  </div>
</div>

<div class="row">
  <div class="col">
    <div class="label">Current — 48px (4× zoom)</div><br>
    <img src="data:image/png;base64,{_png_b64(cur48_check)}" width="192" height="192">
    <p>How it looks on the taskbar</p>
  </div>
  <div class="col">
    <div class="label">Proposed — 48px (4× zoom)</div><br>
    <img src="data:image/png;base64,{_png_b64(prop48_check)}" width="192" height="192">
    <p>Same visual weight as other icons</p>
  </div>
</div>
</body></html>"""

out=os.path.join(os.path.dirname(os.path.abspath(__file__)),"icon_preview.html")
with open(out,"w") as f: f.write(html)
print(f"Preview: {out}")
