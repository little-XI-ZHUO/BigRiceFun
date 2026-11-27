"""Build the BigRiceFun / 野人先生 icon set from the extracted logo master.

The brand mark is a single-colour silhouette (orange shape, the flame is a cut-out that
opens into the notch at the bottom). The master is therefore flattened to one colour
with a clean alpha matte taken from the blue channel, which removes any light halo
left by the source's white background.

Small sizes get a slightly bolder cut-out so the flame still reads at 16-32 px.

usage: python -I make_icon.py <logo-master.png> <out_dir>
"""
import os
import sys

from collections import Counter

from PIL import Image, ImageFilter


def flatten(master):
    """Return (RGBA image, brand colour): one flat colour with a clean alpha matte."""
    master = master.convert("RGBA")
    w, h = master.size
    mp = master.load()
    votes = Counter()
    for y in range(0, h, 3):
        for x in range(0, w, 3):
            r, g, b, a = mp[x, y]
            if a > 200 and r > 170 and g < 150 and b < 120:
                votes[(r // 2 * 2, g // 2 * 2, b // 2 * 2)] += 1
    if not votes:
        raise SystemExit("no brand colour found in the master")
    (cr, cg, cb), _ = votes.most_common(1)[0]
    # Blue has the largest contrast against the white the logo was drawn on, so it gives
    # the coverage of each edge pixel. The master's own alpha keeps the background and
    # the cut-outs transparent (a plain convert("RGB") would turn them black = opaque).
    lo, hi = float(cb), 255.0
    out = Image.new("RGBA", (w, h), (cr, cg, cb, 0))
    op = out.load()
    for y in range(h):
        for x in range(w):
            ma = mp[x, y][3]
            if ma == 0:
                continue
            a = (hi - mp[x, y][2]) / (hi - lo)
            a = 0.0 if a < 0.0 else (1.0 if a > 1.0 else a)
            a *= ma / 255.0
            if a <= 0.02:
                continue
            op[x, y] = (cr, cg, cb, 255 if a >= 0.98 else int(a * 255 + 0.5))
    return out, (cr, cg, cb)


def crop_square(img):
    bbox = img.getchannel("A").getbbox()
    img = img.crop(bbox)
    side = max(img.size)
    pad = int(round(side * 0.02))
    canvas = Image.new("RGBA", (side + 2 * pad, side + 2 * pad), (0, 0, 0, 0))
    canvas.paste(img, ((canvas.width - img.width) // 2, (canvas.height - img.height) // 2))
    return canvas


def main():
    src, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    flat, colour = flatten(Image.open(src))
    flat = crop_square(flat)
    flat.save(os.path.join(out, "..", "logo-flat.png"))
    # bolder cut-out for the tiny sizes: eroding the matte widens the holes
    bold = flat.filter(ImageFilter.MinFilter(15))
    sizes = (16, 20, 24, 32, 48, 64, 128, 256)
    imgs = {}
    for s in sizes:
        im = (bold if s <= 32 else flat).resize((s, s), Image.LANCZOS)
        imgs[s] = im
        im.save(os.path.join(out, "icon%d.png" % s))
    imgs[256].save(os.path.join(out, "icon.ico"), sizes=[(s, s) for s in sizes])
    print("brand colour #%02X%02X%02X | master %dx%d | wrote %d sizes to %s"
          % (colour + flat.size + (len(sizes), out)))


if __name__ == "__main__":
    main()
