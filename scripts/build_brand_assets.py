#!/usr/bin/env python3
"""Export the web-sized brand images in assets/brand/ from the 2172x724 masters in assets/.

The masters stay where they are; this script only reads them. Every export is a
downscale (LANCZOS), never an upscale. Run it after a master changes and commit the
results. It needs Pillow (`pip install Pillow`), which CI does not install, so there is
no drift check: image encoders differ between Pillow versions, and a byte-for-byte
check would fail on a version bump with no visible change.

Exports (source -> file, size, format):

  StarWolf64Version2Banner.png    -> starwolf64-banner-1280.png       1280x427  PNG-8   README and profile header
  banner-draft-4.png              -> starwolf64-hero-1600.webp        1600x533  WebP    site cover, dark stage
                                  -> starwolf64-hero-960.webp          960x320  WebP    site cover, small screens
  StarWolf64Version2Banner.png    -> starwolf64-hero-light-960.webp    960x320  WebP    light theme and print (P2)
  StarWolf64BannerTransparent.png -> starwolf64-logotype-480.png       480x160  PNG-8   compact text logotype
  StarWolf64Version2Banner.png    -> social-1280x640.jpg              1280x640  JPEG    GitHub social preview
                                  -> og-1200x630.jpg                  1200x630  JPEG    site og:image
  StarWolf64BannerTransparent.png -> favicon-16.png, favicon-32.png, apple-touch-icon-180.png,
                                     icon-192.png, icon-512.png       the red "64" star, cut out of the logotype

The two fox emblems, the white wolf mask and the constellation emblem are not exported:
they resemble third-party insignia (see docs/VOICE.md, "Persona and look").

Usage:
    python scripts/build_brand_assets.py          # write assets/brand/ and print each file's size
"""
from __future__ import annotations

import os
from collections import deque

from PIL import Image, ImageFilter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "assets")
OUT = os.path.join(ROOT, "assets", "brand")

VERSION2 = "StarWolf64Version2Banner.png"
DRAFT4 = "banner-draft-4.png"
LOGOTYPE = "StarWolf64BannerTransparent.png"

NAVY = (13, 17, 33)          # #0d1121, the social-preview stage
SITE_BG = (11, 18, 32)       # #0b1220, the site background


def master(name: str) -> Image.Image:
    im = Image.open(os.path.join(SRC, name))
    im.load()
    return im.convert("RGBA")


def scaled(im: Image.Image, width: int) -> Image.Image:
    if width > im.width:
        raise SystemExit(f"refusing to upscale {im.width}px to {width}px")
    height = round(im.height * width / im.width)
    return im.resize((width, height), Image.Resampling.LANCZOS)


def save_png8(im: Image.Image, name: str) -> None:
    q = im.quantize(colors=256, method=Image.Quantize.FASTOCTREE)
    q.save(os.path.join(OUT, name), optimize=True)


def save_webp(im: Image.Image, name: str) -> None:
    im.save(os.path.join(OUT, name), "WEBP", quality=85, method=6)


def on_stage(im: Image.Image, size: tuple[int, int], art_width: int, bg) -> Image.Image:
    """The banner, scaled to art_width, centered on a solid background."""
    art = scaled(im, art_width)
    stage = Image.new("RGBA", size, bg + (255,))
    stage.alpha_composite(art, ((size[0] - art.width) // 2, (size[1] - art.height) // 2))
    return stage.convert("RGB")


def save_jpeg(im: Image.Image, name: str) -> None:
    im.save(os.path.join(OUT, name), "JPEG", quality=85, optimize=True, progressive=True)


def star_mark(logo: Image.Image) -> Image.Image:
    """Cut the red-outlined "64" star out of the text logotype.

    The star overlaps the end of the lettering plate, so a rectangular crop would carry
    part of the "F" with it. Instead: mark the star's red outline, flood-fill the
    background from the crop's border without crossing red, and keep what the fill could
    not reach (the outline and everything it encloses). A 4 px dilation keeps the thin
    dark edge outside the red. The result is trimmed and padded to a square.
    """
    box = (1640, 0, logo.width, logo.height)          # right end of the logotype
    crop = logo.crop(box)
    w, h = crop.size
    px = crop.load()
    red = [[False] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            red[y][x] = a > 128 and r > 170 and g < 90 and b < 90
    outside = [[False] * w for _ in range(h)]
    queue = deque()
    for x in range(w):
        queue.extend(((x, 0), (x, h - 1)))
    for y in range(h):
        queue.extend(((0, y), (w - 1, y)))
    while queue:
        x, y = queue.popleft()
        if x < 0 or y < 0 or x >= w or y >= h or outside[y][x] or red[y][x]:
            continue
        outside[y][x] = True
        queue.extend(((x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)))
    mask = Image.new("L", (w, h), 0)
    mp = mask.load()
    for y in range(h):
        for x in range(w):
            if not outside[y][x]:
                mp[x, y] = 255
    mask = mask.filter(ImageFilter.MaxFilter(9))       # 4 px dilation
    mask = mask.filter(ImageFilter.GaussianBlur(0.8))  # soft edge
    alpha = Image.composite(crop.getchannel("A"), Image.new("L", (w, h), 0), mask)
    star = crop.copy()
    star.putalpha(alpha)
    star = star.crop(alpha.getbbox())
    side = max(star.size)
    square = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    square.alpha_composite(star, ((side - star.width) // 2, (side - star.height) // 2))
    return square


def icon(mark: Image.Image, size: int, bg=None, pad: float = 0.0) -> Image.Image:
    inner = round(size * (1 - 2 * pad))
    if inner > mark.width:
        raise SystemExit(f"refusing to upscale the star mark ({mark.width}px) to {inner}px")
    art = mark.resize((inner, inner), Image.Resampling.LANCZOS)
    canvas = Image.new("RGBA", (size, size), (bg + (255,)) if bg else (0, 0, 0, 0))
    off = (size - inner) // 2
    canvas.alpha_composite(art, (off, off))
    return canvas


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    v2, d4, logo = master(VERSION2), master(DRAFT4), master(LOGOTYPE)

    save_png8(scaled(v2, 1280), "starwolf64-banner-1280.png")
    save_webp(scaled(d4, 1600), "starwolf64-hero-1600.webp")
    save_webp(scaled(d4, 960), "starwolf64-hero-960.webp")
    save_webp(scaled(v2, 960), "starwolf64-hero-light-960.webp")
    save_png8(scaled(logo, 480), "starwolf64-logotype-480.png")
    save_jpeg(on_stage(v2, (1280, 640), 1280, NAVY), "social-1280x640.jpg")
    save_jpeg(on_stage(v2, (1200, 630), 1200, NAVY), "og-1200x630.jpg")

    mark = star_mark(logo)
    icon(mark, 16).save(os.path.join(OUT, "favicon-16.png"), optimize=True)
    icon(mark, 32).save(os.path.join(OUT, "favicon-32.png"), optimize=True)
    # iOS fills transparency with black, so the larger icons sit on the site background
    for size, name in ((180, "apple-touch-icon-180.png"), (192, "icon-192.png"), (512, "icon-512.png")):
        save_png8(icon(mark, size, SITE_BG, pad=0.08).convert("RGB"), name)

    for name in sorted(os.listdir(OUT)):
        p = os.path.join(OUT, name)
        with Image.open(p) as im:
            print(f"  {name:34} {im.width}x{im.height:<5} {im.mode:5} {os.path.getsize(p):>8,} B")


if __name__ == "__main__":
    main()
