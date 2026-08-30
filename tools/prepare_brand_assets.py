from __future__ import annotations

from pathlib import Path
from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
BRANDING = ROOT / "assets" / "branding"
SOURCE = BRANDING / "resource-studio-mark.png"


def remove_magenta_background(image: Image.Image) -> Image.Image:
    rgba = image.convert("RGBA")
    pixels = rgba.load()
    for y in range(rgba.height):
        for x in range(rgba.width):
            r, g, b, _ = pixels[x, y]
            if r > 140 and b > 100 and g < 135 and r - g > 65 and b - g > 35:
                pixels[x, y] = (r, g, b, 0)
    return rgba


def main() -> None:
    image = remove_magenta_background(Image.open(SOURCE))
    image.save(BRANDING / "resource-studio-mark.png")
    image.resize((256, 256), Image.Resampling.LANCZOS).save(BRANDING / "resource-studio-mark-256.png")
    for size in (64, 32, 16):
        image.resize((size, size), Image.Resampling.LANCZOS).save(BRANDING / f"resource-studio-icon-{size}.png")
    image.resize((256, 256), Image.Resampling.LANCZOS).save(BRANDING / "resource-studio.ico", format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("brand-assets: prepared transparent mark and Windows sizes")


if __name__ == "__main__":
    main()
