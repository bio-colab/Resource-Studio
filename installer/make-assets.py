from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

root = Path(__file__).resolve().parents[1]
source = root / "assets" / "branding" / "resource-studio-mark-256.png"
out = root / "build" / "windows-installer" / "stage"
out.mkdir(parents=True, exist_ok=True)
mark = Image.open(source).convert("RGBA")

# Inno Setup accepts BMP wizard artwork; keep the existing dark/cyan brand and add a restrained title.
try:
    font = ImageFont.truetype("C:/Windows/Fonts/segoeui.ttf", 16)
except OSError:
    font = ImageFont.load_default()

banner = Image.new("RGB", (164, 314), (15, 23, 42))
mark_resized = mark.resize((128, 128), Image.Resampling.LANCZOS)
banner.paste(mark_resized, (18, 58), mark_resized)
draw = ImageDraw.Draw(banner)
draw.text((20, 214), "RESOURCE", fill=(102, 226, 239), font=font)
draw.text((20, 238), "STUDIO", fill=(102, 226, 239), font=font)
banner.save(out / "installer-wizard.bmp", format="BMP")

small = Image.new("RGB", (55, 55), (15, 23, 42))
small.paste(mark.resize((48, 48), Image.Resampling.LANCZOS), (4, 3), mark.resize((48, 48), Image.Resampling.LANCZOS))
small.save(out / "installer-small.bmp", format="BMP")
