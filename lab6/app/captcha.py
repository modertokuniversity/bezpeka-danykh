import io
import random
import secrets

from PIL import Image, ImageDraw, ImageFilter, ImageFont

# без схожих символів (0/O, 1/I/l)
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _font(size: int):
    for name in ("arialbd.ttf", "DejaVuSans-Bold.ttf", "arial.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default()


def new_text(length: int = 5) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def render(text: str) -> bytes:
    rnd = random.SystemRandom()
    w, h = 190, 64
    img = Image.new("RGB", (w, h), (244, 246, 250))
    draw = ImageDraw.Draw(img)
    for _ in range(7):
        draw.line(
            [(rnd.randint(0, w), rnd.randint(0, h)), (rnd.randint(0, w), rnd.randint(0, h))],
            fill=(rnd.randint(120, 200),) * 3, width=rnd.randint(1, 2),
        )
    x = 14
    for ch in text:
        glyph = Image.new("RGBA", (44, 56), (0, 0, 0, 0))
        ImageDraw.Draw(glyph).text(
            (6, 4), ch, font=_font(rnd.randint(34, 40)),
            fill=(rnd.randint(10, 90), rnd.randint(10, 90), rnd.randint(60, 140), 255),
        )
        glyph = glyph.rotate(rnd.randint(-22, 22), resample=Image.BICUBIC, expand=False)
        img.paste(glyph, (x, rnd.randint(0, 8)), glyph)
        x += 34
    for _ in range(220):
        draw.point((rnd.randint(0, w - 1), rnd.randint(0, h - 1)), fill=(rnd.randint(80, 180),) * 3)
    img = img.filter(ImageFilter.SMOOTH)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()
