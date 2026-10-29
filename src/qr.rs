use qrcode::{Color, QrCode};

pub struct QrBitmap {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

pub fn render(text: &str, scale: u32, quiet_zone: u32) -> Option<QrBitmap> {
    let code = QrCode::new(text.as_bytes()).ok()?;
    let modules = code.width() as u32;
    let colors = code.to_colors();
    let side = (modules + quiet_zone * 2) * scale;
    let mut rgba = vec![255u8; (side * side * 4) as usize];
    for y in 0..modules {
        for x in 0..modules {
            if colors[(y * modules + x) as usize] != Color::Dark {
                continue;
            }
            for dy in 0..scale {
                for dx in 0..scale {
                    let px = (x + quiet_zone) * scale + dx;
                    let py = (y + quiet_zone) * scale + dy;
                    let offset = ((py * side + px) * 4) as usize;
                    rgba[offset] = 0;
                    rgba[offset + 1] = 0;
                    rgba[offset + 2] = 0;
                    rgba[offset + 3] = 255;
                }
            }
        }
    }
    Some(QrBitmap { width: side, height: side, rgba })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_square_bitmap_with_quiet_zone() {
        let bitmap = render("tg://proxy?server=127.0.0.1&port=1443&secret=dd00112233445566778899aabbccddeeff", 4, 2).unwrap();
        assert_eq!(bitmap.width, bitmap.height);
        assert_eq!(bitmap.rgba.len() as u32, bitmap.width * bitmap.height * 4);
        assert_eq!(&bitmap.rgba[..4], &[255, 255, 255, 255]);
        assert!(bitmap.rgba.chunks(4).any(|px| px[0] == 0));
    }

    #[test]
    fn different_payloads_differ() {
        let a = render("aaaa", 2, 1).unwrap();
        let b = render("bbbb", 2, 1).unwrap();
        assert_ne!(a.rgba, b.rgba);
    }
}
