use slint::{Image, Rgba8Pixel, SharedPixelBuffer};

pub const ICON_BYTES: &[u8] = include_bytes!("../../icon.ico");

pub fn load_icon_rgba(size: Option<u32>) -> Option<(Vec<u8>, u32, u32)> {
    let image = image::load_from_memory_with_format(ICON_BYTES, image::ImageFormat::Ico).ok()?;
    let image = match size {
        Some(size) => image.resize_exact(size, size, image::imageops::FilterType::Lanczos3),
        None => image,
    };
    let rgba = image.to_rgba8();
    let (w, h) = rgba.dimensions();
    Some((rgba.into_raw(), w, h))
}

pub fn rgba_to_image(rgba: &[u8], width: u32, height: u32) -> Image {
    let mut buffer = SharedPixelBuffer::<Rgba8Pixel>::new(width, height);
    buffer.make_mut_bytes().copy_from_slice(rgba);
    Image::from_rgba8(buffer)
}

pub fn window_icon() -> Image {
    match load_icon_rgba(Some(64)) {
        Some((rgba, w, h)) => rgba_to_image(&rgba, w, h),
        None => Image::default(),
    }
}

pub fn qr_image(link: &str) -> Image {
    match crate::qr::render(link, 4, 0) {
        Some(bitmap) => rgba_to_image(&bitmap.rgba, bitmap.width, bitmap.height),
        None => Image::default(),
    }
}
