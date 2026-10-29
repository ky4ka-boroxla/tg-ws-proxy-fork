fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }
    println!("cargo:rerun-if-changed=ui");
    println!("cargo:rerun-if-changed=icon.ico");
    let config = slint_build::CompilerConfiguration::new()
        .with_style("fluent".into())
        .embed_resources(slint_build::EmbedResourcesKind::EmbedFiles);
    slint_build::compile_with_config("ui/app.slint", config).expect("slint compile");

    let mut resource = winresource::WindowsResource::new();
    resource.set_icon("icon.ico");
    resource.set("ProductName", "TG WS Proxy");
    resource.set("FileDescription", "Telegram MTProto WebSocket bridge proxy");
    resource.set("OriginalFilename", "TgWsProxy.exe");
    resource.compile().expect("windows resources");
}
