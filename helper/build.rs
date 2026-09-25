fn main() {
    println!("cargo:rerun-if-env-changed=KONSOLLINK_TPWS_SHA256");
    println!("cargo:rerun-if-env-changed=KONSOLLINK_PCAP2SOCKS_SHA256");
    let tpws = std::env::var("KONSOLLINK_TPWS_SHA256").unwrap_or_else(|_| {
        "f2749747f9fee28d92bbf149211b21492308c0c9bc6c818a829adc08dd722225".into()
    });
    let gateway = std::env::var("KONSOLLINK_PCAP2SOCKS_SHA256").unwrap_or_else(|_| {
        "0345531054e54fbcb4f66d065a700b3f847b4b4c8ec9a8884f383619d6d046ed".into()
    });
    for (name, value) in [
        ("KONSOLLINK_TPWS_SHA256", tpws),
        ("KONSOLLINK_PCAP2SOCKS_SHA256", gateway),
    ] {
        assert!(value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()));
        println!("cargo:rustc-env={name}={}", value.to_ascii_lowercase());
    }
}
