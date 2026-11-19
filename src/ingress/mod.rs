mod h3;
mod quic;
mod udp;

#[cfg(target_os = "linux")]
mod tun;
#[cfg(target_os = "linux")]
mod wireguard;

pub use h3::send_h3;
#[cfg(target_os = "linux")]
pub use tun::serve_tun;
pub use udp::serve_h3;
#[cfg(target_os = "linux")]
pub use wireguard::serve_wireguard;

#[cfg(not(target_os = "linux"))]
pub async fn serve_tun(_: std::sync::Arc<crate::App>, _: &str) -> anyhow::Result<()> {
    anyhow::bail!("TUN ingress requires Linux")
}

#[cfg(not(target_os = "linux"))]
pub async fn serve_wireguard(
    _: std::sync::Arc<crate::App>,
    _: std::net::SocketAddr,
    _: &std::path::Path,
) -> anyhow::Result<()> {
    anyhow::bail!("WireGuard ingress requires Linux")
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
