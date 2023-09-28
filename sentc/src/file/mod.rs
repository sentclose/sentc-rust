#[cfg(feature = "network")]
pub mod downloader_net;
#[cfg(feature = "network")]
pub mod uploader_net;

pub type DefaultCallback = fn(u32);
