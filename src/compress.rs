use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Read, Write};

/// Compress data with gzip. Returns compressed bytes.
pub fn gzip_maybe(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    if encoder.write_all(data).is_err() {
        return data.to_vec();
    }
    encoder.finish().unwrap_or_else(|_| data.to_vec())
}

/// Decompress gzip data. Returns decompressed bytes, or original if decompression fails.
pub fn gunzip_maybe(data: &[u8]) -> Vec<u8> {
    let mut decoder = GzDecoder::new(data);
    let mut buf = Vec::new();
    if decoder.read_to_end(&mut buf).is_ok() {
        return buf;
    }
    data.to_vec()
}
