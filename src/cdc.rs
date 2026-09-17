//! Content-defined chunking (FastCDC).
//!
//! Cut points are derived from content, not position: a byte inserted
//! at the front of a file shifts one boundary instead of invalidating
//! every downstream chunk, so dedup survives edits that fixed-size
//! chunking cannot. Normalized chunking (level 2) keeps sizes clustered
//! near CDC_AVG; CDC_MIN/CDC_MAX bound the tails.
//!
//! Chunk boundaries are implicit in the object set — manifests record
//! only the ordered hash list, so changing the splitter does not change
//! the manifest format. Legacy fixed-chunk objects remain readable.

use crate::{Error, Result, CDC_AVG, CDC_MAX, CDC_MIN};
use std::io::Read;

/// Split `data` into content-defined chunks. Each chunk is handed to
/// `Store::put_object` by the caller; sizes stay inside [CDC_MIN, CDC_MAX].
pub fn chunk_bytes(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let cdc = fastcdc::v2020::FastCDC::with_level(
        data,
        CDC_MIN as u32,
        CDC_AVG as u32,
        CDC_MAX as u32,
        fastcdc::v2020::Normalization::Level2,
    );
    Ok(cdc
        .map(|c| data[c.offset..c.offset + c.length].to_vec())
        .collect())
}

/// Stream a file through the chunker without holding the whole file in
/// memory — same cut points, bounded by CDC_MAX per yielded chunk.
pub struct Chunker<R: Read> {
    inner: fastcdc::v2020::StreamCDC<R>,
}

impl<R: Read> Chunker<R> {
    pub fn new(source: R) -> Self {
        Self {
            inner: fastcdc::v2020::StreamCDC::with_level(
                source,
                CDC_MIN as u32,
                CDC_AVG as u32,
                CDC_MAX as u32,
                fastcdc::v2020::Normalization::Level2,
            ),
        }
    }
}

impl<R: Read> Iterator for Chunker<R> {
    type Item = Result<Vec<u8>>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|r| {
            r.map(|c| c.data)
                .map_err(|e| Error::Io(std::io::Error::other(e)))
        })
    }
}
