//! Content-addressed object store.
//!
//! Objects are zstd-compressed blobs keyed by BLAKE3 hash of their
//! *uncompressed* bytes, fanned out into `objects/<2-hex>/<62-hex>`.
//! Writes are atomic (tmp + rename). Reads verify the hash, so a
//! corrupted or tampered object is detected on access, not on audit.

use crate::{hash_bytes, Error, Hash, Result, FABRIC_DIR};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub struct Store {
    root: PathBuf, // worktree root
}

impl Store {
    /// Initialize a new fabric inside `root`.
    pub fn init(root: &Path) -> Result<Self> {
        let dir = root.join(FABRIC_DIR);
        fs::create_dir_all(dir.join("objects"))?;
        fs::create_dir_all(dir.join("manifests"))?;
        if !dir.join("HEAD").exists() {
            fs::write(dir.join("HEAD"), "")?;
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Open an existing fabric.
    pub fn open(root: &Path) -> Result<Self> {
        let dir = root.join(FABRIC_DIR);
        if !dir.join("objects").is_dir() {
            return Err(Error::NotInitialized);
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Find the worktree root by walking up from `start`.
    pub fn find_root(start: &Path) -> Result<PathBuf> {
        let mut cur = start.canonicalize().map_err(|_| Error::NotInitialized)?;
        loop {
            if cur.join(FABRIC_DIR).join("objects").is_dir() {
                return Ok(cur);
            }
            if !cur.pop() {
                return Err(Error::NotInitialized);
            }
        }
    }

    pub fn fabric_dir(&self) -> PathBuf {
        self.root.join(FABRIC_DIR)
    }

    fn object_path(&self, h: &Hash) -> PathBuf {
        let hex = crate::hash_hex(h);
        self.fabric_dir()
            .join("objects")
            .join(&hex[..2])
            .join(&hex[2..])
    }

    fn manifest_path(&self, h: &Hash) -> PathBuf {
        let hex = crate::hash_hex(h);
        self.fabric_dir()
            .join("manifests")
            .join(&hex[..2])
            .join(&hex[2..])
    }

    /// Store bytes, returning the content hash. Idempotent.
    pub fn put_object(&self, data: &[u8]) -> Result<Hash> {
        let h = hash_bytes(data);
        let path = self.object_path(&h);
        if path.exists() {
            return Ok(h);
        }
        let compressed = zstd::encode_all(data, 3).map_err(Error::Io)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&compressed)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        Ok(h)
    }

    /// Store raw bytes pre-hashed by the caller (used by sync: the hash
    /// arrives over the wire, content is verified before accepting).
    pub fn put_object_as(&self, h: &Hash, data: &[u8]) -> Result<()> {
        if hash_bytes(data) != *h {
            return Err(Error::Corrupt(format!(
                "object {} failed content verification",
                crate::short(h)
            )));
        }
        self.put_object(data)?;
        Ok(())
    }

    /// Read and decompress an object; verifies content hash on read.
    pub fn get_object(&self, h: &Hash) -> Result<Vec<u8>> {
        let path = self.object_path(h);
        let compressed = fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::MissingObject(*h)
            } else {
                Error::Io(e)
            }
        })?;
        let data = zstd::decode_all(&compressed[..]).map_err(Error::Io)?;
        if hash_bytes(&data) != *h {
            return Err(Error::Corrupt(format!(
                "object {} failed content verification",
                crate::short(h)
            )));
        }
        Ok(data)
    }

    pub fn has_object(&self, h: &Hash) -> bool {
        self.object_path(h).exists()
    }

    /// Store a serialized manifest; returns its snapshot id.
    pub fn put_manifest(&self, data: &[u8]) -> Result<Hash> {
        let h = hash_bytes(data);
        let path = self.manifest_path(&h);
        if path.exists() {
            return Ok(h);
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, data)?;
        fs::rename(&tmp, &path)?;
        Ok(h)
    }

    /// Store manifest bytes under a caller-supplied id (sync path).
    pub fn put_manifest_as(&self, h: &Hash, data: &[u8]) -> Result<()> {
        if hash_bytes(data) != *h {
            return Err(Error::Corrupt("manifest hash mismatch".into()));
        }
        self.put_manifest(data)?;
        Ok(())
    }

    pub fn get_manifest_bytes(&self, h: &Hash) -> Result<Vec<u8>> {
        let path = self.manifest_path(h);
        fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::MissingObject(*h)
            } else {
                Error::Io(e)
            }
        })
    }

    pub fn has_manifest(&self, h: &Hash) -> bool {
        self.manifest_path(h).exists()
    }

    /// Current HEAD snapshot id, if any.
    pub fn head(&self) -> Result<Option<Hash>> {
        let s = fs::read_to_string(self.fabric_dir().join("HEAD")).unwrap_or_default();
        let s = s.trim();
        if s.is_empty() {
            Ok(None)
        } else {
            Ok(Some(crate::parse_hash(s)?))
        }
    }

    /// Swap HEAD — the O(1) part of "undo".
    pub fn set_head(&self, h: Option<&Hash>) -> Result<()> {
        let content = match h {
            Some(h) => crate::hash_hex(h),
            None => String::new(),
        };
        let tmp = self.fabric_dir().join("HEAD.tmp");
        fs::write(&tmp, content)?;
        fs::rename(&tmp, self.fabric_dir().join("HEAD"))?;
        Ok(())
    }

    /// Read a stream of bytes and hash them without loading the file
    /// fully into memory.
    pub fn hash_reader<R: Read>(mut r: R) -> Result<(Hash, u64)> {
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total += n as u64;
        }
        Ok((*hasher.finalize().as_bytes(), total))
    }
}
