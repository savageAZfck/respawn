//! Secured transport for sync: Noise NNpsk0 over TCP.
//!
//! `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` — mutual authentication from
//! a shared passphrase (mixed at position 0, so a wrong-PSK peer cannot
//! complete the handshake) plus forward secrecy from the ephemeral DH
//! exchange. No certificates, no PKI: the passphrase is the credential,
//! which fits "sync between machines I own" exactly.
//!
//! Connection prologue: the client sends `SFAB` + version + mode before
//! anything else. A plaintext client (no --psk) sends nothing and uses
//! the legacy framing — so old peers keep working; a --psk client sends
//! MODE_NOISE and handshakes. A --psk *server* rejects non-selector
//! connections, so security cannot be silently downgraded: the operator
//! on the serving side decides the floor.
//!
//! Transport framing: each app frame is sent as a length header carried
//! inside a Noise message, then Noise messages of <= 48 KiB plaintext.
//! Frame sizes are encrypted too — the wire shows only ciphertext.

use crate::{Error, Result};
use snow::{Builder, HandshakeState, TransportState};
use std::io::{Read, Write};
use std::net::TcpStream;

pub const PROTO_MAGIC: &[u8; 4] = b"SFAB";
pub const PROTO_VERSION: u8 = 2;
pub const MODE_NOISE: u8 = 0x01;

const PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
/// Noise transport messages cap near 64 KiB; 48 KiB leaves headroom.
const PLAINTEXT_MSG: usize = 48 * 1024;
const MAX_HS_MSG: usize = 1024;
const MAX_FRAME: usize = 64 * 1024 * 1024;

/// Derive the 32-byte pre-shared key from a passphrase. Documented as a
/// bearer credential: anyone holding it can authenticate to the fabric.
pub fn derive_psk(passphrase: &str) -> [u8; 32] {
    blake3::derive_key("respawn sync psk v1", passphrase.as_bytes())
}

fn hs_params() -> Result<snow::params::NoiseParams> {
    PARAMS
        .parse()
        .map_err(|e| Error::Sync(format!("noise params: {e:?}")))
}

fn write_msg(s: &mut TcpStream, data: &[u8]) -> Result<()> {
    if data.len() > PLAINTEXT_MSG + 64 {
        return Err(Error::Sync("noise message oversized".into()));
    }
    s.write_all(&(data.len() as u32).to_le_bytes())?;
    s.write_all(data)?;
    Ok(())
}

fn read_msg(s: &mut TcpStream, cap: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    s.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > cap {
        return Err(Error::Sync("noise message length invalid".into()));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

/// Initiator side of NNpsk0: `-> e, psk` then `<- e, ee`.
fn hs_initiator(s: &mut TcpStream, psk: &[u8; 32]) -> Result<TransportState> {
    let mut hs: HandshakeState = hs_params().and_then(|p| {
        Builder::new(p)
            .psk(0, psk)
            .build_initiator()
            .map_err(|e| Error::Sync(format!("noise init: {e}")))
    })?;
    let mut buf = vec![0u8; 1024];
    let n = hs
        .write_message(&[], &mut buf)
        .map_err(|e| Error::Sync(format!("noise write: {e}")))?;
    write_msg(s, &buf[..n])?;
    let reply = read_msg(s, MAX_HS_MSG).map_err(|e| {
        Error::Sync(format!(
            "peer ended the handshake (wrong --psk or unsecured listener?): {e}"
        ))
    })?;
    hs.read_message(&reply, &mut buf)
        .map_err(|e| Error::Sync(format!("noise handshake rejected: {e}")))?;
    hs.into_transport_mode()
        .map_err(|e| Error::Sync(format!("noise transport: {e}")))
}

/// Responder side of NNpsk0.
fn hs_responder(s: &mut TcpStream, psk: &[u8; 32]) -> Result<TransportState> {
    let mut hs: HandshakeState = hs_params().and_then(|p| {
        Builder::new(p)
            .psk(0, psk)
            .build_responder()
            .map_err(|e| Error::Sync(format!("noise init: {e}")))
    })?;
    let mut buf = vec![0u8; 1024];
    let first = read_msg(s, MAX_HS_MSG)?;
    hs.read_message(&first, &mut buf)
        .map_err(|e| Error::Sync(format!("noise handshake rejected: {e}")))?;
    let n = hs
        .write_message(&[], &mut buf)
        .map_err(|e| Error::Sync(format!("noise write: {e}")))?;
    write_msg(s, &buf[..n])?;
    hs.into_transport_mode()
        .map_err(|e| Error::Sync(format!("noise transport: {e}")))
}

/// Frame IO over an encrypted Noise channel. Satisfies the same
/// contract as the legacy plaintext framing so the sync protocol is
/// transport-agnostic.
pub struct SecureStream {
    stream: TcpStream,
    transport: TransportState,
    buf: Vec<u8>,
}

impl SecureStream {
    /// Client path: send the selector, then run the initiator handshake.
    /// The caller has already connected `stream` and set timeouts.
    pub fn connect(mut stream: TcpStream, psk: &[u8; 32]) -> Result<Self> {
        stream.write_all(PROTO_MAGIC)?;
        stream.write_all(&[PROTO_VERSION, MODE_NOISE])?;
        let transport = hs_initiator(&mut stream, psk)?;
        Ok(Self {
            stream,
            transport,
            buf: vec![0u8; PLAINTEXT_MSG + 64],
        })
    }

    /// Server path: the selector was already consumed; finish the
    /// responder handshake on `stream`.
    pub fn accept(mut stream: TcpStream, psk: &[u8; 32]) -> Result<Self> {
        let transport = hs_responder(&mut stream, psk)?;
        Ok(Self {
            stream,
            transport,
            buf: vec![0u8; PLAINTEXT_MSG + 64],
        })
    }

    pub fn read_frame(&mut self) -> Result<Vec<u8>> {
        // First Noise message carries the app-frame length.
        let hdr_ct = read_msg(&mut self.stream, PLAINTEXT_MSG + 64)?;
        let n = self
            .transport
            .read_message(&hdr_ct, &mut self.buf)
            .map_err(|e| Error::Sync(format!("noise decrypt: {e}")))?;
        if n != 4 {
            return Err(Error::Sync("noise frame header malformed".into()));
        }
        let app_len = u32::from_le_bytes(self.buf[..4].try_into().unwrap()) as usize;
        if app_len > MAX_FRAME {
            return Err(Error::Sync("frame too large".into()));
        }
        // A peer can claim a 64 MB frame then trickle — don't reserve
        // the whole claim up front; grow with what actually arrives.
        let mut out = Vec::with_capacity(app_len.min(4 * 1024 * 1024));
        while out.len() < app_len {
            let ct = read_msg(&mut self.stream, PLAINTEXT_MSG + 64)?;
            let n = self
                .transport
                .read_message(&ct, &mut self.buf)
                .map_err(|e| Error::Sync(format!("noise decrypt: {e}")))?;
            if out.len() + n > app_len {
                return Err(Error::Sync("noise frame overflow".into()));
            }
            out.extend_from_slice(&self.buf[..n]);
            if n == 0 {
                return Err(Error::Sync("noise frame stalled".into()));
            }
        }
        Ok(out)
    }

    pub fn write_frame(&mut self, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_FRAME {
            return Err(Error::Sync("frame too large".into()));
        }
        let n = self
            .transport
            .write_message(&(payload.len() as u32).to_le_bytes(), &mut self.buf)
            .map_err(|e| Error::Sync(format!("noise encrypt: {e}")))?;
        write_msg(&mut self.stream, &self.buf[..n])?;
        for chunk in payload.chunks(PLAINTEXT_MSG) {
            let n = self
                .transport
                .write_message(chunk, &mut self.buf)
                .map_err(|e| Error::Sync(format!("noise encrypt: {e}")))?;
            write_msg(&mut self.stream, &self.buf[..n])?;
        }
        Ok(())
    }
}

/// Plaintext frame IO — the legacy transport. Same contract, no crypto;
/// kept so unprotected peers and old binaries still interop when the
/// operator did not ask for security.
pub struct PlainStream {
    pub stream: TcpStream,
}

impl PlainStream {
    pub fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_FRAME {
            return Err(Error::Sync("frame too large".into()));
        }
        // Same trickle guard as the Noise path — grow the buffer as
        // bytes arrive so a peer claiming 64 MB then stalling holds
        // only a small allocation.
        let mut buf = Vec::with_capacity(len.min(4 * 1024 * 1024));
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(256 * 1024);
            let start = buf.len();
            buf.resize(start + n, 0);
            self.stream.read_exact(&mut buf[start..])?;
            remaining -= n;
        }
        Ok(buf)
    }

    pub fn write_frame(&mut self, payload: &[u8]) -> Result<()> {
        self.stream
            .write_all(&(payload.len() as u32).to_le_bytes())?;
        self.stream.write_all(payload)?;
        Ok(())
    }
}

/// Transport-agnostic frame sink/source used by the sync protocol.
pub enum FrameIo {
    Plain(PlainStream),
    Secure(SecureStream),
}

impl FrameIo {
    pub fn read_frame(&mut self) -> Result<Vec<u8>> {
        match self {
            FrameIo::Plain(p) => p.read_frame(),
            FrameIo::Secure(s) => s.read_frame(),
        }
    }
    pub fn write_frame(&mut self, payload: &[u8]) -> Result<()> {
        match self {
            FrameIo::Plain(p) => p.write_frame(payload),
            FrameIo::Secure(s) => s.write_frame(payload),
        }
    }
}
