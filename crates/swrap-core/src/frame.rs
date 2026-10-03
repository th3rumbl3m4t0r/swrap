//! Framed, length-prefixed protocol used between clients, daemons, workers and (later) the link.
//!
//! Wire: `len: u32 BE` (of what follows) · `stream: u32 BE` · `kind: u8` · payload.

use anyhow::{bail, Result};
use std::io::{self, Read, Write};

pub const MAX_FRAME: usize = 1 << 20;

pub mod kind {
    /// JSON request.
    pub const REQ: u8 = 1;
    /// JSON response (final).
    pub const RESP: u8 = 2;
    /// Terminal / stream bytes.
    pub const DATA: u8 = 3;
    /// `{"cols":..,"rows":..}`.
    pub const RESIZE: u8 = 4;
    /// Signal number as u8.
    pub const SIGNAL: u8 = 5;
    /// Exit code as i32 BE, optionally followed by a reason string.
    pub const EXIT: u8 = 6;
    /// JSON `{ "error": .. }`.
    pub const ERR: u8 = 7;
    /// Informational line for the user's stdout.
    pub const STDOUT: u8 = 8;
    /// Informational line for the user's stderr.
    pub const STDERR: u8 = 9;
    /// End of input stream.
    pub const EOF: u8 = 10;
    /// JSON event for shell recorder → daemon.
    pub const EVENT: u8 = 11;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub stream: u32,
    pub kind: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(kind: u8, payload: impl Into<Vec<u8>>) -> Self {
        Frame { stream: 0, kind, payload: payload.into() }
    }
    pub fn json<T: serde::Serialize>(kind: u8, v: &T) -> Self {
        Frame::new(kind, serde_json::to_vec(v).expect("serialize"))
    }
    pub fn parse<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.payload)?)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(9 + self.payload.len());
        v.extend_from_slice(&((5 + self.payload.len()) as u32).to_be_bytes());
        v.extend_from_slice(&self.stream.to_be_bytes());
        v.push(self.kind);
        v.extend_from_slice(&self.payload);
        v
    }
    pub fn exit(code: i32, reason: &str) -> Self {
        let mut p = code.to_be_bytes().to_vec();
        p.extend_from_slice(reason.as_bytes());
        Frame::new(kind::EXIT, p)
    }
    pub fn exit_code(&self) -> (i32, String) {
        if self.payload.len() < 4 {
            return (255, String::new());
        }
        let c = i32::from_be_bytes(self.payload[..4].try_into().unwrap());
        (c, String::from_utf8_lossy(&self.payload[4..]).into_owned())
    }
}

pub fn write_frame<W: Write>(w: &mut W, f: &Frame) -> io::Result<()> {
    w.write_all(&f.encode())?;
    w.flush()
}

/// Read one frame. `Ok(None)` on clean EOF at a frame boundary.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Option<Frame>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if !(5..=MAX_FRAME + 5).contains(&len) {
        bail!("bad frame length {len}");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some(Frame {
        stream: u32::from_be_bytes(buf[..4].try_into().unwrap()),
        kind: buf[4],
        payload: buf[5..].to_vec(),
    }))
}

pub mod aio {
    use super::*;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> io::Result<()> {
        w.write_all(&f.encode()).await?;
        w.flush().await
    }

    pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>> {
        let mut len = [0u8; 4];
        match r.read_exact(&mut len).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_be_bytes(len) as usize;
        if !(5..=MAX_FRAME + 5).contains(&len) {
            bail!("bad frame length {len}");
        }
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf).await?;
        Ok(Some(Frame {
            stream: u32::from_be_bytes(buf[..4].try_into().unwrap()),
            kind: buf[4],
            payload: buf[5..].to_vec(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let f = Frame { stream: 7, kind: kind::DATA, payload: b"abc".to_vec() };
        let mut buf = vec![];
        write_frame(&mut buf, &f).unwrap();
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), f);
        assert!(read_frame(&mut r).unwrap().is_none());
    }
    #[test]
    fn rejects_oversize() {
        let mut buf = ((MAX_FRAME + 100) as u32).to_be_bytes().to_vec();
        buf.extend_from_slice(&[0; 16]);
        assert!(read_frame(&mut &buf[..]).is_err());
    }
}
