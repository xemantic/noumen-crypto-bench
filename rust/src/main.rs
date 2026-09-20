/*
 * SPDX-FileCopyrightText: 2026 Kazimierz Pogoda / Xemantic
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * noumen-crypto-bench - benchmarks for noumen's cryptographic primitives
 * Copyright (C) 2026 Kazimierz Pogoda / Xemantic
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! The Rust reference ceiling, on pure-Rust RustCrypto implementations.
//!
//! Like Go, Rust gets the XChaCha20 subkey derivation from its crate graph
//! (`chacha20::hchacha`), where Kotlin/Native must hand-write the permutation
//! because neither OpenSSL 3 nor cryptography-kotlin exposes it.
//!
//! Note that `aes-gcm` here is RustCrypto's portable GHASH, not a hardware
//! backend; a real Rust client should also measure `ring` or `aws-lc-rs`.

use aes_gcm::Aes256Gcm;
use chacha20::cipher::consts::U10;
use chacha20::hchacha;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::Instant;

const CHUNK: usize = 64 * 1024;
const TAG: usize = 16;
const CT_CHUNK: usize = CHUNK + TAG;

fn env(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

fn emit(impl_: &str, suite: &str, algo: &str, pass: &str, param: &str, unit: &str, value: f64) {
    println!("{impl_},{suite},{algo},{pass},{param},{unit},{value:.0}");
}

fn nonce(counter: u64, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[3..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = last as u8;
    n
}

fn chunk_count(size: usize) -> usize { size.div_ceil(CHUNK) }
fn sealed_size(size: usize) -> usize { size + chunk_count(size) * TAG }

fn median(iters: usize, mut pass: impl FnMut() -> f64) -> f64 {
    pass(); // warm-up
    let mut r: Vec<f64> = (0..iters).map(|_| pass()).collect();
    r.sort_by(|a, b| a.partial_cmp(b).unwrap());
    r[iters / 2]
}

/// ChaCha20-Poly1305 and AES-256-GCM share a 12-byte nonce and a 16-byte tag,
/// so a small enum gives the suites uniform dispatch without the generics
/// leaking into every function signature.
enum Cipher {
    ChaCha(ChaCha20Poly1305),
    Aes(Aes256Gcm),
}

impl Cipher {
    fn seal(&self, n: &[u8; 12], data: &mut [u8], tag_out: &mut [u8]) {
        let tag = match self {
            Cipher::ChaCha(c) => c.encrypt_in_place_detached(n.into(), &[], data),
            Cipher::Aes(c) => c.encrypt_in_place_detached(n.into(), &[], data),
        }
        .expect("seal");
        tag_out.copy_from_slice(&tag);
    }

    fn open(&self, n: &[u8; 12], data: &mut [u8], tag: &[u8]) {
        match self {
            Cipher::ChaCha(c) => c.decrypt_in_place_detached(n.into(), &[], data, tag.into()),
            Cipher::Aes(c) => c.decrypt_in_place_detached(n.into(), &[], data, tag.into()),
        }
        .expect("open");
    }
}

struct Algo {
    name: &'static str,
    cipher: Cipher,
}

fn algos(key: &[u8; 32], header: &[u8; 24]) -> Vec<Algo> {
    // The XChaCha20 STREAM framing: one subkey per object, then ordinary
    // ChaCha20-Poly1305 under the counter nonce.
    let subkey = hchacha::<U10>(key.into(), header[..16].into());
    vec![
        Algo { name: "chacha20poly1305", cipher: Cipher::ChaCha(ChaCha20Poly1305::new(key.into())) },
        Algo { name: "aes256gcm", cipher: Cipher::Aes(Aes256Gcm::new(key.into())) },
        Algo { name: "xchacha20poly1305", cipher: Cipher::ChaCha(ChaCha20Poly1305::new(&subkey)) },
    ]
}

fn seeded(seed: u64, buf: &mut [u8]) {
    rand::rngs::StdRng::seed_from_u64(seed).fill_bytes(buf);
}

// ----------------------------------------------------------------- aead suite

// The buffer holds `chunks` slots of CT_CHUNK bytes; the payload lives in the
// first `len` bytes of each slot and the tag after it, which is exactly the
// packed on-disk layout. Work happens in place.

fn encrypt(a: &Cipher, buf: &mut [u8], plain_len: usize) -> f64 {
    let chunks = chunk_count(plain_len);
    let t0 = Instant::now();
    let mut ip = 0usize;
    for i in 0..chunks {
        let len = CHUNK.min(plain_len - ip);
        let off = i * CT_CHUNK;
        let n = nonce(i as u64, i == chunks - 1);
        let (data, tag) = buf[off..off + len + TAG].split_at_mut(len);
        a.seal(&n, data, tag);
        ip += len;
    }
    ip as f64 / 1048576.0 / t0.elapsed().as_secs_f64()
}

fn decrypt(a: &Cipher, buf: &mut [u8], plain_len: usize) -> f64 {
    let chunks = chunk_count(plain_len);
    let t0 = Instant::now();
    let (mut pp, mut processed) = (0usize, 0usize);
    for i in 0..chunks {
        let len = CHUNK.min(plain_len - pp);
        let off = i * CT_CHUNK;
        let n = nonce(i as u64, i == chunks - 1);
        let (data, tag) = buf[off..off + len + TAG].split_at_mut(len);
        a.open(&n, data, tag);
        pp += len;
        processed += len + TAG;
    }
    processed as f64 / 1048576.0 / t0.elapsed().as_secs_f64()
}

/// Lays `plain` out in the slotted buffer the aead suite works in.
fn load(buf: &mut [u8], plain: &[u8]) {
    for (i, c) in plain.chunks(CHUNK).enumerate() {
        let off = i * CT_CHUNK;
        buf[off..off + c.len()].copy_from_slice(c);
    }
}

fn aead_suite(size_mib: usize, iters: usize) {
    let mut plain = vec![0u8; size_mib << 20];
    seeded(42, &mut plain);
    let mut key = [0u8; 32];
    seeded(7, &mut key);
    let mut header = [0u8; 24];
    seeded(11, &mut header);

    let mut buf = vec![0u8; chunk_count(plain.len()) * CT_CHUNK];

    for algo in algos(&key, &header) {
        load(&mut buf, &plain);
        let enc = median(iters, || {
            load(&mut buf, &plain);
            encrypt(&algo.cipher, &mut buf, plain.len())
        });
        let dec = median(iters, || {
            let r = decrypt(&algo.cipher, &mut buf, plain.len());
            encrypt(&algo.cipher, &mut buf, plain.len());
            r
        });
        decrypt(&algo.cipher, &mut buf, plain.len());
        for (i, c) in plain.chunks(CHUNK).enumerate() {
            let off = i * CT_CHUNK;
            assert_eq!(&buf[off..off + c.len()], c, "roundtrip mismatch: {}", algo.name);
        }
        emit("rust", "aead", algo.name, "encrypt", "-", "mib_s", enc);
        emit("rust", "aead", algo.name, "decrypt", "-", "mib_s", dec);
    }

    let h = median(iters, || {
        let t0 = Instant::now();
        Sha256::digest(&plain);
        plain.len() as f64 / 1048576.0 / t0.elapsed().as_secs_f64()
    });
    emit("rust", "aead", "sha256", "hash", "-", "mib_s", h);
}

// --------------------------------------------------------------- stream suite

const SINKS: [&str; 3] = ["null", "file", "pipe"];

struct Sink {
    w: Box<dyn Write>,
    child: Option<Child>,
}

impl Sink {
    fn open(name: &str, dir: &std::path::Path) -> Sink {
        match name {
            "null" => Sink { w: Box::new(File::create("/dev/null").unwrap()), child: None },
            "file" => Sink { w: Box::new(File::create(dir.join("sink.bin")).unwrap()), child: None },
            // A child draining the pipe, modelling a write to object storage.
            "pipe" => {
                let mut c = Command::new("sh")
                    .arg("-c")
                    .arg("cat > /dev/null")
                    .stdin(Stdio::piped())
                    .spawn()
                    .unwrap();
                let stdin = c.stdin.take().unwrap();
                Sink { w: Box::new(stdin), child: Some(c) }
            }
            _ => panic!("unknown sink: {name}"),
        }
    }

    fn finish(mut self) {
        self.w.flush().ok();
        drop(self.w);
        if let Some(mut c) = self.child {
            c.wait().ok();
        }
    }
}

fn create_source(path: &std::path::Path, size: u64) {
    let mut f = File::create(path).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let mut buf = vec![0u8; CHUNK];
    let mut written = 0u64;
    while written < size {
        rng.fill_bytes(&mut buf);
        let n = CHUNK.min((size - written) as usize);
        f.write_all(&buf[..n]).unwrap();
        written += n as u64;
    }
}

/// Reads up to `buf.len()` bytes; returns 0 only at end of file.
fn read_upto(f: &mut File, buf: &mut [u8]) -> usize {
    let mut off = 0;
    while off < buf.len() {
        match f.read(&mut buf[off..]).unwrap() {
            0 => break,
            n => off += n,
        }
    }
    off
}

fn oid_pass(src: &std::path::Path, size: u64, oid: &mut [u8]) -> f64 {
    let mut f = File::open(src).unwrap();
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let t0 = Instant::now();
    loop {
        let n = read_upto(&mut f, &mut buf);
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    oid.copy_from_slice(&h.finalize());
    size as f64 / 1048576.0 / t0.elapsed().as_secs_f64()
}

fn seal_pass(src: &std::path::Path, w: &mut dyn Write, a: &Cipher, size: u64, oid: &mut [u8]) -> f64 {
    let mut f = File::open(src).unwrap();
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CT_CHUNK];
    let chunks = chunk_count(size as usize);
    let t0 = Instant::now();
    let mut i = 0usize;
    loop {
        let n = read_upto(&mut f, &mut buf[..CHUNK]);
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        let nc = nonce(i as u64, i == chunks - 1);
        let (data, tag) = buf[..n + TAG].split_at_mut(n);
        a.seal(&nc, data, tag);
        w.write_all(&buf[..n + TAG]).unwrap();
        i += 1;
    }
    oid.copy_from_slice(&h.finalize());
    size as f64 / 1048576.0 / t0.elapsed().as_secs_f64()
}

fn open_pass(
    sealed: &std::path::Path,
    w: &mut dyn Write,
    a: &Cipher,
    plain_size: u64,
    sealed_bytes: u64,
    oid: &mut [u8],
) -> f64 {
    let mut f = File::open(sealed).unwrap();
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CT_CHUNK];
    let chunks = chunk_count(plain_size as usize);
    let t0 = Instant::now();
    let mut i = 0usize;
    loop {
        let n = read_upto(&mut f, &mut buf);
        if n == 0 {
            break;
        }
        let nc = nonce(i as u64, i == chunks - 1);
        let (data, tag) = buf[..n].split_at_mut(n - TAG);
        a.open(&nc, data, tag);
        h.update(&buf[..n - TAG]);
        w.write_all(&buf[..n - TAG]).unwrap();
        i += 1;
    }
    oid.copy_from_slice(&h.finalize());
    sealed_bytes as f64 / 1048576.0 / t0.elapsed().as_secs_f64()
}

fn stream_suite(size_mib: usize, iters: usize) {
    let size = (size_mib as u64) << 20;
    let dir = std::env::temp_dir().join("noumen-crypto-bench-rust");
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("plain.bin");
    let sealed = dir.join("sealed.bin");
    create_source(&src, size);

    let mut key = [0u8; 32];
    seeded(7, &mut key);
    let mut header = [0u8; 24];
    seeded(11, &mut header);

    let mut plain_oid = [0u8; 32];
    let mut oid = [0u8; 32];
    let sealed_bytes = sealed_size(size as usize) as u64;

    let h = median(iters, || oid_pass(&src, size, &mut plain_oid));
    emit("rust", "stream", "sha256", "oid", "-", "mib_s", h);

    for algo in algos(&key, &header) {
        for name in SINKS {
            let mut s = Sink::open(name, &dir);
            let r = median(iters, || seal_pass(&src, &mut s.w, &algo.cipher, size, &mut oid));
            s.finish();
            assert_eq!(oid, plain_oid, "object id mismatch while sealing {}", algo.name);
            emit("rust", "stream", algo.name, "seal+oid", name, "mib_s", r);
        }

        // A real sealed file, so the open pass reads real input.
        let mut f = File::create(&sealed).unwrap();
        seal_pass(&src, &mut f, &algo.cipher, size, &mut oid);
        drop(f);

        for name in SINKS {
            let mut s = Sink::open(name, &dir);
            let r = median(iters, || {
                open_pass(&sealed, &mut s.w, &algo.cipher, size, sealed_bytes, &mut oid)
            });
            s.finish();
            assert_eq!(oid, plain_oid, "object id mismatch while opening {}", algo.name);
            emit("rust", "stream", algo.name, "open+oid", name, "mib_s", r);
        }
    }

    std::fs::remove_dir_all(&dir).ok();
}

// ------------------------------------------------------------- parallel suite

/// Fans the chunks of `plain` across `workers` threads. Chunk `i` always lands
/// at `i * CT_CHUNK`, so the result is byte-identical to a serial seal.
fn seal_parallel(a: &Cipher, plain: &[u8], out: &mut [u8], workers: usize) -> f64 {
    let chunks = chunk_count(plain.len());
    let per = chunks.div_ceil(workers);
    let t0 = Instant::now();
    std::thread::scope(|scope| {
        for (w, slice) in out.chunks_mut(per * CT_CHUNK).enumerate() {
            let from = w * per;
            scope.spawn(move || {
                for (j, slot) in slice.chunks_mut(CT_CHUNK).enumerate() {
                    let i = from + j;
                    let ip = i * CHUNK;
                    let len = CHUNK.min(plain.len() - ip);
                    slot[..len].copy_from_slice(&plain[ip..ip + len]);
                    let nc = nonce(i as u64, i == chunks - 1);
                    let (data, tag) = slot[..len + TAG].split_at_mut(len);
                    a.seal(&nc, data, tag);
                }
            });
        }
    });
    plain.len() as f64 / 1048576.0 / t0.elapsed().as_secs_f64()
}

fn parallel_suite(size_mib: usize, iters: usize) {
    let mut plain = vec![0u8; size_mib << 20];
    seeded(42, &mut plain);
    let mut key = [0u8; 32];
    seeded(7, &mut key);
    let mut header = [0u8; 24];
    seeded(11, &mut header);

    let mut out = vec![0u8; chunk_count(plain.len()) * CT_CHUNK];
    let mut reference = vec![0u8; chunk_count(plain.len()) * CT_CHUNK];
    let max_workers = env("MAX_WORKERS", 8);

    for algo in algos(&key, &header) {
        load(&mut reference, &plain);
        encrypt(&algo.cipher, &mut reference, plain.len());

        let mut w = 1;
        while w <= max_workers {
            out.fill(0);
            let r = median(iters, || seal_parallel(&algo.cipher, &plain, &mut out, w));
            assert_eq!(out, reference, "parallel output differs from serial: {} at {w}", algo.name);
            emit("rust", "parallel", algo.name, "encrypt", &w.to_string(), "mib_s", r);
            w *= 2;
        }
    }
}

// ---------------------------------------------------------------------- startup

/// What any helper invocation must pay before sealing a byte.
fn crypto_init() {
    let c = ChaCha20Poly1305::new((&[0u8; 32]).into());
    let mut b = [0u8; 16];
    let mut t = [0u8; TAG];
    Cipher::ChaCha(c).seal(&[0u8; 12], &mut b, &mut t);
    Sha256::new();
}

fn main() {
    let suite = std::env::args().nth(1).unwrap_or_else(|| "all".to_string());
    match suite.as_str() {
        "noop" => return,
        "crypto-init" => return crypto_init(),
        "envelope" => return, // carried by the Kotlin/Native binary only
        _ => {}
    }

    let (size_mib, iters) = (env("SIZE_MIB", 256), env("ITERS", 5));
    match suite.as_str() {
        "aead" => aead_suite(size_mib, iters),
        "stream" => stream_suite(size_mib, iters),
        "parallel" => parallel_suite(size_mib, iters),
        "all" => {
            aead_suite(size_mib, iters);
            stream_suite(size_mib, iters);
            parallel_suite(size_mib, iters);
        }
        other => panic!("unknown suite: {other}"),
    }
}
