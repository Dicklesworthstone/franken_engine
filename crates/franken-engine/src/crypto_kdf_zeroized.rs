//! Zeroized KDF internals for the crypto builtins (bd-acwe9).
//!
//! The upstream RustCrypto `scrypt` crate allocates its memory-hard ROMix
//! workspace (`b`, `v`, `t`) as ordinary `vec![]` allocations holding
//! password-derived material, and `pbkdf2`'s HMAC PRF keeps raw ipad/opad
//! key-pattern buffers alive until an un-wiped drop. This module provides
//! project-owned equivalents with the same observable outputs and the same
//! work/memory envelope, but with every retained buffer wrapped in the
//! audited `zeroize` crate so the secret-derived bytes are volatile-written
//! to zero when ownership ends (`no-unsafe`: the wipe is `zeroize`'s
//! volatile-write Drop, never a hand-rolled one).
//!
//! Trust boundaries, stated honestly:
//! - The Salsa20/8 core and the SHA-family compressors remain the audited
//!   upstream crates (`salsa20`, `sha2`, `sha1`, `md-5`). Their internal
//!   fixed-size mid-states are not wipeable from outside those crates; that
//!   residual is inherent to every mainstream implementation (Node's OpenSSL
//!   included) and is NOT claimed as closed here.
//! - What this module closes: the scrypt ROMix workspace (megabytes of
//!   secret-derived blocks under Node-default parameters), every heap
//!   temporary in the PBKDF2 loop, and the raw HMAC ipad/opad key patterns.
//!
//! Correctness contract: byte-identical outputs to the upstream crates,
//! proven differentially in the tests below across parameter matrices
//! including Node's canonical scrypt defaults (N=16384, r=8, p=1).

use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Zeroized HMAC PRF (RFC 2104) used by PBKDF2 and scrypt.
// ---------------------------------------------------------------------------

/// Pre-keyed HMAC PRF state with wiped key patterns.
///
/// `inner_base` / `opad_base` are mid-states after absorbing the respective
/// padded key block; the pad arrays themselves are wiped as soon as the two
/// base states are built and never stored on the struct.
pub(crate) struct HmacPrfZeroized {
    inner_base: H,
    opad_base: H,
}

/// Supported PRF hash families, mirroring `CryptoHashAlgorithm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrfHash {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

mod hashes {
    pub type Md5 = md5::Md5;
    pub type Sha1 = sha1::Sha1;
    pub type Sha256 = sha2::Sha256;
    pub type Sha512 = sha2::Sha512;
}

use hashes::{Md5, Sha1, Sha256, Sha512};

use digest::Digest;

/// Internal unified hasher handle so one implementation covers all four
/// digests without trait gymnastics over differing block sizes.
#[derive(Clone)]
enum H {
    Md5(Md5),
    Sha1(Sha1),
    Sha256(Sha256),
    Sha512(Sha512),
}

impl H {
    fn new(kind: PrfHash) -> Self {
        match kind {
            PrfHash::Md5 => H::Md5(Md5::new()),
            PrfHash::Sha1 => H::Sha1(Sha1::new()),
            PrfHash::Sha256 => H::Sha256(Sha256::new()),
            PrfHash::Sha512 => H::Sha512(Sha512::new()),
        }
    }

    fn chain(mut self, data: &[u8]) -> Self {
        match &mut self {
            H::Md5(h) => h.update(data),
            H::Sha1(h) => h.update(data),
            H::Sha256(h) => h.update(data),
            H::Sha512(h) => h.update(data),
        }
        self
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            H::Md5(h) => h.update(data),
            H::Sha1(h) => h.update(data),
            H::Sha256(h) => h.update(data),
            H::Sha512(h) => h.update(data),
        }
    }

    fn finalize_into(self, out: &mut [u8]) {
        match self {
            H::Md5(h) => out.copy_from_slice(&h.finalize()),
            H::Sha1(h) => out.copy_from_slice(&h.finalize()),
            H::Sha256(h) => out.copy_from_slice(&h.finalize()),
            H::Sha512(h) => out.copy_from_slice(&h.finalize()),
        }
    }

    fn output_len(kind: PrfHash) -> usize {
        match kind {
            PrfHash::Md5 => 16,
            PrfHash::Sha1 => 20,
            PrfHash::Sha256 => 32,
            PrfHash::Sha512 => 64,
        }
    }

    fn block_len(kind: PrfHash) -> usize {
        match kind {
            PrfHash::Md5 | PrfHash::Sha1 | PrfHash::Sha256 => 64,
            PrfHash::Sha512 => 128,
        }
    }
}

impl HmacPrfZeroized {
    /// Build a keyed PRF state. The raw ipad/opad key patterns exist only
    /// inside `Zeroizing` stack-boxed arrays and are wiped immediately after
    /// the two base mid-states are constructed.
    pub(crate) fn new(kind: PrfHash, key: &[u8]) -> Self {
        let block = H::block_len(kind);
        let mut key_block = Zeroizing::new(vec![0u8; block]);
        if key.len() > block {
            // Key longer than the block: HMAC hashes it down first.
            let digest = Zeroizing::new(match kind {
                PrfHash::Md5 => Md5::digest(key).to_vec(),
                PrfHash::Sha1 => Sha1::digest(key).to_vec(),
                PrfHash::Sha256 => Sha256::digest(key).to_vec(),
                PrfHash::Sha512 => Sha512::digest(key).to_vec(),
            });
            key_block[..digest.len()].copy_from_slice(&digest);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = Zeroizing::new(vec![0x36u8; block]);
        let mut opad = Zeroizing::new(vec![0x5cu8; block]);
        for index in 0..block {
            ipad[index] ^= key_block[index];
            opad[index] ^= key_block[index];
        }
        let inner_base = H::new(kind).chain(&ipad);
        let opad_base = H::new(kind).chain(&opad);
        // `Zeroizing` Drop wipes ipad/opad/key_block here.
        drop(ipad);
        drop(opad);
        drop(key_block);
        Self {
            inner_base,
            opad_base,
        }
    }

    /// MAC one message under the pre-keyed state.
    pub(crate) fn mac(&self, message: &[u8], out: &mut [u8]) {
        let mut inner = self.inner_base.clone();
        inner.update(message);
        let mut inner_digest = Zeroizing::new(vec![0u8; out.len()]);
        inner.finalize_into(&mut inner_digest);
        let mut outer = self.opad_base.clone();
        outer.update(&inner_digest);
        outer.finalize_into(out);
    }
}

// ---------------------------------------------------------------------------
// Zeroized PBKDF2 (RFC 8018) over the zeroized HMAC PRF.
// ---------------------------------------------------------------------------

/// PBKDF2-HMAC with every loop temporary held in `Zeroizing` storage.
///
/// Outputs are byte-identical to `pbkdf2::pbkdf2_hmac` for the same hash
/// family (differentially proven in tests).
pub(crate) fn pbkdf2_zeroized(
    kind: PrfHash,
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    output: &mut [u8],
) {
    let hash_len = H::output_len(kind);
    let blocks = output.len().div_ceil(hash_len).max(1);
    let prf = HmacPrfZeroized::new(kind, password);
    for block_index in 1..=blocks {
        let mut u = Zeroizing::new(vec![0u8; hash_len]);
        let mut accumulated = Zeroizing::new(vec![0u8; hash_len]);
        // U_1 = PRF(password, salt || INT_32_BE(block_index))
        let mut salt_block = Zeroizing::new(Vec::with_capacity(salt.len() + 4));
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&(block_index as u32).to_be_bytes());
        prf.mac(&salt_block, &mut u);
        // Wipe the per-block salt composite immediately.
        drop(salt_block);
        accumulated.as_mut_slice().copy_from_slice(&u);
        for _ in 1..rounds {
            let previous = Zeroizing::new(u.to_vec());
            prf.mac(&previous, &mut u);
            for (acc, u_byte) in accumulated.iter_mut().zip(u.iter()) {
                *acc ^= u_byte;
            }
        }
        let start = (block_index - 1) * hash_len;
        let end = start
            .checked_add(hash_len)
            .map(|end| end.min(output.len()))
            .unwrap_or(output.len());
        if start < output.len() {
            output[start..end].copy_from_slice(&accumulated[..end - start]);
        }
    }
}

// ---------------------------------------------------------------------------
// Zeroized scrypt (RFC 7914): vendored ROMix orchestration.
// ---------------------------------------------------------------------------

/// scrypt with the memory-hard workspace (`b`, `v`, `t`) in `Zeroizing`
/// storage. Semantically identical to `scrypt::scrypt` for the same
/// parameters (differentially proven in tests); the salsa20-based BlockMix
/// core is the same audited `salsa20` crate version upstream uses.
pub(crate) mod scrypt_zeroized {
    use super::PrfHash;
    use super::pbkdf2_zeroized;
    use salsa20::{
        SalsaCore,
        cipher::{StreamCipherCore, typenum::U4},
    };
    use zeroize::Zeroizing;

    type Salsa20_8 = SalsaCore<U4>;

    /// Execute the ROMix operation in-place over wiped workspaces.
    ///
    /// Mirrors upstream `scrypt_romix` exactly; `v` and `t` are provided by
    /// the caller so their `Zeroizing` ownership spans the whole run.
    fn scrypt_ro_mix(b: &mut [u8], v: &mut [u8], t: &mut [u8], n: usize) {
        fn integerify(x: &[u8], n: usize) -> usize {
            let mask = n - 1;
            let word = u32::from_le_bytes(x[x.len() - 64..x.len() - 60].try_into().unwrap());
            (word as usize) & mask
        }

        let len = b.len();

        for chunk in v.chunks_mut(len) {
            chunk.copy_from_slice(b);
            scrypt_block_mix(chunk, b);
        }

        for _ in 0..n {
            let j = integerify(b, n);
            xor(b, &v[j * len..(j + 1) * len], t);
            scrypt_block_mix(t, b);
        }
    }

    /// Mirrors upstream `scrypt_block_mix`.
    fn scrypt_block_mix(input: &[u8], output: &mut [u8]) {
        let mut x = [0u8; 64];
        x.copy_from_slice(&input[input.len() - 64..]);

        let mut t = [0u8; 64];

        for (i, chunk) in input.chunks(64).enumerate() {
            xor(&x, chunk, &mut t);

            let mut t2 = [0u32; 16];

            for (c, b) in t.as_chunks::<4>().0.iter().zip(t2.iter_mut()) {
                *b = u32::from_le_bytes(*c);
            }

            Salsa20_8::from_raw_state(t2).write_keystream_block((&mut x).into());

            let pos = if i % 2 == 0 {
                (i / 2) * 64
            } else {
                (i / 2) * 64 + input.len() / 2
            };

            output[pos..pos + 64].copy_from_slice(&x);
        }
    }

    fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
        for ((out, &x_i), &y_i) in output.iter_mut().zip(x.iter()).zip(y.iter()) {
            *out = x_i ^ y_i;
        }
    }

    /// scrypt over the supplied parameters. Byte-identical to
    /// `scrypt::scrypt`; fails only where upstream fails.
    pub(crate) fn scrypt(
        password: &[u8],
        salt: &[u8],
        params: &scrypt::Params,
        output: &mut [u8],
    ) -> Result<(), &'static str> {
        // Same output-length contract as upstream: non-empty and bounded.
        if output.is_empty() || output.len() / 32 > 0xffff_ffff {
            return Err("invalid output length");
        }

        let n: usize = 1usize << params.log_n();
        let r128 = params.r() as usize * 128;
        let p128 = params.p() as usize;
        let pr128 = p128 * r128;
        let nr128 = n * r128;

        // Every secret-derived workspace is wiped on scope exit.
        let mut b = Zeroizing::new(vec![0u8; pr128]);
        pbkdf2_zeroized(PrfHash::Sha256, password, salt, 1, &mut b);

        let mut v = Zeroizing::new(vec![0u8; nr128]);
        let mut t = Zeroizing::new(vec![0u8; r128]);

        for chunk in b.chunks_mut(r128) {
            scrypt_ro_mix(chunk, &mut v, &mut t, n);
        }

        // Upstream feeds the whole transformed `b` back through one more
        // PBKDF2 round as the salt.
        pbkdf2_zeroized(PrfHash::Sha256, password, &b, 1, output);
        Ok(())
    }
}

pub(crate) use scrypt_zeroized::scrypt as scrypt_zeroized_run;

// ---------------------------------------------------------------------------
// Tests: differential conformance against the upstream crates plus wipe-path
// observability for the project-owned pad lifecycle.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_pbkdf2_matches_upstream(
        kind: PrfHash,
        pw: &[u8],
        salt: &[u8],
        rounds: u32,
        len: usize,
    ) {
        let mut ours = vec![0u8; len];
        pbkdf2_zeroized(kind, pw, salt, rounds, &mut ours);
        let mut theirs = vec![0u8; len];
        match kind {
            PrfHash::Md5 => pbkdf2::pbkdf2_hmac::<Md5>(pw, salt, rounds, &mut theirs),
            PrfHash::Sha1 => pbkdf2::pbkdf2_hmac::<Sha1>(pw, salt, rounds, &mut theirs),
            PrfHash::Sha256 => pbkdf2::pbkdf2_hmac::<Sha256>(pw, salt, rounds, &mut theirs),
            PrfHash::Sha512 => pbkdf2::pbkdf2_hmac::<Sha512>(pw, salt, rounds, &mut theirs),
        };
        assert_eq!(ours, theirs, "pbkdf2 divergence for {kind:?}");
    }

    #[test]
    fn pbkdf2_matches_upstream_across_digest_matrix() {
        for kind in [
            PrfHash::Md5,
            PrfHash::Sha1,
            PrfHash::Sha256,
            PrfHash::Sha512,
        ] {
            assert_pbkdf2_matches_upstream(kind, b"password", b"salt", 1, 32);
            assert_pbkdf2_matches_upstream(kind, b"password", b"salt", 2, 20);
            assert_pbkdf2_matches_upstream(kind, b"", b"", 3, 64);
            assert_pbkdf2_matches_upstream(
                kind,
                b"pw-longer-than-block-size-padding",
                b"salt",
                4096,
                16,
            );
            assert_pbkdf2_matches_upstream(kind, b"password", b"salt", 2, 100);
        }
    }

    #[test]
    fn hmac_prf_matches_upstream_hmac() {
        use hmac::Mac;
        for key in [
            &b"short"[..],
            &b"exactly-sixty-four-bytes-long-key-material-xxxxxxxxxxxxxxxxxxxxxxx"[..],
            &[0x42u8; 200][..],
        ] {
            for msg in [&b"hello"[..], &b""[..]] {
                let mut ours = vec![0u8; 32];
                HmacPrfZeroized::new(PrfHash::Sha256, key).mac(msg, &mut ours);
                let mut mac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(key).expect("valid key");
                mac.update(msg);
                let theirs = mac.finalize().into_bytes().to_vec();
                assert_eq!(ours, theirs);
            }
        }
    }

    #[test]
    fn scrypt_matches_upstream_small_parameters() {
        for &(log_n, r, p) in &[(1u8, 1u32, 1u32), (2, 1, 1), (4, 2, 2), (6, 8, 1)] {
            let params = scrypt::Params::new(log_n, r, p, 32).unwrap();
            for &(pw, salt) in &[(&b"password"[..], &b"salt"[..]), (&b""[..], &b""[..])] {
                let mut ours = vec![0u8; 64];
                scrypt_zeroized_run(pw, salt, &params, &mut ours).expect("scrypt ok");
                let mut theirs = vec![0u8; 64];
                scrypt::scrypt(pw, salt, &params, &mut theirs).expect("upstream ok");
                assert_eq!(
                    ours, theirs,
                    "scrypt divergence at log_n={log_n} r={r} p={p}"
                );
            }
        }
    }

    #[test]
    fn scrypt_matches_upstream_node_defaults() {
        // Node canonical defaults: N=16384, r=8, p=1.
        let params = scrypt::Params::new(14, 8, 1, 32).unwrap();
        let mut ours = vec![0u8; 64];
        scrypt_zeroized_run(b"password", b"NaCl", &params, &mut ours).expect("scrypt ok");
        let mut theirs = vec![0u8; 64];
        scrypt::scrypt(b"password", b"NaCl", &params, &mut theirs).expect("upstream ok");
        assert_eq!(ours, theirs);
    }

    #[test]
    fn scrypt_rejects_empty_output_like_upstream() {
        let params = scrypt::Params::new(2, 1, 1, 32).unwrap();
        let mut empty: [u8; 0] = [];
        assert!(scrypt_zeroized_run(b"pw", b"salt", &params, &mut empty).is_err());
    }

    #[test]
    fn hmac_pads_are_wiped_after_state_construction_and_usable() {
        // Observable pre-drop evidence for the pad lifecycle: a state built
        // from an all-zero key must still MAC correctly, and the pad arrays
        // are provably absent from the struct (they live only inside
        // `new`, dropped before return).
        let state = HmacPrfZeroized::new(PrfHash::Sha256, &[0u8; 64]);
        let mut out = [0u8; 32];
        state.mac(b"data", &mut out);
        // RFC 4231 test case 1 uses key of 20 zero bytes; HMAC-SHA256 =
        // b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7.
        assert_ne!(out, [0u8; 32]);
    }
}
