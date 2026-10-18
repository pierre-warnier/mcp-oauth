//! Owner password verification with bounded memory.
//!
//! One argon2id verification needs `m` KiB of working memory (19 MiB with the
//! parameters of [`crate::hash_password`]). Unbounded, N concurrent wrong
//! passwords cost N x 19 MiB: a few dozen requests from distinct IPs (the
//! per-IP ban does not help, every IP is new) exceed a 128 MiB container.
//!
//! So at most `max` verifications run at once ([`OwnerPassword::try_slot`]);
//! a login that finds no free slot is answered at once (503, see
//! `authorize_post`), never queued. Each slot owns one working buffer that is
//! allocated on first use and then reused: the argon2 memory of the whole
//! process is at most `max` x `m` KiB, for good, whatever the allocator
//! does. Freed after each check, a buffer may stay in a glibc malloc arena
//! (the mmap threshold rises to the size of the first freed 19 MiB chunk),
//! and how much stays then depends on the number of arenas. Measured on
//! a glibc 2.41, 20-core server (distinct IPs): unbounded, 60 concurrent
//! wrong passwords peaked at 644 MiB and kept 643 MiB; bounded to 2, 3600
//! checks kept 49-53 MiB over base with either kind of buffer. See the
//! README.

use argon2::{Algorithm, Argon2, Block, Params, PasswordHash, Version};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

/// Default number of owner password verifications running at once.
pub const DEFAULT_MAX_PASSWORD_CHECKS: usize = 2;

/// The parsed owner password hash and the pool of argon2 working buffers.
pub(crate) struct OwnerPassword {
    argon2: Argon2<'static>,
    salt: Vec<u8>,
    expected: Vec<u8>,
    /// Working memory of one verification, in 1 KiB blocks.
    blocks: usize,
    max: AtomicUsize,
    pool: Mutex<Pool>,
}

#[derive(Default)]
struct Pool {
    /// Verifications running now.
    busy: usize,
    /// Buffers not in use (allocated once, kept for the next verification).
    free: Vec<Vec<Block>>,
}

/// Permission to run one verification, with its working buffer; returns the
/// buffer to the pool when dropped (also when the verification panicked or
/// the request was cancelled meanwhile: the slot lives in the blocking task).
pub(crate) struct Slot {
    pw: Arc<OwnerPassword>,
    buf: Option<Vec<Block>>,
}

impl OwnerPassword {
    /// Parse an argon2id PHC string (`$argon2id$v=19$m=..,t=..,p=..$salt$hash`).
    pub(crate) fn new(hash: &str, max: usize) -> Result<Self, String> {
        let h = PasswordHash::new(hash)
            .map_err(|e| format!("owner password hash is not a PHC string: {e}"))?;
        if h.algorithm != argon2::ARGON2ID_IDENT {
            return Err(format!(
                "owner password hash must be argon2id, got {}",
                h.algorithm
            ));
        }
        let version = match h.version {
            Some(v) => Version::try_from(v)
                .map_err(|e| format!("owner password hash: argon2 version {v}: {e}"))?,
            None => Version::default(),
        };
        // Includes output_len = length of the stored hash.
        let params =
            Params::try_from(&h).map_err(|e| format!("owner password hash: parameters: {e}"))?;
        let salt = h
            .salt
            .as_ref()
            .ok_or("owner password hash has no salt")?
            .as_ref()
            .to_vec();
        let expected = h
            .hash
            .as_ref()
            .ok_or("owner password hash has no hash value")?
            .as_bytes()
            .to_vec();
        let blocks = params.block_count();
        Ok(Self {
            argon2: Argon2::new(Algorithm::Argon2id, version, params),
            salt,
            expected,
            blocks,
            max: AtomicUsize::new(max.max(1)),
            pool: Mutex::default(),
        })
    }

    /// Working memory of one verification in bytes.
    #[cfg(test)]
    pub(crate) fn memory_bytes(&self) -> usize {
        self.blocks * Block::SIZE
    }

    pub(crate) fn set_max(&self, max: usize) {
        self.max.store(max.max(1), Ordering::Relaxed);
    }

    pub(crate) fn max(&self) -> usize {
        self.max.load(Ordering::Relaxed)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Pool> {
        // The pool holds no invariant a panic could break halfway.
        self.pool.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A free slot, or `None` when `max` verifications are running.
    pub(crate) fn try_slot(self: &Arc<Self>) -> Option<Slot> {
        let mut p = self.lock();
        if p.busy >= self.max() {
            return None;
        }
        p.busy += 1;
        let buf = p.free.pop();
        Some(Slot {
            pw: self.clone(),
            buf,
        })
    }

    /// (busy, pooled buffers): for tests.
    #[cfg(test)]
    pub(crate) fn usage(&self) -> (usize, usize) {
        let p = self.lock();
        (p.busy, p.free.len())
    }
}

impl Slot {
    /// argon2id of `password` with the stored parameters and salt, compared
    /// in constant time with the stored hash. CPU-bound (tens of ms): call it
    /// from a blocking thread.
    pub(crate) fn verify(mut self, password: &str) -> bool {
        let pw = self.pw.clone();
        let buf = self
            .buf
            .get_or_insert_with(|| vec![Block::new(); pw.blocks]);
        let mut out = vec![0u8; pw.expected.len()];
        pw.argon2
            .hash_password_into_with_memory(password.as_bytes(), &pw.salt, &mut out, &mut buf[..])
            .is_ok()
            && bool::from(out.ct_eq(&pw.expected))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut p = self.pw.lock();
        p.busy -= 1;
        // Keep at most `max` buffers (fewer if `max` was lowered meanwhile).
        if let Some(b) = self.buf.take()
            && p.busy + p.free.len() < self.pw.max()
        {
            p.free.push(b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::PasswordHasher;

    fn verify(pw: &Arc<OwnerPassword>, password: &str) -> bool {
        pw.try_slot().expect("free slot").verify(password)
    }

    /// Same answers as the argon2 crate's own verifier, for the default
    /// parameters and for unusual ones (p > 1, long output, odd m).
    #[test]
    fn matches_argon2_verify_password() {
        use argon2::PasswordVerifier;
        let custom = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(1000, 3, 3, Some(48)).unwrap(),
        );
        let hashes = [
            crate::hash_password("correct horse").unwrap(),
            custom.hash_password(b"correct horse").unwrap().to_string(),
        ];
        for h in &hashes {
            let pw = Arc::new(OwnerPassword::new(h, 2).unwrap());
            for (cand, want) in [
                ("correct horse", true),
                ("correct horsE", false),
                ("", false),
                ("correct horse ", false),
            ] {
                let theirs = Argon2::default()
                    .verify_password(cand.as_bytes(), &PasswordHash::new(h).unwrap())
                    .is_ok();
                assert_eq!(theirs, want, "{h} {cand:?}");
                assert_eq!(verify(&pw, cand), want, "{h} {cand:?}");
                // Twice: a reused (dirty) buffer gives the same answer.
                assert_eq!(verify(&pw, cand), want, "{h} {cand:?} again");
            }
        }
        let pw = OwnerPassword::new(&hashes[1], 2).unwrap();
        assert_eq!(
            pw.memory_bytes(),
            996 * 1024,
            "m=1000, p=3: 4 x 3 segments of 83 blocks"
        );
    }

    /// An independent implementation: the reference C implementation
    /// (phc-winner-argon2, as bundled by argon2-cffi 25.1:
    /// `argon2.low_level.hash_secret(b"correct horse", b"somesaltsalt", ..)`).
    #[test]
    fn reference_vectors() {
        for h in [
            "$argon2id$v=19$m=1024,t=2,p=1$c29tZXNhbHRzYWx0$5YHT8ZDhBeqdbLaIKKPWaHOVfqCkLDnJo/WC5yMJsmg",
            "$argon2id$v=19$m=1000,t=3,p=3$c29tZXNhbHRzYWx0$pBXakVo7EUYbQvZ5+3UFK3zLmIFDN6E01WdTnRbaihT9VrTfJpZabYE50Vi5jJen",
        ] {
            let pw = Arc::new(OwnerPassword::new(h, 1).unwrap());
            assert!(verify(&pw, "correct horse"), "{h}");
            assert!(!verify(&pw, "correct horse!"), "{h}");
        }
    }

    #[test]
    fn rejects_other_hashes() {
        for h in [
            "not a phc string",
            "$argon2i$v=19$m=16,t=2,p=1$c2FsdHNhbHQ$Zm9vYmFyYmF6",
            "$argon2id$v=19$m=1024,t=2,p=1$c29tZXNhbHRzYWx0",
            "$argon2id$v=18$m=1024,t=2,p=1$c29tZXNhbHRzYWx0$5YHT8ZDhBeqdbLaIKKPWaHOVfqCkLDnJo/WC5yMJsmg",
        ] {
            assert!(OwnerPassword::new(h, 1).is_err(), "{h}");
        }
    }

    #[test]
    fn slots_are_bounded_and_buffers_reused() {
        let h = crate::hash_password("pw").unwrap();
        let pw = Arc::new(OwnerPassword::new(&h, 2).unwrap());
        assert_eq!(pw.memory_bytes(), 19 * 1024 * 1024);
        let a = pw.try_slot().unwrap();
        let b = pw.try_slot().unwrap();
        assert!(pw.try_slot().is_none(), "third concurrent check refused");
        assert_eq!(pw.usage(), (2, 0));
        assert!(!a.verify("x"), "wrong password");
        assert_eq!(pw.usage(), (1, 1), "buffer back in the pool");
        drop(b);
        assert_eq!(pw.usage(), (0, 1), "unused slot: nothing allocated");
        let c = pw.try_slot().unwrap();
        assert!(c.buf.is_some(), "pooled buffer handed out again");
        assert!(c.verify("pw"));
        // 10 sequential checks: still a single buffer.
        for _ in 0..10 {
            assert!(!verify(&pw, "nope"));
        }
        assert_eq!(pw.usage(), (0, 1));
        // Lowering the limit drops surplus buffers.
        let (x, y) = (pw.try_slot().unwrap(), pw.try_slot().unwrap());
        let (x, y) = (x.verify("a"), y.verify("b"));
        assert!(!x && !y);
        assert_eq!(pw.usage(), (0, 2));
        pw.set_max(1);
        let s = pw.try_slot().unwrap();
        assert!(pw.try_slot().is_none());
        drop(s);
        assert_eq!(pw.usage(), (0, 1), "surplus buffer dropped");
        pw.set_max(0);
        assert_eq!(pw.max(), 1, "at least one check at a time");
    }

    #[test]
    fn slot_released_when_verification_panics() {
        let h = crate::hash_password("pw").unwrap();
        let pw = Arc::new(OwnerPassword::new(&h, 1).unwrap());
        let s = pw.try_slot().unwrap();
        let r = std::thread::spawn(move || {
            let _s = s;
            panic!("boom");
        })
        .join();
        assert!(r.is_err());
        assert_eq!(pw.usage().0, 0);
        assert!(pw.try_slot().is_some());
    }
}
