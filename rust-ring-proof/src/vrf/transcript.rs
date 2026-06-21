use crate::vrf::codec::enc_64;
use sha2::{Digest, Sha512};

#[derive(Clone)]
pub struct Transcript {
    hasher: Option<Sha512>,
    seed: [u8; 64],
    counter: u64,
    buf: Vec<u8>,
    started: bool,
}

impl Transcript {
    pub fn new(suite_id: &[u8]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(suite_id);
        Transcript { hasher: Some(hasher), seed: [0u8; 64], counter: 0, buf: Vec::new(), started: false }
    }

    pub fn absorb(&mut self, data: &[u8]) {
        let h = self.hasher.as_mut().expect("absorb after squeeze");
        h.update(data);
    }

    fn start_squeeze(&mut self) {
        let h = self.hasher.take().expect("already squeezing");
        self.seed.copy_from_slice(&h.finalize());
        self.started = true;
    }

    pub fn squeeze(&mut self, n: usize) -> Vec<u8> {
        if !self.started { self.start_squeeze(); }
        while self.buf.len() < n {
            let mut h = Sha512::new();
            h.update(&self.seed);
            h.update(enc_64(self.counter));
            self.counter += 1;
            self.buf.extend_from_slice(&h.finalize());
        }
        self.buf.drain(..n).collect()
    }

    pub fn fork(&self) -> Self {
        self.clone()
    }
}
