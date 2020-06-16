#![feature(test)]
extern crate test;

use evercrypt::*;
use std::convert::TryInto;
use std::ptr;
use test::{black_box, Bencher};

#[bench]
fn bench_chacha20_poly1305_encrypt(b: &mut Bencher) {
    let k = [0u8; 32];
    let n = [0u8; 12];
    let m = [0u8; 1400];
    let mut c = [0u8; 1400];
    let mut tag = [0u8; 16];

    unsafe {
        EverCrypt_AutoConfig2_init();
    }

    b.bytes = 1400;

    b.iter(|| unsafe {
        EverCrypt_Chacha20Poly1305_aead_encrypt(
            k.as_ptr(),
            black_box(n).as_ptr(),
            0,
            ptr::null(),
            m.len().try_into().unwrap(),
            m.as_ptr(),
            c.as_mut_ptr(),
            tag.as_mut_ptr(),
        );
    });
}
