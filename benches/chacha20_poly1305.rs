#![feature(test)]
extern crate test;

use evercrypt_sys::*;
use std::convert::TryInto;
use std::ptr;
use test::{black_box, Bencher};

#[bench]
fn bench_chacha20_poly1305_encrypt(b: &mut Bencher) {
    let mut key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut m = [0u8; 1400];
    let mut c = [0u8; 1400];
    let mut tag = [0u8; 16];

    unsafe {
        EverCrypt_AutoConfig2_init();
    }

    b.bytes = 1400;

    b.iter(|| unsafe {
        EverCrypt_Chacha20Poly1305_aead_encrypt(
            key.as_mut_ptr(),
            black_box(nonce).as_mut_ptr(),
            0,
            ptr::null_mut(),
            m.len().try_into().unwrap(),
            m.as_mut_ptr(),
            c.as_mut_ptr(),
            tag.as_mut_ptr(),
        );
    });
}

#[bench]
fn bench_chacha20_poly1305_encrypt_vec128(b: &mut Bencher) {
    let mut key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut m = [0u8; 1400];
    let mut c = [0u8; 1400];
    let mut tag = [0u8; 16];

    unsafe {
        EverCrypt_AutoConfig2_init();
        EverCrypt_AutoConfig2_disable_avx2();
    }

    b.bytes = 1400;

    b.iter(|| unsafe {
        EverCrypt_Chacha20Poly1305_aead_encrypt(
            key.as_mut_ptr(),
            black_box(nonce).as_mut_ptr(),
            0,
            ptr::null_mut(),
            m.len().try_into().unwrap(),
            m.as_mut_ptr(),
            c.as_mut_ptr(),
            tag.as_mut_ptr(),
        );
    });
}
