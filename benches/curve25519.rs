#![feature(test)]
extern crate test;

use test::Bencher;
use titun_hacl::*;

#[bench]
fn bench_curve25519_scalarmult(b: &mut Bencher) {
    let our_secret: [u8; 32] = [
        165, 70, 227, 107, 240, 82, 124, 157, 59, 22, 21, 75, 130, 70, 94, 221, 98, 20, 76, 10,
        193, 252, 90, 24, 80, 106, 34, 68, 186, 68, 154, 196,
    ];
    let their_public: [u8; 32] = [
        230, 219, 104, 103, 88, 48, 48, 219, 53, 148, 193, 164, 36, 177, 95, 124, 114, 102, 36,
        236, 38, 179, 53, 59, 16, 169, 3, 166, 208, 171, 28, 76,
    ];

    b.iter(|| curve25519_multiplexed_scalarmult(&our_secret, &their_public))
}

#[bench]
fn bench_curve25519_scalarmult_libsodium(b: &mut Bencher) {
    let mut out = [0u8; 32];
    let our_secret: [u8; 32] = [
        165, 70, 227, 107, 240, 82, 124, 157, 59, 22, 21, 75, 130, 70, 94, 221, 98, 20, 76, 10,
        193, 252, 90, 24, 80, 106, 34, 68, 186, 68, 154, 196,
    ];
    let their_public: [u8; 32] = [
        230, 219, 104, 103, 88, 48, 48, 219, 53, 148, 193, 164, 36, 177, 95, 124, 114, 102, 36,
        236, 38, 179, 53, 59, 16, 169, 3, 166, 208, 171, 28, 76,
    ];
    unsafe {
        libsodium_sys::sodium_init();
    };

    b.iter(|| unsafe {
        libsodium_sys::crypto_scalarmult(
            out.as_mut_ptr(),
            our_secret.as_ptr() as _,
            their_public.as_ptr() as _,
        );
    })
}

#[bench]
fn bench_curve25519_scalarmult_dalek(b: &mut Bencher) {
    let our_secret: [u8; 32] = [
        165, 70, 227, 107, 240, 82, 124, 157, 59, 22, 21, 75, 130, 70, 94, 221, 98, 20, 76, 10,
        193, 252, 90, 24, 80, 106, 34, 68, 186, 68, 154, 196,
    ];
    let their_public: [u8; 32] = [
        230, 219, 104, 103, 88, 48, 48, 219, 53, 148, 193, 164, 36, 177, 95, 124, 114, 102, 36,
        236, 38, 179, 53, 59, 16, 169, 3, 166, 208, 171, 28, 76,
    ];

    b.iter(|| x25519_dalek::x25519(our_secret, their_public))
}
