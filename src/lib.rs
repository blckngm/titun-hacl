#![allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    clippy::missing_safety_doc,
    clippy::too_many_arguments
)]

use core::convert::TryInto;

mod bindings;
#[doc(hidden)]
pub use bindings::*;

#[inline]
pub fn chacha20_poly1305_multiplexed_aead_encrypt(
    k: &[u8; 32],
    n: &[u8; 12],
    aad: &[u8],
    m: &[u8],
    cipher: &mut [u8],
    mac: &mut [u8; 16],
) {
    assert_eq!(cipher.len(), m.len());

    let k = k.as_ptr() as *mut u8;
    let n = n.as_ptr() as *mut u8;
    let aadlen = aad.len().try_into().unwrap();
    let aad = aad.as_ptr() as *mut u8;
    let mlen = m.len().try_into().unwrap();
    let m = m.as_ptr() as *mut u8;
    let cipher = cipher.as_mut_ptr();
    let mac = mac.as_mut_ptr();

    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                return Hacl_Chacha20Poly1305_256_aead_encrypt(
                    k, n, aadlen, aad, mlen, m, cipher, mac,
                );
            } else if std::is_x86_feature_detected!("sse4.2") {
                return Hacl_Chacha20Poly1305_128_aead_encrypt(
                    k, n, aadlen, aad, mlen, m, cipher, mac,
                );
            }
        }
        Hacl_Chacha20Poly1305_32_aead_encrypt(k, n, aadlen, aad, mlen, m, cipher, mac);
    }
}

#[inline]
pub fn chacha20_poly1305_multiplexed_aead_decrypt(
    k: &[u8; 32],
    n: &[u8; 12],
    aad: &[u8],
    m: &mut [u8],
    cipher: &[u8],
    mac: &[u8; 16],
) -> Result<(), ()> {
    assert_eq!(cipher.len(), m.len());

    let k = k.as_ptr() as *mut u8;
    let n = n.as_ptr() as *mut u8;
    let aadlen = aad.len().try_into().unwrap();
    let aad = aad.as_ptr() as *mut u8;
    let mlen = m.len().try_into().unwrap();
    let m = m.as_mut_ptr();
    let cipher = cipher.as_ptr() as *mut u8;
    let mac = mac.as_ptr() as *mut u8;

    fn result(code: u32) -> Result<(), ()> {
        match code {
            0 => Ok(()),
            _ => Err(()),
        }
    }

    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                return result(Hacl_Chacha20Poly1305_256_aead_decrypt(
                    k, n, aadlen, aad, mlen, m, cipher, mac,
                ));
            } else if std::is_x86_feature_detected!("sse4.2") {
                return result(Hacl_Chacha20Poly1305_128_aead_decrypt(
                    k, n, aadlen, aad, mlen, m, cipher, mac,
                ));
            }
        }
        result(Hacl_Chacha20Poly1305_32_aead_decrypt(
            k, n, aadlen, aad, mlen, m, cipher, mac,
        ))
    }
}

#[inline]
pub fn curve25519_multiplexed_scalarmult(
    our_secret: &[u8; 32],
    their_public: &[u8; 32],
) -> [u8; 32] {
    let mut out = [0u8; 32];
    let priv_ = our_secret.as_ptr() as *mut u8;
    let pub_ = their_public.as_ptr() as *mut u8;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("adx") && std::is_x86_feature_detected!("bmi2") {
                Hacl_Curve25519_64_scalarmult(out.as_mut_ptr(), priv_, pub_);
                return out;
            }
        }
        Hacl_Curve25519_51_scalarmult(out.as_mut_ptr(), priv_, pub_);
        out
    }
}

#[inline]
pub fn curve25519_multiplexed_ecdh(
    our_secret: &[u8; 32],
    their_public: &[u8; 32],
) -> Result<[u8; 32], ()> {
    let mut out = [0u8; 32];
    let priv_ = our_secret.as_ptr() as *mut u8;
    let pub_ = their_public.as_ptr() as *mut u8;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("adx") && std::is_x86_feature_detected!("bmi2") {
                let r = Hacl_Curve25519_64_ecdh(out.as_mut_ptr(), priv_, pub_);
                return if r { Ok(out) } else { Err(()) };
            }
        }
        let r = Hacl_Curve25519_51_ecdh(out.as_mut_ptr(), priv_, pub_);
        if r {
            Ok(out)
        } else {
            Err(())
        }
    }
}

#[inline]
pub fn curve25519_multiplexed_secret_to_public(secret: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let priv_ = secret.as_ptr() as *mut u8;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("adx") && std::is_x86_feature_detected!("bmi2") {
                Hacl_Curve25519_64_secret_to_public(out.as_mut_ptr(), priv_);
                return out;
            }
        }
        Hacl_Curve25519_51_secret_to_public(out.as_mut_ptr(), priv_);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_poly1305_vector() {
        const KEY: &[u8; 32] = &[
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];

        const AAD: &[u8; 12] = &[
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];

        const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: \
            If I could offer you only one tip for the future, sunscreen would be it.";

        const NONCE: &[u8; 12] = &[
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];

        const CIPHERTEXT: &[u8] = &[
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];

        const TAG: &[u8] = &[
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let mut m = PLAINTEXT.to_vec();
        let mut c = vec![0u8; PLAINTEXT.len()];
        let mut tag = [0u8; 16];

        chacha20_poly1305_multiplexed_aead_encrypt(KEY, NONCE, AAD, PLAINTEXT, &mut c, &mut tag);

        assert_eq!(tag, TAG);
        assert_eq!(c, CIPHERTEXT);
        for b in &mut m[..] {
            *b = 0;
        }

        let r = chacha20_poly1305_multiplexed_aead_decrypt(KEY, NONCE, AAD, &mut m, &c, &tag);
        assert!(r.is_ok());
        assert_eq!(m, PLAINTEXT);

        tag[0] = tag[0].wrapping_add(1);
        let r = chacha20_poly1305_multiplexed_aead_decrypt(KEY, NONCE, AAD, &mut m, &c, &tag);
        assert!(r.is_err());
    }

    #[test]
    fn curve25519_vector() {
        let our_secret: [u8; 32] = [
            165, 70, 227, 107, 240, 82, 124, 157, 59, 22, 21, 75, 130, 70, 94, 221, 98, 20, 76, 10,
            193, 252, 90, 24, 80, 106, 34, 68, 186, 68, 154, 196,
        ];
        let their_public: [u8; 32] = [
            230, 219, 104, 103, 88, 48, 48, 219, 53, 148, 193, 164, 36, 177, 95, 124, 114, 102, 36,
            236, 38, 179, 53, 59, 16, 169, 3, 166, 208, 171, 28, 76,
        ];
        let out = curve25519_multiplexed_scalarmult(&our_secret, &their_public);
        assert_eq!(
            out,
            [
                195, 218, 85, 55, 157, 233, 198, 144, 142, 148, 234, 77, 242, 141, 8, 79, 50, 236,
                207, 3, 73, 28, 113, 247, 84, 180, 7, 85, 119, 162, 133, 82
            ]
        );
    }
}
