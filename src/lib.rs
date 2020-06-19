#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

// Opaque type.
pub type EverCrypt_Hash_state_s = u8;

include!("bindings.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::TryInto;

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

        unsafe {
            EverCrypt_AutoConfig2_init();
            EverCrypt_Chacha20Poly1305_aead_encrypt(
                KEY.as_ptr() as _,
                NONCE.as_ptr() as _,
                AAD.len().try_into().unwrap(),
                AAD.as_ptr() as _,
                m.len().try_into().unwrap(),
                m.as_mut_ptr(),
                c.as_mut_ptr(),
                tag.as_mut_ptr(),
            );
            assert_eq!(tag, TAG);
            assert_eq!(c, CIPHERTEXT);
            for b in &mut m[..] {
                *b = 0;
            }
            let r = EverCrypt_Chacha20Poly1305_aead_decrypt(
                KEY.as_ptr() as _,
                NONCE.as_ptr() as _,
                AAD.len().try_into().unwrap(),
                AAD.as_ptr() as _,
                m.len().try_into().unwrap(),
                m.as_mut_ptr(),
                c.as_mut_ptr(),
                tag.as_mut_ptr(),
            );
            assert_eq!(r, 0);
            assert_eq!(m, PLAINTEXT);

            tag[0] = tag[0].wrapping_add(1);
            let r = EverCrypt_Chacha20Poly1305_aead_decrypt(
                KEY.as_ptr() as _,
                NONCE.as_ptr() as _,
                AAD.len().try_into().unwrap(),
                AAD.as_ptr() as _,
                m.len().try_into().unwrap(),
                m.as_mut_ptr(),
                c.as_mut_ptr(),
                tag.as_mut_ptr(),
            );
            assert_ne!(r, 0);
        }
    }

    #[test]
    fn blake2s_vector() {
        let input = b"abc";
        let mut output = [0u8; 32];
        let key: &[u8] = &[];

        if cfg!(any(target_arch = "aarch64", target_arch = "x86-64")) {
            unsafe {
                Hacl_Blake2s_128_blake2s(
                    output.len() as _,
                    output.as_mut_ptr(),
                    input.len() as _,
                    input.as_ptr() as _,
                    key.len() as _,
                    key.as_ptr() as _,
                );
            }
            assert_eq!(
                output,
                [
                    0x50, 0x8C, 0x5E, 0x8C, 0x32, 0x7C, 0x14, 0xE2, 0xE1, 0xA7, 0x2B, 0xA3, 0x4E,
                    0xEB, 0x45, 0x2F, 0x37, 0x45, 0x8B, 0x20, 0x9E, 0xD6, 0x3A, 0x29, 0x4D, 0x99,
                    0x9B, 0x4C, 0x86, 0x67, 0x59, 0x82,
                ]
            );
        }
        unsafe {
            Hacl_Blake2s_32_blake2s(
                output.len() as _,
                output.as_mut_ptr(),
                input.len() as _,
                input.as_ptr() as _,
                key.len() as _,
                key.as_ptr() as _,
            );
        }
        assert_eq!(
            output,
            [
                0x50, 0x8C, 0x5E, 0x8C, 0x32, 0x7C, 0x14, 0xE2, 0xE1, 0xA7, 0x2B, 0xA3, 0x4E, 0xEB,
                0x45, 0x2F, 0x37, 0x45, 0x8B, 0x20, 0x9E, 0xD6, 0x3A, 0x29, 0x4D, 0x99, 0x9B, 0x4C,
                0x86, 0x67, 0x59, 0x82,
            ]
        );
    }
}
