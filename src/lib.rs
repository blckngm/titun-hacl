#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

include!("bindings.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::TryInto;
    use core::ptr;

    #[test]
    fn chacha20_poly1305_round_trip() {
        let mut k = [0u8; 32];
        let mut n = [0u8; 12];
        let mut m = [0u8; 5];
        let mut c = [0u8; 5];
        let mut tag = [0u8; 16];

        unsafe {
            EverCrypt_AutoConfig2_init();
            EverCrypt_Chacha20Poly1305_aead_encrypt(
                k.as_mut_ptr(),
                n.as_mut_ptr(),
                0,
                ptr::null_mut(),
                m.len().try_into().unwrap(),
                m.as_mut_ptr(),
                c.as_mut_ptr(),
                tag.as_mut_ptr(),
            );
            m = [1u8; 5];
            let r = EverCrypt_Chacha20Poly1305_aead_decrypt(
                k.as_mut_ptr(),
                n.as_mut_ptr(),
                0,
                ptr::null_mut(),
                m.len().try_into().unwrap(),
                m.as_mut_ptr(),
                c.as_mut_ptr(),
                tag.as_mut_ptr(),
            );
            assert_eq!(r, 0);
            assert_eq!(m, [0u8; 5]);

            tag[0] = tag[0].wrapping_add(1);
            let r = EverCrypt_Chacha20Poly1305_aead_decrypt(
                k.as_mut_ptr(),
                n.as_mut_ptr(),
                0,
                ptr::null_mut(),
                m.len().try_into().unwrap(),
                m.as_mut_ptr(),
                c.as_mut_ptr(),
                tag.as_mut_ptr(),
            );
            assert_ne!(r, 0);
        }
    }
}
