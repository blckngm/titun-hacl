extern "C" {
    pub fn EverCrypt_AutoConfig2_init();
    pub fn EverCrypt_Chacha20Poly1305_aead_encrypt(
        k: *const u8,
        n1: *const u8,
        aadlen: u32,
        aad: *const u8,
        mlen: u32,
        m: *const u8,
        cipher: *mut u8,
        tag: *mut u8,
    );

    pub fn EverCrypt_Chacha20Poly1305_aead_decrypt(
        k: *const u8,
        n1: *const u8,
        aadlen: u32,
        aad: *const u8,
        mlen: u32,
        m: *mut u8,
        cipher: *const u8,
        tag: *const u8,
    ) -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use core::convert::TryInto;

    #[test]
    fn chacha20_poly1305_round_trip() {
        let k = [0u8; 32];
        let n = [0u8; 12];
        let mut m = [0u8; 5];
        let mut c = [0u8; 5];
        let mut tag = [0u8; 16];

        unsafe {
            EverCrypt_AutoConfig2_init();
            EverCrypt_Chacha20Poly1305_aead_encrypt(
                k.as_ptr(),
                n.as_ptr(),
                0,
                ptr::null(),
                m.len().try_into().unwrap(),
                m.as_ptr(),
                c.as_mut_ptr(),
                tag.as_mut_ptr(),
            );
            m = [1u8; 5];
            let r = EverCrypt_Chacha20Poly1305_aead_decrypt(
                k.as_ptr(),
                n.as_ptr(),
                0,
                ptr::null(),
                m.len().try_into().unwrap(),
                m.as_mut_ptr(),
                c.as_ptr(),
                tag.as_ptr(),
            );
            assert_eq!(r, 0);
            assert_eq!(m, [0u8; 5]);

            tag[0] = tag[0].wrapping_add(1);
            let r = EverCrypt_Chacha20Poly1305_aead_decrypt(
                k.as_ptr(),
                n.as_ptr(),
                0,
                ptr::null(),
                m.len().try_into().unwrap(),
                m.as_mut_ptr(),
                c.as_ptr(),
                tag.as_ptr(),
            );
            assert_ne!(r, 0);
        }
    }
}
