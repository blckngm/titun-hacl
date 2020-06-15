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

    #[test]
    fn chacha20_poly1305_round_trip() {
        use std::ptr::null;

        let k = [0u8; 32];
        let n = [0u8; 12];
        let mut m = [];
        let mut c = [];
        let mut tag = [0u8; 16];

        unsafe {
            EverCrypt_AutoConfig2_init();
            EverCrypt_Chacha20Poly1305_aead_encrypt(
                k.as_ptr(),
                n.as_ptr(),
                0,
                null(),
                0,
                m.as_ptr(),
                c.as_mut_ptr(),
                tag.as_mut_ptr(),
            );
            let r = EverCrypt_Chacha20Poly1305_aead_decrypt(
                k.as_ptr(),
                n.as_ptr(),
                0,
                null(),
                0,
                m.as_mut_ptr(),
                c.as_ptr(),
                tag.as_ptr(),
            );
            assert_eq!(r, 0);
        }
    }
}
