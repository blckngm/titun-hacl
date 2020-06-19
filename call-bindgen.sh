bindgen \
    --whitelist-type=EverCrypt.* \
    '--blacklist-type=EverCrypt_Hash_state_s.*' \
    --blacklist-type=Hacl_HMAC_DRBG_state.* \
    --whitelist-function=EverCrypt.* \
    --whitelist-function=Hacl_Blake2.* \
    '--whitelist-var=EverCrypt.*|Spec.*' \
    --blacklist-function=.*___.* \
    all.h \
    -- -I hacl-star-dist/gcc-compatible/ \
    -I hacl-star-dist/kremlin/include/ \
    -I hacl-star-dist/kremlin/kremlib/dist/minimal/ \
    > src/bindings.rs
