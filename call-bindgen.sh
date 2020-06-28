bindgen \
    '--whitelist-function=Hacl_Chacha20Poly1305_(32|128|256)_aead_(encrypt|decrypt)' \
    '--whitelist-function=Hacl_Curve25519_(64|51)_(ecdh|scalarmult|secret_to_public)' \
    all.h \
    -- -I hacl-star-dist/gcc-compatible/ \
    -I hacl-star-dist/kremlin/include/ \
    -I hacl-star-dist/kremlin/kremlib/dist/minimal/ \
    > src/bindings.rs
