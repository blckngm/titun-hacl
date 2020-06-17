bindgen \
    --whitelist-type=EverCrypt.* \
    --whitelist-function=EverCrypt.* \
    '--whitelist-var=EverCrypt.*|Spec.*' \
    --blacklist-function=.*___.* \
    all.h \
    -- -I hacl-star-dist/gcc-compatible/ \
    -I hacl-star-dist/kremlin/include/ \
    -I hacl-star-dist/kremlin/kremlib/dist/minimal/ \
    > src/bindings.rs
