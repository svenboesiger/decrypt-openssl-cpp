# Decrypt OpenSSL Salted AES-256-CBC Data In Memory

This project is now structured as a small C++20 library for decrypting legacy
OpenSSL `enc` payloads that use the `Salted__` header, MD5-based
`EVP_BytesToKey`, and AES-256-CBC.

## Layout

- `include/decrypt_openssl/decrypt.hpp`: public core API with no Qt dependency
- `include/decrypt_openssl/qt_decrypt.hpp`: optional Qt adapter API
- `src/`: parser, key derivation, decryptor, and API orchestration
- `tests/`: unit and integration-style coverage
- `examples/`: a runnable end-to-end example

## Build

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

## Optional Qt Adapter

Build the Qt wrapper target only when Qt is available:

```bash
cmake -S . -B build -DDECRYPT_OPENSSL_WITH_QT=ON
cmake --build build
```

## Notes

- The core library returns a `DecryptResult` rather than logging or throwing.
- Sensitive key and IV buffers are wiped before release with `OPENSSL_cleanse`.
- The included fixture and example target decrypt the plaintext
  `hello from openssl\n`.
