#pragma once

#include "decrypt_openssl/decrypt.hpp"
#include "key_derivation.hpp"

#include <span>

namespace decrypt_openssl::internal {

[[nodiscard]] DecryptResult decryptCiphertext(
    std::span<const std::uint8_t> ciphertext,
    const KeyMaterial& keyMaterial) noexcept;

}  // namespace decrypt_openssl::internal
