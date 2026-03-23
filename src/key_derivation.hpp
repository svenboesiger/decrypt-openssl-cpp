#pragma once

#include "decrypt_openssl/decrypt.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace decrypt_openssl::internal {

struct KeyMaterial {
    std::array<unsigned char, 32> key {};
    std::array<unsigned char, 16> iv {};

    KeyMaterial() = default;
    KeyMaterial(const KeyMaterial&) = delete;
    KeyMaterial& operator=(const KeyMaterial&) = delete;
    KeyMaterial(KeyMaterial&&) = delete;
    KeyMaterial& operator=(KeyMaterial&&) = delete;
    ~KeyMaterial();
};

[[nodiscard]] std::optional<DecryptError> deriveLegacyKeyMaterial(
    const std::array<std::uint8_t, 8>& salt,
    std::string_view password,
    KeyMaterial& keyMaterial) noexcept;

}  // namespace decrypt_openssl::internal
