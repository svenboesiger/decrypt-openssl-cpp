#pragma once

#include "decrypt_openssl/decrypt.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>

namespace decrypt_openssl::internal {

struct ParsedCiphertext {
    std::array<std::uint8_t, 8> salt {};
    std::span<const std::uint8_t> ciphertext;
    std::optional<DecryptError> error;

    [[nodiscard]] bool ok() const noexcept { return !error.has_value(); }
};

[[nodiscard]] ParsedCiphertext parseSaltedCiphertext(
    std::span<const std::uint8_t> input) noexcept;

}  // namespace decrypt_openssl::internal
