#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace decrypt_openssl {

enum class DecryptErrorCode {
    input_too_short,
    invalid_header,
    input_too_large,
    key_derivation_failed,
    decrypt_init_failed,
    decrypt_update_failed,
    decrypt_final_failed,
    allocation_failure,
    internal_error,
};

struct DecryptError {
    DecryptErrorCode code {};
    std::string message;
};

struct DecryptResult {
    std::vector<std::uint8_t> plaintext;
    std::optional<DecryptError> error;

    [[nodiscard]] bool ok() const noexcept { return !error.has_value(); }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
};

[[nodiscard]] DecryptResult decryptSaltedAes256Cbc(
    std::span<const std::uint8_t> input,
    std::string_view password) noexcept;

}  // namespace decrypt_openssl
