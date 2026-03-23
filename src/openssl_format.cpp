#include "openssl_format.hpp"

#include <algorithm>
#include <array>

namespace decrypt_openssl::internal {
namespace {

constexpr std::array<std::uint8_t, 8> kSaltedPrefix {
    'S', 'a', 'l', 't', 'e', 'd', '_', '_',
};

DecryptError makeError(DecryptErrorCode code, std::string message) {
    return DecryptError {code, std::move(message)};
}

}  // namespace

ParsedCiphertext parseSaltedCiphertext(
    std::span<const std::uint8_t> input) noexcept {
    if (input.size() < 16U) {
        return ParsedCiphertext {
            {},
            {},
            makeError(
                DecryptErrorCode::input_too_short,
                "Encrypted input must include the Salted__ header and 8-byte salt"),
        };
    }

    const auto prefix = input.first(kSaltedPrefix.size());
    if (!std::equal(prefix.begin(), prefix.end(), kSaltedPrefix.begin())) {
        return ParsedCiphertext {
            {},
            {},
            makeError(
                DecryptErrorCode::invalid_header,
                "Encrypted input does not start with the OpenSSL Salted__ header"),
        };
    }

    ParsedCiphertext parsed;
    std::copy_n(input.begin() + 8, parsed.salt.size(), parsed.salt.begin());
    parsed.ciphertext = input.subspan(16);
    return parsed;
}

}  // namespace decrypt_openssl::internal
