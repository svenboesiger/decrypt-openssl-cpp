#include "decrypt_openssl/decrypt.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view kFixtureHex =
    "53616c7465645f5f0102030405060708"
    "8c3822543ca5e11f2111b3dca0c036bd9ab31a0c822edcab586fe66fd5ffa4c6";

constexpr std::string_view kExpectedPlaintext = "hello from openssl\n";

int fromHexDigit(const char digit) {
    if (digit >= '0' && digit <= '9') {
        return digit - '0';
    }
    if (digit >= 'a' && digit <= 'f') {
        return 10 + (digit - 'a');
    }
    if (digit >= 'A' && digit <= 'F') {
        return 10 + (digit - 'A');
    }
    throw std::runtime_error("Invalid hex digit in example fixture");
}

std::vector<std::uint8_t> decodeHex(std::string_view hex) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(hex.size() / 2U);

    for (std::size_t index = 0; index < hex.size(); index += 2U) {
        const auto high = static_cast<std::uint8_t>(fromHexDigit(hex[index]));
        const auto low = static_cast<std::uint8_t>(fromHexDigit(hex[index + 1]));
        bytes.push_back(static_cast<std::uint8_t>((high << 4U) | low));
    }

    return bytes;
}

}  // namespace

int main() {
    const auto input = decodeHex(kFixtureHex);
    const auto result = decrypt_openssl::decryptSaltedAes256Cbc(input, "secret");

    if (!result) {
        std::cerr << result.error->message << '\n';
        return EXIT_FAILURE;
    }

    const auto plaintext = std::string(result.plaintext.begin(), result.plaintext.end());
    if (plaintext != kExpectedPlaintext) {
        std::cerr << "Unexpected plaintext: " << plaintext << '\n';
        return EXIT_FAILURE;
    }

    std::cout << plaintext;
    return EXIT_SUCCESS;
}
