#include "decrypt_openssl/decrypt.hpp"
#include "openssl_format.hpp"

#include <array>
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
    throw std::runtime_error("Invalid hex digit in test fixture");
}

std::vector<std::uint8_t> decodeHex(std::string_view hex) {
    if (hex.size() % 2 != 0U) {
        throw std::runtime_error("Hex fixture must have an even number of digits");
    }

    std::vector<std::uint8_t> bytes;
    bytes.reserve(hex.size() / 2U);

    for (std::size_t index = 0; index < hex.size(); index += 2U) {
        const auto high = static_cast<std::uint8_t>(fromHexDigit(hex[index]));
        const auto low = static_cast<std::uint8_t>(fromHexDigit(hex[index + 1]));
        bytes.push_back(static_cast<std::uint8_t>((high << 4U) | low));
    }

    return bytes;
}

class TestRunner {
public:
    void expect(bool condition, std::string_view message) {
        if (condition) {
            return;
        }

        ++failures_;
        std::cerr << "FAILED: " << message << '\n';
    }

    [[nodiscard]] int failures() const noexcept { return failures_; }

private:
    int failures_ = 0;
};

void parseValidHeader(TestRunner& runner) {
    const auto input = decodeHex(kFixtureHex);
    const auto parsed = decrypt_openssl::internal::parseSaltedCiphertext(input);

    runner.expect(parsed.ok(), "Expected OpenSSL salted payload parsing to succeed");
    runner.expect(parsed.salt == std::array<std::uint8_t, 8> {1, 2, 3, 4, 5, 6, 7, 8},
        "Expected the parser to expose the 8-byte salt");
    runner.expect(parsed.ciphertext.size() == 32U,
        "Expected the parser to return the ciphertext bytes after the header");
}

void rejectShortInput(TestRunner& runner) {
    const std::array<std::uint8_t, 15> shortInput {};
    const auto result = decrypt_openssl::decryptSaltedAes256Cbc(shortInput, "secret");

    runner.expect(!result, "Expected short input decryption to fail");
    runner.expect(result.error.has_value(), "Expected short input to include an error");
    runner.expect(
        result.error && result.error->code == decrypt_openssl::DecryptErrorCode::input_too_short,
        "Expected short input to return input_too_short");
}

void rejectInvalidHeader(TestRunner& runner) {
    auto input = decodeHex(kFixtureHex);
    input.front() = 'B';

    const auto result = decrypt_openssl::decryptSaltedAes256Cbc(input, "secret");

    runner.expect(!result, "Expected invalid header decryption to fail");
    runner.expect(result.error.has_value(), "Expected invalid header to include an error");
    runner.expect(
        result.error && result.error->code == decrypt_openssl::DecryptErrorCode::invalid_header,
        "Expected invalid header to return invalid_header");
}

void rejectWrongPassword(TestRunner& runner) {
    const auto input = decodeHex(kFixtureHex);
    const auto result = decrypt_openssl::decryptSaltedAes256Cbc(input, "wrong-password");

    runner.expect(!result, "Expected wrong password decryption to fail");
    runner.expect(result.error.has_value(), "Expected wrong password to include an error");
    runner.expect(
        result.error && result.error->code == decrypt_openssl::DecryptErrorCode::decrypt_final_failed,
        "Expected wrong password to fail during final padding verification");
}

void decryptKnownFixture(TestRunner& runner) {
    const auto input = decodeHex(kFixtureHex);
    const auto result = decrypt_openssl::decryptSaltedAes256Cbc(input, "secret");

    runner.expect(result.ok(), "Expected known OpenSSL fixture decryption to succeed");
    if (!result) {
        return;
    }

    const auto plaintext = std::string(result.plaintext.begin(), result.plaintext.end());
    runner.expect(
        plaintext == kExpectedPlaintext,
        "Expected decrypted plaintext to match the known fixture");
}

}  // namespace

int main() {
    TestRunner runner;

    parseValidHeader(runner);
    rejectShortInput(runner);
    rejectInvalidHeader(runner);
    rejectWrongPassword(runner);
    decryptKnownFixture(runner);

    if (runner.failures() == 0) {
        std::cout << "All decrypt_openssl tests passed\n";
        return EXIT_SUCCESS;
    }

    std::cerr << runner.failures() << " test(s) failed\n";
    return EXIT_FAILURE;
}
