#include "decryptor.hpp"

#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <openssl/err.h>
#include <openssl/evp.h>

namespace decrypt_openssl::internal {
namespace {

DecryptResult makeError(DecryptErrorCode code, std::string message) {
    return DecryptResult {
        {},
        DecryptError {code, std::move(message)},
    };
}

std::string readOpenSslError(std::string_view fallbackMessage) {
    std::string message;

    for (unsigned long errorCode = ERR_get_error();
         errorCode != 0;
         errorCode = ERR_get_error()) {
        char buffer[256] {};
        ERR_error_string_n(errorCode, buffer, sizeof(buffer));

        if (!message.empty()) {
            message.append(" | ");
        }
        message.append(buffer);
    }

    if (message.empty()) {
        message.assign(fallbackMessage);
    }

    return message;
}

}  // namespace

DecryptResult decryptCiphertext(
    std::span<const std::uint8_t> ciphertext,
    const KeyMaterial& keyMaterial) noexcept {
    constexpr auto kBlockSize = 16U;
    const auto maxInt = static_cast<std::size_t>(std::numeric_limits<int>::max());

    if (ciphertext.size() > maxInt - kBlockSize) {
        return makeError(
            DecryptErrorCode::input_too_large,
            "Ciphertext size exceeds the OpenSSL EVP decryption API limit");
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        EVP_CIPHER_CTX_new(),
        &EVP_CIPHER_CTX_free);

    if (!context) {
        return makeError(
            DecryptErrorCode::decrypt_init_failed,
            "OpenSSL EVP_CIPHER_CTX allocation failed");
    }

    std::vector<std::uint8_t> plaintext(ciphertext.size() + kBlockSize);

    ERR_clear_error();
    if (EVP_DecryptInit_ex(
            context.get(),
            EVP_aes_256_cbc(),
            nullptr,
            keyMaterial.key.data(),
            keyMaterial.iv.data()) != 1) {
        return makeError(
            DecryptErrorCode::decrypt_init_failed,
            readOpenSslError("OpenSSL EVP_DecryptInit_ex failed"));
    }

    int updateLength = 0;
    ERR_clear_error();
    if (EVP_DecryptUpdate(
            context.get(),
            plaintext.data(),
            &updateLength,
            reinterpret_cast<const unsigned char*>(ciphertext.data()),
            static_cast<int>(ciphertext.size())) != 1) {
        return makeError(
            DecryptErrorCode::decrypt_update_failed,
            readOpenSslError("OpenSSL EVP_DecryptUpdate failed"));
    }

    int finalLength = 0;
    ERR_clear_error();
    if (EVP_DecryptFinal_ex(
            context.get(),
            plaintext.data() + updateLength,
            &finalLength) != 1) {
        return makeError(
            DecryptErrorCode::decrypt_final_failed,
            readOpenSslError("OpenSSL EVP_DecryptFinal_ex failed"));
    }

    plaintext.resize(static_cast<std::size_t>(updateLength + finalLength));
    return DecryptResult {std::move(plaintext), std::nullopt};
}

}  // namespace decrypt_openssl::internal
