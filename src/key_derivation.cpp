#include "key_derivation.hpp"

#include <limits>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace decrypt_openssl::internal {
namespace {

DecryptError makeError(DecryptErrorCode code, std::string message) {
    return DecryptError {code, std::move(message)};
}

}  // namespace

KeyMaterial::~KeyMaterial() {
    OPENSSL_cleanse(key.data(), key.size());
    OPENSSL_cleanse(iv.data(), iv.size());
}

std::optional<DecryptError> deriveLegacyKeyMaterial(
    const std::array<std::uint8_t, 8>& salt,
    std::string_view password,
    KeyMaterial& keyMaterial) noexcept {
    if (password.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return makeError(
            DecryptErrorCode::input_too_large,
            "Password length exceeds the OpenSSL EVP_BytesToKey input limit");
    }

    const auto derivedKeyLength = EVP_BytesToKey(
        EVP_aes_256_cbc(),
        EVP_md5(),
        salt.data(),
        reinterpret_cast<const unsigned char*>(password.data()),
        static_cast<int>(password.size()),
        1,
        keyMaterial.key.data(),
        keyMaterial.iv.data());

    if (derivedKeyLength != static_cast<int>(keyMaterial.key.size())) {
        return makeError(
            DecryptErrorCode::key_derivation_failed,
            "OpenSSL EVP_BytesToKey failed to derive an AES-256 key");
    }

    return std::nullopt;
}

}  // namespace decrypt_openssl::internal
