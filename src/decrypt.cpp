#include "decrypt_openssl/decrypt.hpp"

#include "decryptor.hpp"
#include "key_derivation.hpp"
#include "openssl_format.hpp"

#include <exception>
#include <utility>

namespace decrypt_openssl {
namespace {

DecryptResult makeError(DecryptErrorCode code, std::string message) {
    return DecryptResult {
        {},
        DecryptError {code, std::move(message)},
    };
}

DecryptResult decryptImpl(
    std::span<const std::uint8_t> input,
    std::string_view password) {
    const auto parsed = internal::parseSaltedCiphertext(input);
    if (!parsed.ok()) {
        return makeError(parsed.error->code, parsed.error->message);
    }

    internal::KeyMaterial keyMaterial;
    if (auto error = internal::deriveLegacyKeyMaterial(parsed.salt, password, keyMaterial)) {
        return makeError(error->code, error->message);
    }

    return internal::decryptCiphertext(parsed.ciphertext, keyMaterial);
}

}  // namespace

DecryptResult decryptSaltedAes256Cbc(
    std::span<const std::uint8_t> input,
    std::string_view password) noexcept {
    try {
        return decryptImpl(input, password);
    } catch (const std::bad_alloc&) {
        return makeError(
            DecryptErrorCode::allocation_failure,
            "Allocation failed while decrypting ciphertext");
    } catch (const std::exception& exception) {
        return makeError(
            DecryptErrorCode::internal_error,
            exception.what());
    } catch (...) {
        return makeError(
            DecryptErrorCode::internal_error,
            "Unknown internal error while decrypting ciphertext");
    }
}

}  // namespace decrypt_openssl
