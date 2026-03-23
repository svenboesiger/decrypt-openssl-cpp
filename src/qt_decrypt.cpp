#include "decrypt_openssl/qt_decrypt.hpp"

#include <span>
#include <utility>

namespace decrypt_openssl {

DecryptResultQt decryptSaltedAes256Cbc(
    const QByteArray& input,
    const QString& password) noexcept {
    const auto passwordBytes = password.toUtf8();
    const auto inputBytes = std::span(
        reinterpret_cast<const std::uint8_t*>(input.constData()),
        static_cast<std::size_t>(input.size()));

    auto result = decryptSaltedAes256Cbc(
        inputBytes,
        std::string_view(passwordBytes.constData(), static_cast<std::size_t>(passwordBytes.size())));

    if (!result) {
        return DecryptResultQt {
            {},
            std::move(result.error),
        };
    }

    return DecryptResultQt {
        QByteArray(
            reinterpret_cast<const char*>(result.plaintext.data()),
            static_cast<qsizetype>(result.plaintext.size())),
        std::nullopt,
    };
}

}  // namespace decrypt_openssl
