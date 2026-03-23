#pragma once

#include "decrypt_openssl/decrypt.hpp"

#include <QByteArray>
#include <QString>

namespace decrypt_openssl {

struct DecryptResultQt {
    QByteArray plaintext;
    std::optional<DecryptError> error;

    [[nodiscard]] bool ok() const noexcept { return !error.has_value(); }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
};

[[nodiscard]] DecryptResultQt decryptSaltedAes256Cbc(
    const QByteArray& input,
    const QString& password) noexcept;

}  // namespace decrypt_openssl
