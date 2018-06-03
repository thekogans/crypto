// Copyright 2016 Boris Kogan (boris@thekogans.net)
//
// This file is part of libthekogans_crypto.
//
// libthekogans_crypto is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libthekogans_crypto is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libthekogans_crypto. If not, see <http://www.gnu.org/licenses/>.

#include "thekogans/util/Exception.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/Decryptor.h"

namespace thekogans {
    namespace crypto {

        Decryptor::Decryptor (
                SymmetricKey::Ptr key,
                const EVP_CIPHER *cipher) {
            if (key.Get () != 0 && cipher != 0) {
                if (EVP_DecryptInit_ex (
                            &context,
                            cipher,
                            OpenSSLInit::engine,
                            key->Get ().GetReadPtr (),
                            0) != 1 ||
                        (GetCipherMode (cipher) == EVP_CIPH_GCM_MODE &&
                            EVP_CIPHER_CTX_ctrl (
                                &context,
                                EVP_CTRL_GCM_SET_IVLEN,
                                EVP_CIPHER_CTX_iv_length (&context),
                                0) != 1)) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void Decryptor::Init (const util::ui8 *iv) {
            if (iv != 0) {
                if (EVP_DecryptInit_ex (&context, 0, 0, 0, iv) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void Decryptor::SetAssociatedData (
                const void *associatedData,
                std::size_t associatedDataLength) {
            if (associatedData != 0 && associatedDataLength > 0) {
                util::i32 updateLength = 0;
                if (EVP_DecryptUpdate (
                        &context,
                        0,
                        &updateLength,
                        (const util::ui8 *)associatedData,
                        (util::i32)associatedDataLength) != 1) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t Decryptor::Update (
                const void *ciphertext,
                std::size_t ciphertextLength,
                util::ui8 *plaintext) {
            if (ciphertext != 0 && ciphertextLength > 0 && plaintext != 0) {
                util::i32 updateLength = 0;
                if (EVP_DecryptUpdate (
                        &context,
                        plaintext,
                        &updateLength,
                        (const util::ui8 *)ciphertext,
                        (util::i32)ciphertextLength) == 1) {
                    stats.Update (updateLength);
                    return (std::size_t)updateLength;
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool Decryptor::SetTag (
                const void *tag,
                std::size_t tagLength) {
            if (tag != 0 && tagLength > 0) {
                if (EVP_CIPHER_CTX_ctrl (
                        &context,
                        EVP_CTRL_GCM_SET_TAG,
                        (util::i32)tagLength,
                        (void *)tag) == 1) {
                    return true;
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t Decryptor::Final (util::ui8 *plaintext) {
            if (plaintext != 0) {
                util::i32 finalLength = 0;
                if (EVP_DecryptFinal_ex (
                        &context,
                        plaintext,
                        &finalLength) == 1) {
                    stats.Update (finalLength);
                    return (std::size_t)finalLength;
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
