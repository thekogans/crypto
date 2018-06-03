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

#include "thekogans/util/RandomSource.h"
#include "thekogans/util/Exception.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/Encryptor.h"

namespace thekogans {
    namespace crypto {

        Encryptor::Encryptor (
                SymmetricKey::Ptr key,
                const EVP_CIPHER *cipher) {
            if (key.Get () && cipher != 0) {
                if (EVP_EncryptInit_ex (
                            &context,
                            cipher,
                            OpenSSLInit::engine,
                            key->Get ().GetReadPtr (),
                            0) != 1 ||
                        (GetCipherMode (cipher) == EVP_CIPH_GCM_MODE &&
                            EVP_CIPHER_CTX_ctrl (
                                &context,
                                EVP_CTRL_GCM_SET_IVLEN,
                                (util::i32)GetIVLength (),
                                0) != 1)) {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t Encryptor::Init (util::ui8 *iv) {
            if (iv != 0) {
                // An explicit iv for each frame will thwart BEAST.
                // http://www.slideshare.net/danrlde/20120418-luedtke-ssltlscbcbeast
                std::size_t ivLength = GetIVLength ();
                if (util::GlobalRandomSource::Instance ().GetBytes (iv, ivLength) == ivLength) {
                    if (EVP_EncryptInit_ex (&context, 0, 0, 0, iv) != 1) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                    return ivLength;
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to get %u random bytes for iv.", ivLength);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        void Encryptor::SetAssociatedData (
                const void *associatedData,
                std::size_t associatedDataLength) {
            if (associatedData != 0 && associatedDataLength > 0) {
                util::i32 updateLength = 0;
                if (EVP_EncryptUpdate (
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

        std::size_t Encryptor::Update (
                const void *plaintext,
                std::size_t plaintextLength,
                util::ui8 *ciphertext) {
            if (plaintext != 0 && plaintextLength > 0 && ciphertext != 0) {
                util::i32 updateLength = 0;
                if (EVP_EncryptUpdate (
                        &context,
                        ciphertext,
                        &updateLength,
                        (const util::ui8 *)plaintext,
                        (util::i32)plaintextLength) == 1) {
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

        std::size_t Encryptor::Final (util::ui8 *ciphertext) {
            if (ciphertext != 0) {
                util::i32 finalLength = 0;
                if (EVP_EncryptFinal_ex (
                        &context,
                        ciphertext,
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

        std::size_t Encryptor::GetTag (util::ui8 *tag) {
            if (tag != 0) {
                if (EVP_CIPHER_CTX_ctrl (
                        &context,
                        EVP_CTRL_GCM_GET_TAG,
                        EVP_GCM_TLS_TAG_LEN,
                        tag) == 1) {
                    return EVP_GCM_TLS_TAG_LEN;
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
