// Copyright 2011 Boris Kogan (boris@thekogans.net)
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

#if defined (TOOLCHAIN_OS_Windows)
    #include <winsock2.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/util/FixedArray.h"
#include "thekogans/util/File.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/RSA.h"

namespace thekogans {
    namespace crypto {

        AsymmetricKey::Ptr RSA::CreateKey (
                std::size_t keyLength,
                BIGNUMPtr publicExponent,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (keyLength > 0 && publicExponent.get () != 0) {
                EVP_PKEY *key = 0;
                EVP_PKEY_CTXPtr ctx (
                    EVP_PKEY_CTX_new_id (EVP_PKEY_RSA, OpenSSLInit::engine));
                if (ctx.get () != 0 &&
                        EVP_PKEY_keygen_init (ctx.get ()) == 1 &&
                        EVP_PKEY_CTX_set_rsa_keygen_bits (ctx.get (), (util::i32)keyLength) == 1 &&
                        EVP_PKEY_CTX_set_rsa_keygen_pubexp (ctx.get (), publicExponent.get ()) == 1 &&
                        EVP_PKEY_keygen (ctx.get (), &key) == 1) {
                    publicExponent.release ();
                    return AsymmetricKey::Ptr (
                        new AsymmetricKey (EVP_PKEYPtr (key), true, id, name, description));
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

        namespace {
            std::string paddingTostring (util::i32 padding) {
                return padding == RSA_PKCS1_PADDING ? "RSA_PKCS1_PADDING" :
                    padding == RSA_SSLV23_PADDING ? "RSA_SSLV23_PADDING" :
                    padding == RSA_NO_PADDING ? "RSA_NO_PADDING" :
                    padding == RSA_PKCS1_OAEP_PADDING ? "RSA_PKCS1_OAEP_PADDING" :
                    padding == RSA_X931_PADDING ? "RSA_X931_PADDING" :
                    padding == RSA_PKCS1_PSS_PADDING ? "RSA_PKCS1_PSS_PADDING" : "Unknown";
            }
        }

        std::size_t RSA::GetMaxPlaintextLength (
                std::size_t keyLength,
                util::i32 padding) {
            if (util::OneBitCount (keyLength) == 1) {
                std::size_t paddingLength = 0;
                switch (padding) {
                    case RSA_PKCS1_PADDING:
                    case RSA_SSLV23_PADDING:
                        paddingLength = 12;
                        break;
                    case RSA_NO_PADDING:
                        break;
                    case RSA_PKCS1_OAEP_PADDING:
                        paddingLength = 42;
                        break;
                    case RSA_X931_PADDING:
                    case RSA_PKCS1_PSS_PADDING:
                    default:
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Invalid padding type: %d.",
                            paddingTostring (padding).c_str ());
                }
                return (keyLength >> 3) - paddingLength;
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Key length (%d) must be a power of 2.",
                    keyLength);
            }
        }

        util::Buffer::UniquePtr RSA::EncryptBuffer (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::Ptr publicKey,
                util::i32 padding) {
            if (plaintext != 0 && plaintextLength > 0 &&
                    publicKey.Get () != 0 && publicKey->GetType () == EVP_PKEY_RSA) {
                EVP_PKEY_CTXPtr ctx (
                    EVP_PKEY_CTX_new (publicKey->Get (), OpenSSLInit::engine));
                if (ctx.get () != 0 &&
                        EVP_PKEY_encrypt_init (ctx.get ()) == 1 &&
                        EVP_PKEY_CTX_set_rsa_padding (ctx.get (), padding) == 1) {
                    size_t ciphertextLength = 0;
                    if (EVP_PKEY_encrypt (ctx.get (), 0, &ciphertextLength,
                            (const util::ui8 *)plaintext, plaintextLength) == 1) {
                        util::Buffer::UniquePtr ciphertext (
                            new util::Buffer (util::HostEndian, (util::ui32)ciphertextLength));
                        if (EVP_PKEY_encrypt (ctx.get (),
                                ciphertext->GetWritePtr (), &ciphertextLength,
                                (const util::ui8 *)plaintext, plaintextLength) == 1) {
                            ciphertext->AdvanceWriteOffset ((util::ui32)ciphertextLength);
                            return ciphertext;
                        }
                        else {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
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

        util::Buffer::UniquePtr RSA::DecryptBuffer (
                const void *ciphertext,
                std::size_t ciphertextLength,
                AsymmetricKey::Ptr privateKey,
                util::i32 padding,
                bool secure,
                util::Endianness endianness) {
            if (ciphertext != 0 && ciphertextLength > 0 &&
                    privateKey.Get () != 0 && privateKey->GetType () == EVP_PKEY_RSA) {
                EVP_PKEY_CTXPtr ctx (
                    EVP_PKEY_CTX_new (privateKey->Get (), OpenSSLInit::engine));
                if (ctx.get () != 0 &&
                        EVP_PKEY_decrypt_init (ctx.get ()) == 1 &&
                        EVP_PKEY_CTX_set_rsa_padding (ctx.get (), padding) == 1) {
                    size_t plaintextLength = 0;
                    if (EVP_PKEY_decrypt (ctx.get (), 0, &plaintextLength,
                            (const util::ui8 *)ciphertext, ciphertextLength) == 1) {
                        util::Buffer::UniquePtr plaintext (secure ?
                            new util::SecureBuffer (endianness, (util::ui32)plaintextLength) :
                            new util::Buffer (endianness, (util::ui32)plaintextLength));
                        if (EVP_PKEY_decrypt (ctx.get (),
                                plaintext->GetWritePtr (), &plaintextLength,
                                (const util::ui8 *)ciphertext, ciphertextLength) == 1) {
                            plaintext->AdvanceWriteOffset ((util::ui32)plaintextLength);
                            return plaintext;
                        }
                        else {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
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
