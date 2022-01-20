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

#include "thekogans/util/Environment.h"
#if defined (TOOLCHAIN_OS_Windows)
    #include <winsock2.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/util/Constants.h"
#include "thekogans/util/FixedArray.h"
#include "thekogans/util/File.h"
#include "thekogans/crypto/CipherSuite.h"
#include "thekogans/crypto/FrameHeader.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLAsymmetricKey.h"
#include "thekogans/crypto/RSA.h"

namespace thekogans {
    namespace crypto {

        AsymmetricKey::SharedPtr RSA::CreateKey (
                std::size_t keyLength,
                BIGNUMPtr publicExponent,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (keyLength > 0 && (keyLength & ~3) == keyLength && publicExponent.get () != 0) {
                EVP_PKEY *key = 0;
                EVP_PKEY_CTXPtr ctx (
                    EVP_PKEY_CTX_new_id (EVP_PKEY_RSA, OpenSSLInit::engine));
                if (ctx.get () != 0 &&
                        EVP_PKEY_keygen_init (ctx.get ()) == 1 &&
                        EVP_PKEY_CTX_set_rsa_keygen_bits (ctx.get (), (util::i32)keyLength) == 1 &&
                        EVP_PKEY_CTX_set_rsa_keygen_pubexp (ctx.get (), publicExponent.get ()) == 1 &&
                        EVP_PKEY_keygen (ctx.get (), &key) == 1) {
                    publicExponent.release ();
                    return AsymmetricKey::SharedPtr (
                        new OpenSSLAsymmetricKey (EVP_PKEYPtr (key), true, id, name, description));
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
            inline bool IsValidPadding (util::i32 padding) {
                return padding == RSA_PKCS1_PADDING ||
                    padding == RSA_SSLV23_PADDING ||
                    padding == RSA_NO_PADDING ||
                    padding == RSA_PKCS1_OAEP_PADDING;
            }
        }

        std::size_t RSA::GetMaxPlaintextLength (
                std::size_t keyLength,
                util::i32 padding) {
            if (keyLength > 0 && (keyLength & ~3) == keyLength && IsValidPadding (padding)) {
                std::size_t paddingLength =
                    padding == RSA_PKCS1_PADDING || padding == RSA_SSLV23_PADDING ? 12 :
                    padding == RSA_PKCS1_OAEP_PADDING ? 42 : 0;
                return (keyLength >> 3) - paddingLength;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t RSA::Encrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::SharedPtr publicKey,
                util::i32 padding,
                util::ui8 *ciphertext) {
            if (plaintext != 0 && plaintextLength > 0 &&
                    publicKey.Get () != 0 && !publicKey->IsPrivate () &&
                    publicKey->GetKeyType () == OPENSSL_PKEY_RSA &&
                    IsValidPadding (padding) &&
                    ciphertext != 0) {
                EVP_PKEY_CTXPtr ctx (
                    EVP_PKEY_CTX_new (
                        ((OpenSSLAsymmetricKey *)publicKey.Get ())->key.get (),
                        OpenSSLInit::engine));
                if (ctx.get () != 0 &&
                        EVP_PKEY_encrypt_init (ctx.get ()) == 1 &&
                        EVP_PKEY_CTX_set_rsa_padding (ctx.get (), padding) == 1) {
                    size_t ciphertextLength = 0;
                    if (EVP_PKEY_encrypt (ctx.get (), 0, &ciphertextLength,
                                (const util::ui8 *)plaintext, plaintextLength) == 1 &&
                            EVP_PKEY_encrypt (ctx.get (), ciphertext, &ciphertextLength,
                                (const util::ui8 *)plaintext, plaintextLength) == 1) {
                        return ciphertextLength;
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

        util::Buffer RSA::Encrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::SharedPtr publicKey,
                util::i32 padding) {
            if (plaintext != 0 && plaintextLength > 0 &&
                    publicKey.Get () != 0 && !publicKey->IsPrivate () &&
                    publicKey->GetKeyType () == OPENSSL_PKEY_RSA &&
                    IsValidPadding (padding)) {
                util::Buffer ciphertext (util::NetworkEndian, publicKey->GetKeyLength ());
                ciphertext.AdvanceWriteOffset (
                    Encrypt (
                        plaintext,
                        plaintextLength,
                        publicKey,
                        padding,
                        ciphertext.GetWritePtr ()));
                return ciphertext;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t RSA::EncryptAndEnlengthen (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::SharedPtr publicKey,
                util::i32 padding,
                util::ui8 *ciphertext) {
            if (plaintext != 0 && plaintextLength > 0 &&
                    publicKey.Get () != 0 && !publicKey->IsPrivate () &&
                    publicKey->GetKeyType () == OPENSSL_PKEY_RSA &&
                    IsValidPadding (padding) &&
                    ciphertext != 0) {
                std::size_t ciphertextLength = Encrypt (
                    plaintext,
                    plaintextLength,
                    publicKey,
                    padding,
                    ciphertext + util::UI32_SIZE);
                util::TenantWriteBuffer buffer (util::NetworkEndian, ciphertext, util::UI32_SIZE);
                buffer << (util::ui32)ciphertextLength;
                return util::UI32_SIZE + ciphertextLength;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        namespace {
            inline std::size_t GetMaxBufferLength (std::size_t keyLength) {
                return FrameHeader::SIZE + keyLength;
            }
        }

        util::Buffer RSA::EncryptAndEnlengthen (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::SharedPtr publicKey,
                util::i32 padding) {
            if (plaintext != 0 && plaintextLength > 0 &&
                    publicKey.Get () != 0 && !publicKey->IsPrivate () &&
                    publicKey->GetKeyType () == OPENSSL_PKEY_RSA &&
                    IsValidPadding (padding)) {
                util::Buffer ciphertext (
                    util::NetworkEndian,
                    GetMaxBufferLength (plaintextLength));
                ciphertext.AdvanceWriteOffset (
                    EncryptAndEnlengthen (
                        plaintext,
                        plaintextLength,
                        publicKey,
                        padding,
                        ciphertext.GetWritePtr ()));
                return ciphertext;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t RSA::EncryptAndFrame (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::SharedPtr publicKey,
                util::i32 padding,
                util::ui8 *ciphertext) {
            if (plaintext != 0 && plaintextLength > 0 &&
                    publicKey.Get () != 0 && !publicKey->IsPrivate () &&
                    publicKey->GetKeyType () == OPENSSL_PKEY_RSA &&
                    IsValidPadding (padding) &&
                    ciphertext != 0) {
                std::size_t ciphertextLength = Encrypt (
                    plaintext,
                    plaintextLength,
                    publicKey,
                    padding,
                    ciphertext + FrameHeader::SIZE);
                util::TenantWriteBuffer buffer (util::NetworkEndian, ciphertext, FrameHeader::SIZE);
                buffer << FrameHeader (publicKey->GetId (), (util::ui32)ciphertextLength);
                return FrameHeader::SIZE + ciphertextLength;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        util::Buffer RSA::EncryptAndFrame (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::SharedPtr publicKey,
                util::i32 padding) {
            if (plaintext != 0 && plaintextLength > 0 &&
                    publicKey.Get () != 0 && !publicKey->IsPrivate () &&
                    publicKey->GetKeyType () == OPENSSL_PKEY_RSA &&
                    IsValidPadding (padding)) {
                util::Buffer ciphertext (
                    util::NetworkEndian,
                    GetMaxBufferLength (plaintextLength));
                ciphertext.AdvanceWriteOffset (
                    EncryptAndFrame (
                        plaintext,
                        plaintextLength,
                        publicKey,
                        padding,
                        ciphertext.GetWritePtr ()));
                return ciphertext;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t RSA::Decrypt (
                const void *ciphertext,
                std::size_t ciphertextLength,
                AsymmetricKey::SharedPtr privateKey,
                util::i32 padding,
                util::ui8 *plaintext) {
            if (ciphertext != 0 && ciphertextLength > 0 &&
                    privateKey.Get () != 0 && privateKey->IsPrivate () &&
                    privateKey->GetKeyType () == OPENSSL_PKEY_RSA &&
                    IsValidPadding (padding) &&
                    plaintext != 0) {
                EVP_PKEY_CTXPtr ctx (
                    EVP_PKEY_CTX_new (
                        ((OpenSSLAsymmetricKey *)privateKey.Get ())->key.get (),
                        OpenSSLInit::engine));
                if (ctx.get () != 0 &&
                        EVP_PKEY_decrypt_init (ctx.get ()) == 1 &&
                        EVP_PKEY_CTX_set_rsa_padding (ctx.get (), padding) == 1) {
                    size_t plaintextLength = privateKey->GetKeyLength ();
                    if (EVP_PKEY_decrypt (ctx.get (), plaintext, &plaintextLength,
                            (const util::ui8 *)ciphertext, ciphertextLength) == 1) {
                        return plaintextLength;
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

        util::Buffer RSA::Decrypt (
                const void *ciphertext,
                std::size_t ciphertextLength,
                AsymmetricKey::SharedPtr privateKey,
                util::i32 padding,
                bool secure,
                util::Endianness endianness) {
            if (ciphertext != 0 && ciphertextLength > 0 &&
                    privateKey.Get () != 0 && privateKey->IsPrivate () &&
                    privateKey->GetKeyType () == OPENSSL_PKEY_RSA &&
                    IsValidPadding (padding)) {
                util::Buffer plaintext = secure ?
                    util::SecureBuffer (endianness, privateKey->GetKeyLength ()) :
                    util::Buffer (endianness, privateKey->GetKeyLength ());
                plaintext.AdvanceWriteOffset (
                    Decrypt (
                        ciphertext,
                        ciphertextLength,
                        privateKey,
                        padding,
                        plaintext.GetWritePtr ()));
                return plaintext;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        namespace {
            struct RSAHeader {
                util::ui8 cipherIndex;
                util::ui8 keyLength;
                const util::ui8 *key;

                RSAHeader (
                    util::ui8 cipherIndex_ = 0,
                    util::ui8 keyLength_ = 0,
                    const util::ui8 *key_ = 0) :
                    cipherIndex (cipherIndex_),
                    keyLength (keyLength_),
                    key (key_) {}

                static std::size_t Size (std::size_t cipherIndex) {
                    return
                        util::UI8_SIZE +
                        util::UI8_SIZE +
                        GetCipherKeyLength (CipherSuite::GetOpenSSLCipherByIndex (cipherIndex));
                }
            };

            inline util::Serializer &operator << (
                    util::Serializer &serializer,
                    const RSAHeader &header) {
                if (header.cipherIndex < CipherSuite::GetCiphers ().size () &&
                        header.keyLength == GetCipherKeyLength (
                            CipherSuite::GetOpenSSLCipherByIndex (header.cipherIndex)) &&
                        header.key != 0) {
                    serializer << header.cipherIndex << header.keyLength;
                    serializer.Write (header.key, header.keyLength);
                    return serializer;
                }
                else {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                }
            }

            inline util::Buffer &operator >> (
                    util::Buffer &buffer,
                    RSAHeader &header) {
                buffer >> header.cipherIndex;
                if (header.cipherIndex < CipherSuite::GetCiphers ().size ()) {
                    buffer >> header.keyLength;
                    if (header.keyLength == GetCipherKeyLength (
                            CipherSuite::GetOpenSSLCipherByIndex (header.cipherIndex))) {
                        header.key = buffer.GetReadPtr ();
                        if (buffer.AdvanceReadOffset (header.keyLength) == header.keyLength) {
                            return buffer;
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Invalid key: %u, " THEKOGANS_UTIL_SIZE_T_FORMAT,
                                header.cipherIndex,
                                header.keyLength);
                        }
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Invalid keyLength: " THEKOGANS_UTIL_SIZE_T_FORMAT,
                            header.keyLength);
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Invalid cipherIndex: %u",
                        header.cipherIndex);
                }
            }

            std::size_t GetCipherIndex (
                    std::size_t keyLength,
                    util::i32 padding = RSA_PKCS1_OAEP_PADDING) {
                std::size_t maxPlaintextLength = RSA::GetMaxPlaintextLength (keyLength, padding);
                for (std::size_t cipherIndex = 0, count = CipherSuite::GetCiphers ().size ();
                        cipherIndex < count; ++cipherIndex) {
                    if (RSAHeader::Size (cipherIndex) <= maxPlaintextLength) {
                        return cipherIndex;
                    }
                }
                return util::NIDX;
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL std::size_t _LIB_THEKOGANS_CRYPTO_API
        RSAEncrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::SharedPtr publicKey,
                util::i32 padding,
                util::ui8 *ciphertext) {
            if (plaintext != 0 && plaintextLength > 0 &&
                    publicKey.Get () != 0 && !publicKey->IsPrivate () &&
                    publicKey->GetKeyType () == OPENSSL_PKEY_RSA &&
                    IsValidPadding (padding) &&
                    ciphertext != 0) {
                std::size_t cipherIndex = GetCipherIndex (publicKey->GetKeyLength (), padding);
                SymmetricKey::SharedPtr key =
                    SymmetricKey::FromRandom (
                        SymmetricKey::MIN_RANDOM_LENGTH,
                        0,
                        0,
                        GetCipherKeyLength (
                            CipherSuite::GetOpenSSLCipherByIndex (cipherIndex)));
                util::SecureBuffer headerBuffer (
                    util::NetworkEndian,
                    RSAHeader::Size (cipherIndex));
                headerBuffer << RSAHeader (
                    (util::ui8)cipherIndex,
                    (util::ui8)key->GetKeyLength (),
                    key->Get ().GetReadPtr ());
                std::size_t headerLength =
                    RSA::EncryptAndEnlengthen (
                        headerBuffer.GetReadPtr (),
                        headerBuffer.GetDataAvailableForReading (),
                        publicKey,
                        padding,
                        ciphertext);
                Cipher cipher (
                    key,
                    CipherSuite::GetOpenSSLCipherByIndex (cipherIndex));
                std::size_t ciphertextLength =
                    cipher.EncryptAndEnlengthen (
                        plaintext,
                        plaintextLength,
                        0,
                        0,
                        ciphertext + headerLength);
                return headerLength + ciphertextLength;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL util::Buffer _LIB_THEKOGANS_CRYPTO_API
        RSAEncrypt (
                const void *plaintext,
                std::size_t plaintextLength,
                AsymmetricKey::SharedPtr publicKey,
                util::i32 padding) {
            if (plaintext != 0 && plaintextLength > 0 &&
                    publicKey.Get () != 0 && !publicKey->IsPrivate () &&
                    publicKey->GetKeyType () == OPENSSL_PKEY_RSA &&
                    IsValidPadding (padding)) {
                util::Buffer buffer (
                    util::NetworkEndian,
                    GetMaxBufferLength (publicKey->GetKeyLength ()) +
                    Cipher::GetMaxBufferLength (plaintextLength));
                buffer.AdvanceWriteOffset (
                    RSAEncrypt (
                        plaintext,
                        plaintextLength,
                        publicKey,
                        padding,
                        buffer.GetWritePtr ()));
                return buffer;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL std::size_t _LIB_THEKOGANS_CRYPTO_API
        RSADecrypt (
                const void *ciphertext,
                std::size_t ciphertextLength,
                AsymmetricKey::SharedPtr privateKey,
                util::i32 padding,
                util::ui8 *plaintext) {
            if (ciphertext != 0 && ciphertextLength > 0 &&
                    privateKey.Get () != 0 && privateKey->IsPrivate () &&
                    privateKey->GetKeyType () == OPENSSL_PKEY_RSA &&
                    IsValidPadding (padding) &&
                    plaintext != 0) {
                util::TenantReadBuffer buffer (util::NetworkEndian, ciphertext, ciphertextLength);
                util::ui32 headerLength;
                buffer >> headerLength;
                util::SecureBuffer headerBuffer (
                    util::NetworkEndian,
                    headerLength);
                headerBuffer.AdvanceWriteOffset (
                    RSA::Decrypt (
                        buffer.GetReadPtr (),
                        headerLength,
                        privateKey,
                        padding,
                        headerBuffer.GetWritePtr ()));
                buffer.AdvanceReadOffset (headerLength);
                RSAHeader header;
                headerBuffer >> header;
                Cipher cipher (
                    SymmetricKey::SharedPtr (
                        new SymmetricKey (header.key, header.keyLength)),
                    CipherSuite::GetOpenSSLCipherByIndex (header.cipherIndex));
                util::ui32 ciphertextLength;
                buffer >> ciphertextLength;
                return cipher.Decrypt (
                    buffer.GetReadPtr (),
                    ciphertextLength,
                    0,
                    0,
                    plaintext);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        _LIB_THEKOGANS_CRYPTO_DECL util::Buffer _LIB_THEKOGANS_CRYPTO_API
        RSADecrypt (
                const void *ciphertext,
                std::size_t ciphertextLength,
                AsymmetricKey::SharedPtr privateKey,
                util::i32 padding,
                bool secure,
                util::Endianness endianness) {
            if (ciphertext != 0 && ciphertextLength > 0 &&
                    privateKey.Get () != 0 && privateKey->IsPrivate () &&
                    privateKey->GetKeyType () == OPENSSL_PKEY_RSA &&
                    IsValidPadding (padding)) {
                util::Buffer buffer = secure ?
                    util::SecureBuffer (endianness, ciphertextLength) :
                    util::Buffer (endianness, ciphertextLength);
                buffer.AdvanceWriteOffset (
                    RSADecrypt (
                        ciphertext,
                        ciphertextLength,
                        privateKey,
                        padding,
                        buffer.GetWritePtr ()));
                return buffer;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
