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

#include "thekogans/crypto/CipherSuite.h"

namespace thekogans {
    namespace crypto {

        const char * const CipherSuite::KEY_EXCHANGE_ECDHE = "ECDHE";
        const char * const CipherSuite::KEY_EXCHANGE_DHE = "DHE";
        const char * const CipherSuite::KEY_EXCHANGE_RSA = "RSA";

        const char * const CipherSuite::AUTHENTICATOR_ECDSA = "ECDSA";
        const char * const CipherSuite::AUTHENTICATOR_DSA = "DSA";
        const char * const CipherSuite::AUTHENTICATOR_RSA = "RSA";

        const char * const CipherSuite::CIPHER_AES_256_GCM = "AES-256-GCM";
        const char * const CipherSuite::CIPHER_AES_192_GCM = "AES-192-GCM";
        const char * const CipherSuite::CIPHER_AES_128_GCM = "AES-128-GCM";
        const char * const CipherSuite::CIPHER_AES_256_CBC = "AES-256-CBC";
        const char * const CipherSuite::CIPHER_AES_192_CBC = "AES-192-CBC";
        const char * const CipherSuite::CIPHER_AES_128_CBC = "AES-128-CBC";

        const char * const CipherSuite::MESSAGE_DIGEST_SHA2_512 = "SHA2-512";
        const char * const CipherSuite::MESSAGE_DIGEST_SHA2_384 = "SHA2-384";
        const char * const CipherSuite::MESSAGE_DIGEST_SHA2_256 = "SHA2-256";

        CipherSuite::CipherSuite (const std::string &cipherSuite) {
            std::string::size_type keyExchangeSeparator = cipherSuite.find_first_of ('_');
            keyExchange = cipherSuite.substr (0, keyExchangeSeparator++);
            std::string::size_type authenticatorSeparator =
                cipherSuite.find_first_of ('_', keyExchangeSeparator);
            authenticator = cipherSuite.substr (
                keyExchangeSeparator,
                authenticatorSeparator++ - keyExchangeSeparator);
            std::string::size_type cipherSeparator =
                cipherSuite.find_first_of ('_', authenticatorSeparator);
            cipher = cipherSuite.substr (
                authenticatorSeparator,
                cipherSeparator++ - authenticatorSeparator);
            messageDigest = cipherSuite.substr (cipherSeparator);
            if (!IsValid ()) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid cipher suite: %s", cipherSuite.c_str ());
            }
        }

        namespace {
            const char *keyExchanges[] = {
                CipherSuite::KEY_EXCHANGE_ECDHE,
                CipherSuite::KEY_EXCHANGE_DHE,
                CipherSuite::KEY_EXCHANGE_RSA
            };
            const std::size_t keyExchangesSize = THEKOGANS_UTIL_ARRAY_SIZE (keyExchanges);

            const char *authenticators[] = {
                CipherSuite::AUTHENTICATOR_ECDSA,
                CipherSuite::AUTHENTICATOR_DSA,
                CipherSuite::AUTHENTICATOR_RSA
            };
            const std::size_t authenticatorsSize = THEKOGANS_UTIL_ARRAY_SIZE (authenticators);

            struct Ciphers {
                const char *name;
                const EVP_CIPHER *cipher;
            } const ciphers[] = {
                {CipherSuite::CIPHER_AES_256_GCM, EVP_aes_256_gcm ()},
                {CipherSuite::CIPHER_AES_192_GCM, EVP_aes_192_gcm ()},
                {CipherSuite::CIPHER_AES_128_GCM, EVP_aes_128_gcm ()},
                {CipherSuite::CIPHER_AES_256_CBC, EVP_aes_256_cbc ()},
                {CipherSuite::CIPHER_AES_192_CBC, EVP_aes_192_cbc ()},
                {CipherSuite::CIPHER_AES_128_CBC, EVP_aes_128_cbc ()}
            };
            const std::size_t ciphersSize = THEKOGANS_UTIL_ARRAY_SIZE (ciphers);

            struct MessageDigests {
                const char *name;
                const EVP_MD *md;
            } const messageDigests[] = {
                {CipherSuite::MESSAGE_DIGEST_SHA2_512, EVP_sha512 ()},
                {CipherSuite::MESSAGE_DIGEST_SHA2_384, EVP_sha384 ()},
                {CipherSuite::MESSAGE_DIGEST_SHA2_256, EVP_sha256 ()}
            };
            const std::size_t messageDigestsSize = THEKOGANS_UTIL_ARRAY_SIZE (messageDigests);

            std::vector<CipherSuite> BuildCipherSuites () {
                std::vector<CipherSuite> cipherSuites;
                for (std::size_t i = 0; i < keyExchangesSize; ++i) {
                    for (std::size_t j = 0; j < authenticatorsSize; ++j) {
                        for (std::size_t k = 0; k < ciphersSize; ++k) {
                            for (std::size_t l = 0; l < messageDigestsSize; ++l) {
                                cipherSuites.push_back (
                                    CipherSuite (
                                        keyExchanges[i],
                                        authenticators[j],
                                        ciphers[k].name,
                                        messageDigests[l].name));
                            }
                        }
                    }
                }
                return cipherSuites;
            }

            std::vector<std::string> BuildCiphers () {
                std::vector<std::string> ciphers_;
                for (std::size_t i = 0; i < ciphersSize; ++i) {
                    ciphers_.push_back (ciphers[i].name);
                }
                return ciphers_;
            }

            std::vector<std::string> BuildMessageDigests () {
                std::vector<std::string> messageDigests_;
                for (std::size_t i = 0; i < messageDigestsSize; ++i) {
                    messageDigests_.push_back (messageDigests[i].name);
                }
                return messageDigests_;
            }
        }

        const std::vector<CipherSuite> &CipherSuite::GetCipherSuites () {
            static std::vector<CipherSuite> cipherSuites = BuildCipherSuites ();
            return cipherSuites;
        }

        const std::vector<std::string> &CipherSuite::GetCiphers () {
            static std::vector<std::string> ciphers = BuildCiphers ();
            return ciphers;
        }

        const std::vector<std::string> &CipherSuite::GetMessageDigests () {
            static std::vector<std::string> messageDigests = BuildMessageDigests ();
            return messageDigests;
        }

        const EVP_CIPHER *CipherSuite::GetOpenSSLCipher (const std::string &cipher) {
            for (std::size_t i = 0; i < ciphersSize; ++i) {
                if (ciphers[i].name == cipher) {
                    return ciphers[i].cipher;
                }
            }
            return 0;
        }

        const EVP_MD *CipherSuite::GetOpenSSLMessageDigest (const std::string &messageDigest) {
            for (std::size_t i = 0; i < messageDigestsSize; ++i) {
                if (messageDigests[i].name == messageDigest) {
                    return messageDigests[i].md;
                }
            }
            return 0;
        }

        namespace {
            bool IsValidKeyExchange (const std::string &keyExchange) {
                for (std::size_t i = 0; i < keyExchangesSize; ++i) {
                    if (keyExchanges[i] == keyExchange) {
                        return true;
                    }
                }
                return false;
            }

            bool IsValidAuthenticator (const std::string &authenticator) {
                for (std::size_t i = 0; i < authenticatorsSize; ++i) {
                    if (authenticators[i] == authenticator) {
                        return true;
                    }
                }
                return false;
            }

            bool IsValidCipher (const std::string &cipher) {
                for (std::size_t i = 0; i < ciphersSize; ++i) {
                    if (ciphers[i].name == cipher) {
                        return true;
                    }
                }
                return false;
            }

            bool IsValidMessageDigest (const std::string &messageDigest) {
                for (std::size_t i = 0; i < messageDigestsSize; ++i) {
                    if (messageDigests[i].name == messageDigest) {
                        return true;
                    }
                }
                return false;
            }
        }

        bool CipherSuite::IsValid () const {
            return
                IsValidKeyExchange (keyExchange) &&
                IsValidAuthenticator (authenticator) &&
                IsValidCipher (cipher) &&
                IsValidMessageDigest (messageDigest);
        }

        bool CipherSuite::VerifyKeyExchangeParams (const Params &params) const {
            util::i32 type = params.GetType ();
            return
                (keyExchange == CipherSuite::KEY_EXCHANGE_ECDHE && type == EVP_PKEY_EC) ||
                (keyExchange == CipherSuite::KEY_EXCHANGE_DHE && type == EVP_PKEY_DH);
        }

        bool CipherSuite::VerifyKeyExchangeKey (const AsymmetricKey &key) const {
            util::i32 type = key.GetType ();
            return
                (keyExchange == CipherSuite::KEY_EXCHANGE_ECDHE && type == EVP_PKEY_EC) ||
                (keyExchange == CipherSuite::KEY_EXCHANGE_DHE && type == EVP_PKEY_DH) ||
                (keyExchange == CipherSuite::KEY_EXCHANGE_RSA && type == EVP_PKEY_RSA);
        }

        bool CipherSuite::VerifyAuthenticatorParams (const Params &params) const {
            util::i32 type = params.GetType ();
            return
                (authenticator == CipherSuite::AUTHENTICATOR_ECDSA && type == EVP_PKEY_EC) ||
                (authenticator == CipherSuite::AUTHENTICATOR_DSA && type == EVP_PKEY_DSA);
        }

        bool CipherSuite::VerifyAuthenticatorKey (const AsymmetricKey &key) const {
            util::i32 type = key.GetType ();
            return
                (authenticator == CipherSuite::AUTHENTICATOR_ECDSA && type == EVP_PKEY_EC) ||
                (authenticator == CipherSuite::AUTHENTICATOR_DSA && type == EVP_PKEY_DSA) ||
                (authenticator == CipherSuite::AUTHENTICATOR_RSA && type == EVP_PKEY_RSA);
        }

        bool CipherSuite::VerifyCipherKey (const SymmetricKey &key) const {
            return Cipher::GetKeyLength (GetOpenSSLCipher (cipher)) == key.Length ();
        }

        bool CipherSuite::VerifyMACKey (const AsymmetricKey &key) const {
            util::i32 type = key.GetType ();
            return type == EVP_PKEY_HMAC || type == EVP_PKEY_CMAC;
        }

        KeyExchange::Ptr CipherSuite::GetKeyExchange (AsymmetricKey::Ptr privateKey) const {
            if (privateKey.Get () != 0 && VerifyKeyExchangeKey (*privateKey)) {
                return KeyExchange::Ptr (new KeyExchange (privateKey));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Authenticator::Ptr CipherSuite::GetAuthenticator (
                Authenticator::Op op,
                AsymmetricKey::Ptr key) const {
            if (key.Get () != 0 &&
                    ((op == Authenticator::Sign && key->IsPrivate ()) ||
                        (op == Authenticator::Verify && !key->IsPrivate ())) &&
                    VerifyAuthenticatorKey (*key)) {
                return Authenticator::Ptr (
                    new Authenticator (
                        op,
                        key,
                        GetOpenSSLMessageDigest (messageDigest)));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Cipher::Ptr CipherSuite::GetCipher (SymmetricKey::Ptr key) const {
            if (key.Get () != 0 && VerifyCipherKey (*key)) {
                return Cipher::Ptr (
                    new Cipher (
                        key,
                        GetOpenSSLCipher (cipher),
                        GetOpenSSLMessageDigest (messageDigest)));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        MessageDigest::Ptr CipherSuite::GetMessageDigest () const {
            return MessageDigest::Ptr (
                new MessageDigest (GetOpenSSLMessageDigest (messageDigest)));
        }

    } // namespace crypto
} // namespace thekogans
