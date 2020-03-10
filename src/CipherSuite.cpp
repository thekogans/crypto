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

#include "thekogans/crypto/DHEKeyExchange.h"
#include "thekogans/crypto/RSAKeyExchange.h"
#include "thekogans/crypto/X25519AsymmetricKey.h"
#include "thekogans/crypto/Ed25519AsymmetricKey.h"
#include "thekogans/crypto/HMAC.h"
#include "thekogans/crypto/CMAC.h"
#include "thekogans/crypto/DSA.h"
#include "thekogans/crypto/RSA.h"
#include "thekogans/crypto/EC.h"
#if defined (THEKOGANS_CRYPTO_HAVE_BLAKE2)
    #include "thekogans/crypto/Blake2b.h"
    #include "thekogans/crypto/Blake2s.h"
#endif // defined (THEKOGANS_CRYPTO_HAVE_BLAKE2)
#include "thekogans/crypto/CipherSuite.h"

namespace thekogans {
    namespace crypto {

        const char * const CipherSuite::KEY_EXCHANGE_ECDHE = "ECDHE";
        const char * const CipherSuite::KEY_EXCHANGE_DHE = "DHE";
        const char * const CipherSuite::KEY_EXCHANGE_RSA = "RSA";

        const char * const CipherSuite::AUTHENTICATOR_ECDSA = "ECDSA";
        const char * const CipherSuite::AUTHENTICATOR_DSA = "DSA";
        const char * const CipherSuite::AUTHENTICATOR_RSA = "RSA";
        const char * const CipherSuite::AUTHENTICATOR_Ed25519 = "Ed25519";

        const char * const CipherSuite::CIPHER_AES_256_GCM = "AES-256-GCM";
        const char * const CipherSuite::CIPHER_AES_192_GCM = "AES-192-GCM";
        const char * const CipherSuite::CIPHER_AES_128_GCM = "AES-128-GCM";
        const char * const CipherSuite::CIPHER_AES_256_CBC = "AES-256-CBC";
        const char * const CipherSuite::CIPHER_AES_192_CBC = "AES-192-CBC";
        const char * const CipherSuite::CIPHER_AES_128_CBC = "AES-128-CBC";

    #if defined (THEKOGANS_CRYPTO_HAVE_BLAKE2)
        const char * const CipherSuite::MESSAGE_DIGEST_BLAKE2B_512 = "BLAKE2B-512";
        const char * const CipherSuite::MESSAGE_DIGEST_BLAKE2B_384 = "BLAKE2B-384";
        const char * const CipherSuite::MESSAGE_DIGEST_BLAKE2B_256 = "BLAKE2B-256";
        const char * const CipherSuite::MESSAGE_DIGEST_BLAKE2S_256 = "BLAKE2S-256";
    #endif // defined (THEKOGANS_CRYPTO_HAVE_BLAKE2)

        const char * const CipherSuite::MESSAGE_DIGEST_SHA2_512 = "SHA2-512";
        const char * const CipherSuite::MESSAGE_DIGEST_SHA2_384 = "SHA2-384";
        const char * const CipherSuite::MESSAGE_DIGEST_SHA2_256 = "SHA2-256";

        CipherSuite::CipherSuite (
                const std::string &keyExchange_,
                const std::string &authenticator_,
                const std::string &cipher_,
                const std::string &messageDigest_) :
                keyExchange (keyExchange_),
                authenticator (authenticator_),
                cipher (cipher_),
                messageDigest (messageDigest_) {
            if (!IsValid ()) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid cipher suite: %s",
                    ToString ().c_str ());
            }
        }

        CipherSuite::CipherSuite (util::Serializer &serializer) {
            serializer >> keyExchange >> authenticator >> cipher >> messageDigest;
            if (!IsValid ()) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid cipher suite: %s",
                    ToString ().c_str ());
            }
        }

        CipherSuite::CipherSuite (const std::string &cipherSuite) {
            Parse (cipherSuite);
        }

        CipherSuite::CipherSuite (const CipherSuite &cipherSuite) :
                keyExchange (cipherSuite.keyExchange),
                authenticator (cipherSuite.authenticator),
                cipher (cipherSuite.cipher),
                messageDigest (cipherSuite.messageDigest) {
            if (!IsValid ()) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid cipher suite: %s",
                    ToString ().c_str ());
            }
        }

        CipherSuite &CipherSuite::operator = (const std::string &cipherSuite) {
            Parse (cipherSuite);
            return *this;
        }

        CipherSuite &CipherSuite::operator = (const CipherSuite &cipherSuite) {
            if (&cipherSuite != this) {
                keyExchange = cipherSuite.keyExchange;
                authenticator = cipherSuite.authenticator;
                cipher = cipherSuite.cipher;
                messageDigest = cipherSuite.messageDigest;
                if (!IsValid ()) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Invalid cipher suite: %s",
                        ToString ().c_str ());
                }
            }
            return *this;
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
                CipherSuite::AUTHENTICATOR_RSA,
                CipherSuite::AUTHENTICATOR_Ed25519
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
            #if defined (THEKOGANS_CRYPTO_HAVE_BLAKE2)
                {CipherSuite::MESSAGE_DIGEST_BLAKE2B_512, EVP_blake2b512 ()},
                {CipherSuite::MESSAGE_DIGEST_BLAKE2B_384, EVP_blake2b384 ()},
                {CipherSuite::MESSAGE_DIGEST_BLAKE2B_256, EVP_blake2b256 ()},
                {CipherSuite::MESSAGE_DIGEST_BLAKE2S_256, EVP_blake2s256 ()},
            #endif // defined (THEKOGANS_CRYPTO_HAVE_BLAKE2)
                {CipherSuite::MESSAGE_DIGEST_SHA2_512, EVP_sha512 ()},
                {CipherSuite::MESSAGE_DIGEST_SHA2_384, EVP_sha384 ()},
                {CipherSuite::MESSAGE_DIGEST_SHA2_256, EVP_sha256 ()}
            };
            const std::size_t messageDigestsSize = THEKOGANS_UTIL_ARRAY_SIZE (messageDigests);

            // Certain algorithms cannot be combined in to a cipher suite.
            // This method will contain a never ending list of exceptions.
            bool ValidateAlgorithms (
                    const std::string &keyExchange,
                    const std::string &authenticator,
                    const std::string &cipher,
                    const std::string &messageDigest) {
                // [EC]DSA is only specified for SHA.
                if ((authenticator == CipherSuite::AUTHENTICATOR_ECDSA ||
                        authenticator == CipherSuite::AUTHENTICATOR_DSA) &&
                        messageDigest != CipherSuite::MESSAGE_DIGEST_SHA2_512 &&
                        messageDigest != CipherSuite::MESSAGE_DIGEST_SHA2_384 &&
                        messageDigest != CipherSuite::MESSAGE_DIGEST_SHA2_256) {
                    return false;
                }
                // FIXME: Add other exceptions above this comment.
                return true;
            }

            std::vector<CipherSuite> BuildCipherSuites () {
                std::vector<CipherSuite> cipherSuites;
                for (std::size_t i = 0; i < keyExchangesSize; ++i) {
                    for (std::size_t j = 0; j < authenticatorsSize; ++j) {
                        for (std::size_t k = 0; k < ciphersSize; ++k) {
                            for (std::size_t l = 0; l < messageDigestsSize; ++l) {
                                if (ValidateAlgorithms (
                                        keyExchanges[i],
                                        authenticators[j],
                                        ciphers[k].name,
                                        messageDigests[l].name)) {
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
                }
                return cipherSuites;
            }

            std::vector<std::string> BuildKeyExchanges () {
                std::vector<std::string> keyExchanges_;
                for (std::size_t i = 0; i < keyExchangesSize; ++i) {
                    keyExchanges_.push_back (keyExchanges[i]);
                }
                return keyExchanges_;
            }

            std::vector<std::string> BuildAuthenticators () {
                std::vector<std::string> authenticators_;
                for (std::size_t i = 0; i < authenticatorsSize; ++i) {
                    authenticators_.push_back (authenticators[i]);
                }
                return authenticators_;
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

        const CipherSuite CipherSuite::Empty;
        const CipherSuite CipherSuite::Strongest (
            KEY_EXCHANGE_ECDHE,
            AUTHENTICATOR_ECDSA,
            CIPHER_AES_256_GCM,
            MESSAGE_DIGEST_SHA2_512);
        const CipherSuite CipherSuite::Weakest (
            KEY_EXCHANGE_RSA,
            AUTHENTICATOR_RSA,
            CIPHER_AES_128_CBC,
            MESSAGE_DIGEST_SHA2_256);

        const std::vector<CipherSuite> &CipherSuite::GetCipherSuites () {
            static std::vector<CipherSuite> cipherSuites = BuildCipherSuites ();
            return cipherSuites;
        }

        const std::vector<std::string> &CipherSuite::GetKeyExchanges () {
            static std::vector<std::string> keyExchanges = BuildKeyExchanges ();
            return keyExchanges;
        }

        const std::vector<std::string> &CipherSuite::GetAuthenticators () {
            static std::vector<std::string> authenticators = BuildAuthenticators ();
            return authenticators;
        }

        const std::vector<std::string> &CipherSuite::GetCiphers () {
            static std::vector<std::string> ciphers = BuildCiphers ();
            return ciphers;
        }

        const std::vector<std::string> &CipherSuite::GetMessageDigests () {
            static std::vector<std::string> messageDigests = BuildMessageDigests ();
            return messageDigests;
        }

        const EVP_CIPHER *CipherSuite::GetOpenSSLCipherByName (const std::string &cipherName) {
            for (std::size_t i = 0; i < ciphersSize; ++i) {
                if (ciphers[i].name == cipherName) {
                    return ciphers[i].cipher;
                }
            }
            return 0;
        }

        const EVP_CIPHER *CipherSuite::GetOpenSSLCipherByIndex (std::size_t cipherIndex) {
            return cipherIndex < ciphersSize ? ciphers[cipherIndex].cipher : 0;
        }

        std::string CipherSuite::GetOpenSSLCipherName (const EVP_CIPHER *cipher) {
            for (std::size_t i = 0; i < ciphersSize; ++i) {
                if (ciphers[i].cipher == cipher) {
                    return ciphers[i].name;
                }
            }
            return std::string ();
        }

        const EVP_MD *CipherSuite::GetOpenSSLMessageDigestByName (const std::string &messageDigestName) {
            for (std::size_t i = 0; i < messageDigestsSize; ++i) {
                if (messageDigests[i].name == messageDigestName) {
                    return messageDigests[i].md;
                }
            }
            return 0;
        }

        std::string CipherSuite::GetOpenSSLMessageDigestName (const EVP_MD *md) {
            for (std::size_t i = 0; i < messageDigestsSize; ++i) {
                if (messageDigests[i].md == md) {
                    return messageDigests[i].name;
                }
            }
            return std::string ();
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
                (keyExchange.empty () &&
                authenticator.empty () &&
                cipher.empty () &&
                messageDigest.empty ()) ||
                (IsValidKeyExchange (keyExchange) &&
                IsValidAuthenticator (authenticator) &&
                IsValidCipher (cipher) &&
                IsValidMessageDigest (messageDigest) &&
                ValidateAlgorithms (keyExchange, authenticator, cipher, messageDigest));
        }

        bool CipherSuite::VerifyKeyExchangeParams (const Params &params) const {
            const char *type = params.GetKeyType ();
            return
                (keyExchange == CipherSuite::KEY_EXCHANGE_ECDHE &&
                    (type == OPENSSL_PKEY_EC || type == X25519AsymmetricKey::KEY_TYPE)) ||
                (keyExchange == CipherSuite::KEY_EXCHANGE_DHE && type == OPENSSL_PKEY_DH);
        }

        bool CipherSuite::VerifyKeyExchangeKey (const AsymmetricKey &key) const {
            const char *type = key.GetKeyType ();
            return keyExchange == CipherSuite::KEY_EXCHANGE_RSA && type == OPENSSL_PKEY_RSA;
        }

        bool CipherSuite::VerifyAuthenticatorParams (const Params &params) const {
            const char *type = params.GetKeyType ();
            return
                (authenticator == CipherSuite::AUTHENTICATOR_ECDSA &&
                    (type == OPENSSL_PKEY_EC || type == Ed25519AsymmetricKey::KEY_TYPE)) ||
                (authenticator == CipherSuite::AUTHENTICATOR_DSA && type == OPENSSL_PKEY_DSA);
        }

        bool CipherSuite::VerifyAuthenticatorKey (const AsymmetricKey &key) const {
            const char *type = key.GetKeyType ();
            return
                (authenticator == CipherSuite::AUTHENTICATOR_ECDSA &&
                    (type == OPENSSL_PKEY_EC || type == Ed25519AsymmetricKey::KEY_TYPE)) ||
                (authenticator == CipherSuite::AUTHENTICATOR_DSA && type == OPENSSL_PKEY_DSA) ||
                (authenticator == CipherSuite::AUTHENTICATOR_RSA && type == OPENSSL_PKEY_RSA) ||
                (authenticator == CipherSuite::AUTHENTICATOR_Ed25519 && type == Ed25519AsymmetricKey::KEY_TYPE);
        }

        bool CipherSuite::VerifyCipherKey (const SymmetricKey &key) const {
            return GetCipherKeyLength (GetOpenSSLCipherByName (cipher)) == key.GetKeyLength ();
        }

        bool CipherSuite::VerifyMACKey (
                const SymmetricKey &key,
                bool hmac) const {
            return hmac || VerifyCipherKey (key);
        }

        KeyExchange::Ptr CipherSuite::GetDHEKeyExchange (
                const ID &keyExchangeId,
                Params::Ptr params,
                const void *salt,
                std::size_t saltLength,
                std::size_t count,
                const ID &keyId,
                const std::string &keyName,
                const std::string &keyDescription) const {
            if (params.Get () != 0 && VerifyKeyExchangeParams (*params)) {
                return KeyExchange::Ptr (
                    new DHEKeyExchange (
                        keyExchangeId,
                        params,
                        salt,
                        saltLength,
                        GetCipherKeyLength (GetOpenSSLCipher ()),
                        GetOpenSSLMessageDigest (),
                        count,
                        keyId,
                        keyName,
                        keyDescription));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        KeyExchange::Ptr CipherSuite::GetRSAKeyExchange (
                const ID &keyExchangeId,
                AsymmetricKey::Ptr key,
                std::size_t secretLength,
                const void *salt,
                std::size_t saltLength,
                std::size_t count,
                const ID &keyId,
                const std::string &keyName,
                const std::string &keyDescription) const {
            if (key.Get () != 0 && VerifyKeyExchangeKey (*key)) {
                return KeyExchange::Ptr (
                    new RSAKeyExchange (
                        keyExchangeId,
                        key,
                        secretLength,
                        salt,
                        saltLength,
                        GetCipherKeyLength (GetOpenSSLCipher ()),
                        GetOpenSSLMessageDigest (),
                        count,
                        keyId,
                        keyName,
                        keyDescription));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Authenticator::Ptr CipherSuite::GetAuthenticator (AsymmetricKey::Ptr key) const {
            if (key.Get () != 0 && VerifyAuthenticatorKey (*key)) {
                return Authenticator::Ptr (
                    new Authenticator (key, GetMessageDigest ()));
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
                        GetOpenSSLCipherByName (cipher),
                        GetOpenSSLMessageDigestByName (messageDigest)));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        MAC::Ptr CipherSuite::GetHMAC (SymmetricKey::Ptr key) const {
            if (key.Get () != 0 && VerifyMACKey (*key, true)) {
                return MAC::Ptr (new HMAC (key, GetOpenSSLMessageDigest ()));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        MAC::Ptr CipherSuite::GetCMAC (SymmetricKey::Ptr key) const {
            if (key.Get () != 0 && VerifyMACKey (*key, false)) {
                return MAC::Ptr (new CMAC (key, GetOpenSSLCipher ()));
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        MessageDigest::Ptr CipherSuite::GetMessageDigest () const {
            return MessageDigest::Ptr (
                new MessageDigest (GetOpenSSLMessageDigestByName (messageDigest)));
        }

        AsymmetricKey::Ptr CipherSuite::CreateAuthenticatorKey (
                std::size_t keyLength,
                BIGNUMPtr RSAPublicExponent,
                const ID &id,
                const std::string &name,
                const std::string &description) const {
            if (!IsAuthenticatorEC ()) {
                if (authenticator == AUTHENTICATOR_DSA) {
                    return crypto::DSA::ParamsFromKeyLength (keyLength, id, name, description)->CreateKey ();
                }
                else if (authenticator == AUTHENTICATOR_RSA) {
                    return crypto::RSA::CreateKey (keyLength,
                        std::move (RSAPublicExponent), id, name, description);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unknown authenticator: %s",
                        authenticator.c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid authenticator: %s",
                    authenticator.c_str ());
            }
        }

        AsymmetricKey::Ptr CipherSuite::CreateAuthenticatorKey (
                const std::string curveName,
                const ID &id,
                const std::string &name,
                const std::string &description) const {
            if (IsAuthenticatorEC ()) {
                if (authenticator == AUTHENTICATOR_ECDSA || authenticator == AUTHENTICATOR_Ed25519) {
                    return EC::ParamsFromCurveName (curveName)->CreateKey ();
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unknown authenticator: %s",
                        authenticator.c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid authenticator: %s",
                    authenticator.c_str ());
            }
        }

        void CipherSuite::Parse (const std::string &cipherSuite) {
            keyExchange.clear ();
            authenticator.clear ();
            cipher.clear ();
            messageDigest.clear ();
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
                    "Invalid cipher suite: %s",
                    cipherSuite.c_str ());
            }
        }

    } // namespace crypto
} // namespace thekogans
