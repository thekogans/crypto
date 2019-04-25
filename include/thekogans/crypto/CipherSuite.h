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

#if !defined (__thekogans_crypto_CipherSuite_h)
#define __thekogans_crypto_CipherSuite_h

#include <cstddef>
#include <memory>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Params.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/KeyExchange.h"
#include "thekogans/crypto/RSAKeyExchange.h"
#include "thekogans/crypto/Authenticator.h"
#include "thekogans/crypto/Cipher.h"
#include "thekogans/crypto/MessageDigest.h"

namespace thekogans {
    namespace crypto {

        /// \struct CipherSuite CipherSuite.h thekogans/crypto/CipherSuite.h
        ///
        /// \brief
        /// CipherSuite collects the various algorithms necessary for key exchange, authentication,
        /// symmetric encryption/decryption, MAC and message digest.
        ///
        /// OpenSSL canonical cipher suite names have the following format: Kx-Auth-Enc-Mode-MD.
        ///
        /// Kx = Key exchange.
        /// Auth = Asymmetric encryption/decryption and sign/verify.
        /// Enc = Symmetric encryption/decryption.
        /// Mode = Symmetric encryption mode.
        /// MD = Message digest.
        ///
        /// Example cipher suite name would be: ECDHE-ECDSA-AES256-CBC-SHA384.
        ///
        /// Kx = ECDHE.
        /// Auth = ECDSA.
        /// Enc = AES256.
        /// Mode = CBC.
        /// MD = SHA384.
        ///
        /// thekogans_crypto uses a similar but slightly different format. Firstly, we only
        /// support a narrow set of algorithms and their combinations. Second, we replace '-'
        /// separator with '_'. And lastly, cipher (Enc-Mode) and message digest (MD) names
        /// are different.
        ///
        /// Ex: ECDHE_ECDSA_AES-256-CBC_SHA2-512.
        ///
        /// Kx = ECDHE.
        /// Auth = ECDSA.
        /// Enc-Mode = AES-256-CBC.
        /// MD = SHA2-512.

        struct _LIB_THEKOGANS_CRYPTO_DECL CipherSuite {
            /// \brief
            /// "ECDHE"
            static const char * const KEY_EXCHANGE_ECDHE;
            /// \brief
            /// "DHE"
            static const char * const KEY_EXCHANGE_DHE;
            /// \brief
            /// "RSA"
            static const char * const KEY_EXCHANGE_RSA;

            /// \brief
            /// "ECDSA"
            static const char * const AUTHENTICATOR_ECDSA;
            /// \brief
            /// "DSA"
            static const char * const AUTHENTICATOR_DSA;
            /// \brief
            /// "RSA"
            static const char * const AUTHENTICATOR_RSA;
            /// \brief
            /// "Ed25519"
            static const char * const AUTHENTICATOR_Ed25519;

            /// \brief
            /// "AES-256-GCM"
            static const char * const CIPHER_AES_256_GCM;
            /// \brief
            /// "AES-192-GCM"
            static const char * const CIPHER_AES_192_GCM;
            /// \brief
            /// "AES-128-GCM"
            static const char * const CIPHER_AES_128_GCM;
            /// \brief
            /// "AES-256-CBC"
            static const char * const CIPHER_AES_256_CBC;
            /// \brief
            /// "AES-192-CBC"
            static const char * const CIPHER_AES_192_CBC;
            /// \brief
            /// "AES-128-CBC"
            static const char * const CIPHER_AES_128_CBC;

        #if defined (THEKOGANS_CRYPTO_HAVE_BLAKE2)
            /// \brief
            /// "BLAKE2B-512"
            static const char * const MESSAGE_DIGEST_BLAKE2B_512;
            /// \brief
            /// "BLAKE2B-384"
            static const char * const MESSAGE_DIGEST_BLAKE2B_384;
            /// \brief
            /// "BLAKE2B-256"
            static const char * const MESSAGE_DIGEST_BLAKE2B_256;
            /// \brief
            /// "BLAKE2S-256"
            static const char * const MESSAGE_DIGEST_BLAKE2S_256;
        #endif // defined (THEKOGANS_CRYPTO_HAVE_BLAKE2)

            /// \brief
            /// "SHA2-512"
            static const char * const MESSAGE_DIGEST_SHA2_512;
            /// \brief
            /// "SHA2-384"
            static const char * const MESSAGE_DIGEST_SHA2_384;
            /// \brief
            /// "SHA2-256"
            static const char * const MESSAGE_DIGEST_SHA2_256;

            /// \brief
            /// \see{KeyExchange}.
            std::string keyExchange;
            /// \brief
            /// \see{Authenticator}.
            std::string authenticator;
            /// \brief
            /// \see{Cipher}.
            std::string cipher;
            /// \brief
            /// \see{MessageDigest}.
            std::string messageDigest;

            /// \brief
            /// ctor.
            CipherSuite () {}
            /// \brief
            /// ctor.
            /// \param[in] keyExchange_ \see{KeyExchange}.
            /// \param[in] authenticator_ \see{Authenticator}.
            /// \param[in] cipher_ \see{Cipher}.
            /// \param[in] messageDigest_ \see{MessageDigest}.
            CipherSuite (
                const std::string &keyExchange_,
                const std::string &authenticator_,
                const std::string &cipher_,
                const std::string &messageDigest_);
            /// \brief
            /// ctor.
            /// \param[in] serializer Serializer containing the cipher suite.
            explicit CipherSuite (util::Serializer &serializer);
            /// \brief
            /// ctor.
            /// \param[in] cipherSuite String encoded cipher suite: Kx_Auth_Enc_MD.
            explicit CipherSuite (const std::string &cipherSuite);
            /// \brief
            /// copy ctor.
            /// \param[in] cipherSuite Cipher suite to copy.
            CipherSuite (const CipherSuite &cipherSuite);

            /// \brief
            /// Empty cipher suite.
            static const CipherSuite Empty;
            /// \brief
            /// Strongest cipher suite.
            static const CipherSuite Strongest;
            /// \brief
            /// Weakest cipher suite.
            static const CipherSuite Weakest;

            /// \brief
            /// Assignment operator.
            /// \param[in] cipherSuite String containing a properly formated cipher suite.
            /// \return *this.
            CipherSuite &operator = (const std::string &cipherSuite);
            /// \brief
            /// Assignment operator.
            /// \param[in] cipherSuite Cipher suite to copy.
            /// \return *this.
            CipherSuite &operator = (const CipherSuite &cipherSuite);

            /// \brief
            /// Return the list of all available cipher suites.
            /// \return The list of all available cipher suites.
            static const std::vector<CipherSuite> &GetCipherSuites ();

            /// \brief
            /// Return the list of all available key exchanges.
            /// \return The list of all available key exchanges.
            static const std::vector<std::string> &GetKeyExchanges ();
            /// \brief
            /// Return the list of all available authenticators.
            /// \return The list of all available authenticators.
            static const std::vector<std::string> &GetAuthenticators ();
            /// \brief
            /// Return the list of all available ciphers.
            /// \return The list of all available ciphers.
            static const std::vector<std::string> &GetCiphers ();
            /// \brief
            /// Return the list of all available message digests.
            /// \return The list of all available message digests.
            static const std::vector<std::string> &GetMessageDigests ();

            /// \brief
            /// Return the OpenSSL EVP_CIPHER represented by the given cipher name.
            /// \param[in] cipherName Cipher name to convert to OpenSSL EVP_CIPHER.
            /// \return OpenSSL EVP_CIPHER represented by the given cipher name.
            static const EVP_CIPHER *GetOpenSSLCipherByName (const std::string &cipherName);
            /// \brief
            /// Return the OpenSSL EVP_CIPHER represented by the given cipher index.
            /// \param[in] cipherIndex Cipher index to convert to OpenSSL EVP_CIPHER.
            /// \return OpenSSL EVP_CIPHER represented by the given cipher index.
            static const EVP_CIPHER *GetOpenSSLCipherByIndex (std::size_t cipherIndex);
            /// \brief
            /// Return the cipher name represented by the given OpenSSL EVP_CIPHER.
            /// \param[in] cipher OpenSSL EVP_CIPHER whose name to return.
            /// \return Cipher name represented by the given OpenSSL EVP_CIPHER.
            static std::string GetOpenSSLCipherName (const EVP_CIPHER *cipher);
            /// \brief
            /// Return the OpenSSL EVP_MD represented by the given message digest name.
            /// \param[in] messageDigestName Message digest name to convert to OpenSSL EVP_MD.
            /// \return OpenSSL EVP_MD represented by the given message digest name.
            static const EVP_MD *GetOpenSSLMessageDigestByName (const std::string &messageDigestName);
            /// \brief
            /// Return the message digest name represented by the given OpenSSL EVP_MD.
            /// \param[in] md OpenSSL EVP_MD whose name to return.
            /// \return Message digest name represented by the given OpenSSL EVP_MD.
            static std::string GetOpenSSLMessageDigestName (const EVP_MD *md);

            /// \brief
            /// Return serialized cipher suite size.
            /// \return Serialized cipher suite size.
            inline std::size_t Size () const {
                return
                    util::Serializer::Size (keyExchange) +
                    util::Serializer::Size (authenticator) +
                    util::Serializer::Size (cipher) +
                    util::Serializer::Size (messageDigest);
            }

            /// \brief
            /// Check if we support the algorithms specified in this cipher suite.
            /// \return true = we support the algorithms specified in this cipher suite.
            bool IsValid () const;

            /// \brief
            /// Verify that the given params are appropriate for this cipher suite \see{DHEKeyExchange}.
            /// \param[in] params \see{Params} to verify.
            /// \return true = given params are appropriate.
            bool VerifyKeyExchangeParams (const Params &params) const;
            /// \brief
            /// Verify that the given key is appropriate for this cipher suite \see{RSAKeyExchange}.
            /// \param[in] key \see{AsymmetricKey} to verify.
            /// \return true = given key is appropriate.
            bool VerifyKeyExchangeKey (const AsymmetricKey &key) const;
            /// \brief
            /// Verify that the given params are appropriate for this cipher suite \see{Authenticator}.
            /// \param[in] params \see{Params} to verify.
            /// \return true = given params are appropriate.
            bool VerifyAuthenticatorParams (const Params &params) const;
            /// \brief
            /// Verify that the given key is appropriate for this cipher suite \see{Authenticator}.
            /// \param[in] key \see{AsymmetricKey} to verify.
            /// \return true = given key is appropriate.
            bool VerifyAuthenticatorKey (const AsymmetricKey &key) const;
            /// \brief
            /// Verify that the given key is appropriate for this cipher suite \see{Cipher}.
            /// \param[in] key \see{SymmetricKey} to verify.
            /// \return true = given key is appropriate.
            bool VerifyCipherKey (const SymmetricKey &key) const;
            /// \brief
            /// Verify that the given key is appropriate for \see{MAC} (EVP_PKEY_HMAC or EVP_PKEY_CMAC).
            /// \param[in] key \see{SymmetricKey} to verify.
            /// \param[in] hmac true == check HMAC key, false == check CMAC key.
            /// \return true = given key is appropriate.
            bool VerifyMACKey (
                const SymmetricKey &key,
                bool hmac) const;

            /// \brief
            /// Return an instance of the \see{DHEKeyExchange} represented by keyExchange (client side [EC]DHE).
            /// \param[in] keyExchangeId \see{KeyExchange::keyExchangeId}.
            /// \param[in] params DH/EC \see{Params} to use for key exchange.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] count A security counter. Increment the count to slow down
            /// \see{SymmetricKey} derivation.
            /// \param[in] keyId Optional \see{SymmetricKey} id.
            /// \param[in] keyName Optional \see{SymmetricKey} name.
            /// \param[in] keyDescription Optional \see{SymmetricKey} description.
            /// \return \see{DHEKeyExchange} instance represented by keyExchange.
            KeyExchange::Ptr GetDHEKeyExchange (
                const ID &keyExchangeId,
                Params::Ptr params,
                const void *salt = 0,
                std::size_t saltLength = 0,
                std::size_t count = 1,
                const ID &keyId = ID (),
                const std::string &keyName = std::string (),
                const std::string &keyDescription = std::string ()) const;
            /// \brief
            /// Return an instance of the \see{RSAKeyExchange} represented by keyExchange (client side RSA).
            /// \param[in] keyExchangeId \see{KeyExchange::keyExchangeId}.
            /// \param[in] key Public RSA \see{AsymmetricKey} to use for key exchange.
            /// \param[in] secretLength Length of random data to use for \see{SymmetricKey} derivation.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] count A security counter. Increment the count to slow down
            /// \see{SymmetricKey} derivation.
            /// \param[in] keyId Optional \see{SymmetricKey} id.
            /// \param[in] keyName Optional \see{SymmetricKey} name.
            /// \param[in] keyDescription Optional \see{SymmetricKey} description.
            /// \return \see{RSAKeyExchange} instance represented by keyExchange.
            KeyExchange::Ptr GetRSAKeyExchange (
                const ID &keyExchangeId,
                AsymmetricKey::Ptr key,
                std::size_t secretLength = RSAKeyExchange::DEFAULT_SECRET_LENGTH,
                const void *salt = 0,
                std::size_t saltLength = 0,
                std::size_t count = 1,
                const ID &keyId = ID (),
                const std::string &keyName = std::string (),
                const std::string &keyDescription = std::string ()) const;
            /// \brief
            /// Return the \see{Authenticator} instance represented by authenticator.
            /// \param[in] key Private (Sign)/Public (Verify) key.
            /// \return \see{Authenticator} instance represented by authenticator.
            Authenticator::Ptr GetAuthenticator (AsymmetricKey::Ptr key) const;
            /// \brief
            /// Return the \see{Cipher} instance represented by cipher.
            /// \param[in] key \see{SymmetricKey} used to encrypt/decrypt.
            /// \return \see{Cipher} instance represented by cipher.
            Cipher::Ptr GetCipher (SymmetricKey::Ptr key) const;
            /// \brief
            /// Return the \see{HMAC} instance represented by messageDigest.
            /// \param[in] key \see{SymmetricKey} used to mac/verify.
            /// \return \see{HMAC} instance represented by messageDigest.
            MAC::Ptr GetHMAC (SymmetricKey::Ptr key) const;
            /// \brief
            /// Return the \see{CMAC} instance represented by cipher.
            /// \param[in] key \see{SymmetricKey} used to mac/verify.
            /// \return \see{CMAC} instance represented by cipher.
            MAC::Ptr GetCMAC (SymmetricKey::Ptr key) const;
            /// \brief
            /// Return the message digest instance represented by messageDigest.
            /// \return Message digest instance represented by messageDigest.
            MessageDigest::Ptr GetMessageDigest () const;

            /// \brief
            /// Return true if key exchange is ECDHE.
            /// \return true == key exchange is ECDHE.
            inline bool IsKeyExchangeEC () const {
                return authenticator == KEY_EXCHANGE_ECDHE;
            }

            /// \brief
            /// Return true if authenticator is ECDSA or Ed25519.
            /// \return true == authenticator is ECDSA or Ed25519.
            inline bool IsAuthenticatorEC () const {
                return authenticator == AUTHENTICATOR_ECDSA || authenticator == AUTHENTICATOR_Ed25519;
            }
            /// \brief
            /// Given a key length (in bits), create an DSA or RSA
            /// (based on authenticator) private/public key pair.
            /// \param[in] keyLength Length of key (in bits).
            /// \param[in] RSAPublicExponent RSA key public exponent. Ignored for DSA.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Private/public random key pair.
            AsymmetricKey::Ptr CreateAuthenticatorKey (
                std::size_t keyLength,
                BIGNUMPtr RSAPublicExponent = BIGNUMFromui32 (65537),
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ()) const;
            /// \brief
            /// Given a curve name (See \see{EC}), create an ECDSA or Ed25519
            /// (based on authenticator) private/public key pair.
            /// \param[in] curveName Name one of the many curve names defined in see{EC}.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Private/public random key pair.
            AsymmetricKey::Ptr CreateAuthenticatorKey (
                const std::string curveName,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ()) const;

            /// \brief
            /// Return the OpenSSL EVP_CIPHER represented by cipher.
            /// \return OpenSSL EVP_CIPHER represented by cipher.
            inline const EVP_CIPHER *GetOpenSSLCipher () const {
                return GetOpenSSLCipherByName (cipher);
            }
            /// \brief
            /// Return the OpenSSL EVP_MD represented by messageDigest.
            /// \return OpenSSL EVP_MD represented by messageDigest.
            inline const EVP_MD *GetOpenSSLMessageDigest () const {
                return GetOpenSSLMessageDigestByName (messageDigest);
            }

            /// \brief
            /// Return the canonical (Kx_Auth_Enc_MD) representation of a cipher suite.
            /// \return The canonical (Kx_Auth_Enc_MD) representation of a cipher suite.
            inline std::string ToString () const {
                return keyExchange + "_" + authenticator + "_" + cipher + "_" + messageDigest;
            }

        private:
            /// \brief
            /// Parse a properly formated cipher suite string.
            /// \param[in] cipherSuite String encoded cipher suite: Kx_Auth_Enc_MD.
            void Parse (const std::string &cipherSuite);
        };

        /// \brief
        /// Compare two cipher suites for equality.
        /// \param[in] cipherSuite1 First cipher suite to compare.
        /// \param[in] cipherSuite2 Second cipher suite to compare.
        /// \return true = identical, false = different.
        inline bool operator == (
                const CipherSuite &cipherSuite1,
                const CipherSuite &cipherSuite2) {
            return
                cipherSuite1.keyExchange == cipherSuite2.keyExchange &&
                cipherSuite1.authenticator == cipherSuite2.authenticator &&
                cipherSuite1.cipher == cipherSuite2.cipher &&
                cipherSuite1.messageDigest == cipherSuite2.messageDigest;
        }

        /// \brief
        /// Compare two cipher suites for inequality.
        /// \param[in] cipherSuite1 First cipher suite to compare.
        /// \param[in] cipherSuite2 Second cipher suite to compare.
        /// \return true = different, false = identical.
        inline bool operator != (
                const CipherSuite &cipherSuite1,
                const CipherSuite &cipherSuite2) {
            return
                cipherSuite1.keyExchange != cipherSuite2.keyExchange ||
                cipherSuite1.authenticator != cipherSuite2.authenticator ||
                cipherSuite1.cipher != cipherSuite2.cipher ||
                cipherSuite1.messageDigest != cipherSuite2.messageDigest;
        }

        /// \brief
        /// CipherSuite serializer.
        /// \param[in] serializer Where to serialize the cipher suite.
        /// \param[in] cipherSuite CipherSuite to serialize.
        /// \return serializer.
        inline util::Serializer &operator << (
                util::Serializer &serializer,
                const CipherSuite &cipherSuite) {
            serializer <<
                cipherSuite.keyExchange <<
                cipherSuite.authenticator <<
                cipherSuite.cipher <<
                cipherSuite.messageDigest;
            return serializer;
        }

        /// \brief
        /// CipherSuite deserializer.
        /// \param[in] serializer From where to deserialize the cipher suite.
        /// \param[out] cipherSuite CipherSuite to deserialize.
        /// \return serializer.
        inline util::Serializer &operator >> (
                util::Serializer &serializer,
                CipherSuite &cipherSuite) {
            serializer >>
                cipherSuite.keyExchange >>
                cipherSuite.authenticator >>
                cipherSuite.cipher >>
                cipherSuite.messageDigest;
            return serializer;
        }

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_CipherSuite_h)
