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

#include <memory>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/KeyExchange.h"
#include "thekogans/crypto/Authenticator.h"
#include "thekogans/crypto/Cipher.h"
#include "thekogans/crypto/MessageDigest.h"

namespace thekogans {
    namespace crypto {

        /// \struct CipherSuite CipherSuite.h thekogans/crypto/CipherSuite.h
        ///
        /// \brief
        /// CipherSuite collects the various algorithms necessary for key exchange, authentication,
        /// symmetric encryption and message digest.
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
                const std::string &messageDigest_) :
                keyExchange (keyExchange_),
                authenticator (authenticator_),
                cipher (cipher_),
                messageDigest (messageDigest_) {}
            /// \brief
            /// ctor.
            /// \param[in] cipherSuite String encoded cipher suite: Kx_Auth_Enc_MD.
            explicit CipherSuite (const std::string &cipherSuite);
            /// \brief
            /// ctor.
            /// \param[in] serializer Serializer containing the cipher suite.
            explicit CipherSuite (util::Serializer &serializer) {
                serializer >> keyExchange >> authenticator >> cipher >> messageDigest;
            }
            /// \brief
            /// copy ctor.
            /// \param[in] cipherSuite Cipher suite to copy.
            CipherSuite (const CipherSuite &cipherSuite) :
                keyExchange (cipherSuite.keyExchange),
                authenticator (cipherSuite.authenticator),
                cipher (cipherSuite.cipher),
                messageDigest (cipherSuite.messageDigest) {}

            /// \brief
            /// Assignment operator.
            /// \param[in] cipherSuite Cipher suite to copy.
            /// \return *this.
            CipherSuite &operator = (const CipherSuite &cipherSuite) {
                if (&cipherSuite != this) {
                    keyExchange = cipherSuite.keyExchange;
                    authenticator = cipherSuite.authenticator;
                    cipher = cipherSuite.cipher;
                    messageDigest = cipherSuite.messageDigest;
                }
                return *this;
            }

            /// \brief
            /// Return the list of all available cipher suites.
            /// \return The list of all available cipher suites.
            static const std::vector<CipherSuite> &GetCipherSuites ();

            /// \brief
            /// Return the list of all available ciphers.
            /// \return The list of all available ciphers.
            static const std::vector<std::string> &GetCiphers ();
            /// \brief
            /// Return the list of all available message digests.
            /// \return The list of all available message digests.
            static const std::vector<std::string> &GetMessageDigests ();

            /// \brief
            /// Return the OpenSSL EVP_CIPHER represented by the given cipher.
            /// \return OpenSSL EVP_CIPHER represented by the given cipher.
            static const EVP_CIPHER *GetOpenSSLCipher (const std::string &cipher);
            /// \brief
            /// Return the OpenSSL EVP_MD represented by the given messageDigest.
            /// \return OpenSSL EVP_MD represented by the given messageDigest.
            static const EVP_MD *GetOpenSSLMessageDigest (const std::string &messageDigest);

            /// \brief
            /// Return serialized cipher suite size.
            /// \return Serialized cipher suite size.
            inline util::ui32 Size () const {
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
            /// Return the \see{KeyExchange} instance represented by keyExchange.
            /// \param[in] privateKey \see{AsymmetricKey} private key to use for key exchange.
            /// \return \see{KeyExchange} instance represented by keyExchange.
            KeyExchange::Ptr GetKeyExchange (AsymmetricKey::Ptr privateKey) const;
            /// \brief
            /// Return the \see{Authenticator} instance represented by authenticator.
            /// \param[in] op Operation (Sign/Verify) to perform.
            /// \param[in] key Private (Sign)/Public (Verify) key.
            /// \return \see{Authenticator} instance represented by authenticator.
            Authenticator::Ptr GetAuthenticator (
                Authenticator::Op op,
                AsymmetricKey::Ptr key) const;
            /// \brief
            /// Return the cipher instance represented by cipher.
            /// \param[in] key \see{SymmetricKey} used to encrypt/decrypt.
            /// \return Cipher instance represented by cipher.
            Cipher::Ptr GetCipher (SymmetricKey::Ptr key) const;
            /// \brief
            /// Return the message digest instance represented by messageDigest.
            /// \return Message digest instance represented by messageDigest.
            MessageDigest::Ptr GetMessageDigest () const;

            /// \brief
            /// Return the canonical (Kx_Auth_Enc_MD) representation of a cipher suite.
            /// \return The canonical (Kx_Auth_Enc_MD) representation of a cipher suite.
            inline std::string ToString () const {
                return keyExchange + "_" + authenticator + "_" + cipher + "_" + messageDigest;
            }
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
