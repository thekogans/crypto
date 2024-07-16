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

#if !defined (__thekogans_crypto_RSAKeyExchange_h)
#define __thekogans_crypto_RSAKeyExchange_h

#include <cstddef>
#include <string>
#include <vector>
#include "thekogans/util/Serializable.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/KeyExchange.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct RSAKeyExchange RSAKeyExchange.h thekogans/crypto/RSAKeyExchange.h
        ///
        /// \brief
        /// A class for computing and exchanging shared \see{SymmetricKey}s using \see{RSA}.
        /// VERY IMPORTANT: The initiator (client) uses the public \see{RSA} key to encrypt
        /// a random \see{SymmetricKey}. The size of the \see{SymmetricKey} + \see{RSA} padding
        /// used to encrypt it puts a lower bound on the size of \see{RSA} keys that can be used
        /// for key exchange (512 bits). Given that today's (2018) best practice is to use
        /// \see{RSA} keys no smaller than 2048 bits, this limitation shouldn't be an issue.

        struct _LIB_THEKOGANS_CRYPTO_DECL RSAKeyExchange : public KeyExchange {
            /// \struct RSAKeyExchange::RSAParams RSAKeyExchange.h thekogans/crypto/RSAKeyExchange.h
            ///
            /// \brief
            /// RSA key exchange parameters.
            struct _LIB_THEKOGANS_CRYPTO_DECL RSAParams : public KeyExchange::Params {
                /// \brief
                /// RSAParams is a \see{util::Serializable}.
                THEKOGANS_UTIL_DECLARE_SERIALIZABLE (RSAParams)

                /// \brief
                /// Private/Public \see{RSA} \see{AsymmetricKey} id.
                ID keyId;
                /// \brief
                /// Encrypted \see{SymmetricKey} (client). \see{SymmetricKey} signature (server).
                std::vector<util::ui8> buffer;

                /// \brief
                /// ctor.
                /// \param[in] id KeyExchange id (see \see{KeyRing::AddKeyExchange}).
                /// \param[in] keyId_ Private/Public RSA \see{AsymmetricKey} id.
                /// \param[in] buffer_ Encrypted \see{SymmetricKey} (client).
                /// \see{SymmetricKey} signature (server).
                RSAParams (
                    const ID &id = ID (),
                    const ID &keyId_ = ID (),
                    const std::vector<util::ui8> &buffer_ = std::vector<util::ui8> ()) :
                    Params (id),
                    keyId (keyId_),
                    buffer (buffer_) {}

                /// \brief
                /// Given my private \see{AsymmetricKey}, create a signature over the parameters.
                /// \param[in] privateKey My private \see{AsymmetricKey} used to create a signature
                /// over the parameters.
                /// \param[in] messageDigest Message digest object.
                virtual void CreateSignature (
                    AsymmetricKey::SharedPtr privateKey,
                    MessageDigest::SharedPtr messageDigest) override;
                /// \brief
                /// Given the peer's public \see{AsymmetricKey}, verify parameters signature.
                /// \param[in] publicKey Peer's public key used to verify parameters signature.
                /// \param[in] messageDigest Message digest object.
                /// \return true == signature is valid, false == signature is invalid.
                virtual bool ValidateSignature (
                    AsymmetricKey::SharedPtr publicKey,
                    MessageDigest::SharedPtr messageDigest) override;

                // util::Serializable
                /// \brief
                /// Return the serializable size.
                /// \return Serializable size.
                virtual std::size_t Size () const override;

                /// Read the serializable from the given serializer.
                /// \param[in] header \see{util::Serializable::BinHeader}.
                /// \param[in] serializer \see{util::Serializer} to read the serializable from.
                virtual void Read (
                    const BinHeader &header,
                    util::Serializer &serializer) override;
                /// \brief
                /// Write the serializable to the given serializer.
                /// \param[out] serializer \see{util::Serializer} to write the serializable to.
                virtual void Write (util::Serializer &serializer) const override;

                /// \brief
                /// "KeyId"
                static const char * const ATTR_KEY_ID;
                /// \brief
                /// "Buffer"
                static const char * const ATTR_BUFFER;

                /// \brief
                /// Read the Serializable from an XML DOM.
                /// \param[in] header \see{util::Serializable::TextHeader}.
                /// \param[in] node XML DOM representation of a Serializable.
                virtual void Read (
                    const TextHeader &header,
                    const pugi::xml_node &node) override;
                /// \brief
                /// Write the Serializable to the XML DOM.
                /// \param[out] node Parent node.
                virtual void Write (pugi::xml_node &node) const override;

                /// \brief
                /// Read a Serializable from an JSON DOM.
                /// \param[in] node JSON DOM representation of a Serializable.
                virtual void Read (
                    const TextHeader &header,
                    const util::JSON::Object &object) override;
                /// \brief
                /// Write a Serializable to the JSON DOM.
                /// \param[out] node Parent node.
                virtual void Write (util::JSON::Object &object) const override;
            };

        private:
            /// \brief
            /// Private/public \see{AsymmetricKey} used for \see{RSA} \see{SymmetricKey} derivation.
            AsymmetricKey::SharedPtr key;
            /// \brief
            /// Shared \see{SymmetricKey} created by the client and signed by the server.
            SymmetricKey::SharedPtr symmetricKey;

        public:
            /// \enum
            /// Default secret length.
            enum {
                DEFAULT_SECRET_LENGTH = 1024
            };
            /// \brief
            /// ctor. Used by the initiator of the key exchange request (client).
            /// \param[in] id \see{KeyExchange} id (see \see{KeyRing::AddKeyExchange}).
            /// \param[in] key_ Public \see{AsymmetricKey used for RSA \see{SymmetricKey} derivation.
            /// \param[in] secretLength Length of random data to use for \see{SymmetricKey} derivation.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] md OpenSSL message digest to use for the signing operation.
            /// \param[in] count A security counter. Increment the count to slow down key derivation.
            /// \param[in] keyId Optional key id.
            /// \param[in] keyName Optional key name.
            /// \param[in] keyDescription Optional key description.
            RSAKeyExchange (
                const ID &id,
                AsymmetricKey::SharedPtr key_,
                std::size_t secretLength = DEFAULT_SECRET_LENGTH,
                const void *salt = 0,
                std::size_t saltLength = 0,
                std::size_t keyLength = GetCipherKeyLength (),
                const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD,
                std::size_t count = 1,
                const ID &keyId = ID (),
                const std::string &keyName = std::string (),
                const std::string &keyDescription = std::string ());
            /// \brief
            /// ctor. Used by the receiver of the key exchange request (server).
            /// \param[in] key_ Private \see{AsymmetricKey} used for \see{RSA} \see{SymmetricKey} derivation.
            /// \param[in] params \see{RSAParams} containing the encrypted \see{SymmetricKey}.
            RSAKeyExchange (
                AsymmetricKey::SharedPtr key_,
                Params::SharedPtr params);

            /// \brief
            /// Get the parameters to send to the key exchange peer.
            /// \param[in] privateKey Optional my private \see{AsymmetricKey} used to create a signature
            /// over the parameters.
            /// \param[in] messageDigest Optional message digest used to hash the parameters.
            /// \return \see{RSAParams} to send to the key exchange peer.
            virtual Params::SharedPtr GetParams (
                AsymmetricKey::SharedPtr privateKey = AsymmetricKey::SharedPtr (),
                MessageDigest::SharedPtr messageDigest = MessageDigest::SharedPtr ()) const override;

            /// \brief
            /// Given the peer's \see{RSAParams}, derive the shared \see{SymmetricKey}.
            /// \param[in] params Peer's \see{RSAParams} parameters.
            /// \return Shared \see{SymmetricKey}.
            virtual SymmetricKey::SharedPtr DeriveSharedSymmetricKey (Params::SharedPtr params) const override;

            /// \brief
            /// RSAKeyExchange is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (RSAKeyExchange)
        };

        /// \brief
        /// Implement RSAKeyExchange::RSAParams extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (RSAKeyExchange::RSAParams)

    } // namespace crypto

    namespace util {

        /// \brief
        /// Implement RSAKeyExchange::RSAParams value parser.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_VALUE_PARSER (crypto::RSAKeyExchange::RSAParams)

    } // namespace util
} // namespace thekogans

#endif // !defined (__thekogans_crypto_RSAKeyExchange_h)
