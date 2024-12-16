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

#if !defined (__thekogans_crypto_DHEKeyExchange_h)
#define __thekogans_crypto_DHEKeyExchange_h

#include <cstddef>
#include <string>
#include "thekogans/util/Serializable.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/KeyExchange.h"
#include "thekogans/crypto/Params.h"
#include "thekogans/crypto/AsymmetricKey.h"

namespace thekogans {
    namespace crypto {

        /// \struct DHEKeyExchange DHEKeyExchange.h thekogans/crypto/DHEKeyExchange.h
        ///
        /// \brief
        /// A class for computing and exchanging shared \see{SymmetricKey}s using DHE.
        /// NOTE: To promote best practice, only ephemeral Diffie-Hellman (DHE) key
        /// exchange is supported. This is why the ctor only takes \see{Params}. It
        /// will use them to create an ephemeral private key to be used in the exchange.
        /// If you need to do key exchange using a precomputed private key, use
        /// \see{RSAKeyExchange}.
        /// WARNING: Unlike \see{RSAKeyExchange}, DHEKeyExchange cannot be used to
        /// exchange \see{SymmetricKey} keys in the clear securely. An authentication
        /// mechanism is needed to make sure you're exchanging keys with the intended
        /// peer and not a man-in-the-middle (MITM). This is why \see{KeyExchange::Params}
        /// exposes CreateSignature and ValidateSignature. Use it to sign and validate
        /// the parameters before exchanging keys with an unknown peer.

        struct _LIB_THEKOGANS_CRYPTO_DECL DHEKeyExchange : public KeyExchange {
            /// \struct DHEKeyExchange::DHEParams DHEKeyExchange.h thekogans/crypto/DHEKeyExchange.h
            ///
            /// \brief
            /// DHE key exchange parameters.
            struct _LIB_THEKOGANS_CRYPTO_DECL DHEParams : public KeyExchange::Params {
                /// \brief
                /// DHEParams is a \see{util::Serializable}.
                THEKOGANS_UTIL_DECLARE_SERIALIZABLE (DHEParams)

                /// \brief
                /// \see{EC} or \see{DH} key exchange params.
                crypto::Params::SharedPtr params;
                /// \brief
                /// Salt for \see{SymmetricKey} derivation.
                std::vector<util::ui8> salt;
                /// \brief
                /// Length of the resulting \see{SymmetricKey} (in bytes).
                util::SizeT keyLength;
                /// \brief
                /// OpenSSL message digest to use for hashing.
                std::string messageDigestName;
                /// \brief
                /// A security counter. Increment the count to slow down
                /// \see{SymmetricKey} derivation.
                util::SizeT count;
                /// \brief
                /// \see{SymmetricKey} id.
                ID keyId;
                /// \brief
                /// \see{SymmetricKey} name.
                std::string keyName;
                /// \brief
                /// \see{SymmetricKey} description.
                std::string keyDescription;
                /// \brief
                /// Public \see{AsymmetricKey} used for key exchange.
                AsymmetricKey::SharedPtr publicKey;

                /// \brief
                /// ctor.
                /// \param[in] id KeyExchange id (see \see{KeyRing::AddKeyExchange}).
                /// \param[in] params_ \see{EC} or \see{DH} key exchange params.
                /// \param[in] salt_ Salt for \see{SymmetricKey} derivation.
                /// \param[in] keyLength_ Length of the resulting \see{SymmetricKey} (in bytes).
                /// \param[in] messageDigestName_ OpenSSL message digest to use for hashing.
                /// \param[in] count_ A security counter. Increment the count to slow
                /// down \see{SymmetricKey} derivation.
                /// \param[in] keyId_ \see{SymmetricKey} id.
                /// \param[in] keyName_ \see{SymmetricKey} name.
                /// \param[in] keyDescription_ \see{SymmetricKey} description.
                /// \param[in] publicKey_ Public \see{DH} \see{AsymmetricKey} used for key exchange.
                DHEParams (
                    const ID &id = ID (),
                    crypto::Params::SharedPtr params_ = nullptr,
                    const std::vector<util::ui8> &salt_ = std::vector<util::ui8> (),
                    std::size_t keyLength_ = 0,
                    const std::string &messageDigestName_ = std::string (),
                    std::size_t count_ = 0,
                    const ID &keyId_ = ID (),
                    const std::string &keyName_ = std::string (),
                    const std::string &keyDescription_ = std::string (),
                    AsymmetricKey::SharedPtr publicKey_ = nullptr) :
                    Params (id),
                    params (params_),
                    salt (salt_),
                    keyLength (keyLength_),
                    messageDigestName (messageDigestName_),
                    count (count_),
                    keyId (keyId_),
                    keyName (keyName_),
                    keyDescription (keyDescription_),
                    publicKey (publicKey_) {}

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

                /// \brief
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
                /// Read a Serializable from an XML DOM.
                /// \param[in] header \see{util::Serializable::TextHeader}.
                /// \param[in] node XML DOM representation of a Serializable.
                virtual void Read (
                    const TextHeader &header,
                    const pugi::xml_node &node) override;
                /// \brief
                /// Write a Serializable to the XML DOM.
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
            /// true == Initiator of key exchange, false == Receiver of key exchange.
            const bool initiator;
            /// \brief
            /// \see{DH}/\see{EC} \see{Params} used for DHE \see{SymmetricKey} derivation.
            crypto::Params::SharedPtr params;
            /// \brief
            /// Salt for \see{SymmetricKey} derivation.
            std::vector<util::ui8> salt;
            /// \brief
            /// Length of the resulting \see{SymmetricKey} (in bytes).
            std::size_t keyLength;
            /// \brief
            /// OpenSSL message digest to use for hashing.
            std::string messageDigestName;
            /// \brief
            /// A security counter. Increment the count to slow down
            /// \see{SymmetricKey} derivation.
            std::size_t count;
            /// \brief
            /// \see{SymmetricKey} id.
            ID keyId;
            /// \brief
            /// \see{SymmetricKey} name.
            std::string keyName;
            /// \brief
            /// \see{SymmetricKey} description.
            std::string keyDescription;
            /// \brief
            /// Private \see{DH}/\see{EC} \see{AsymmetricKey} used for key exchange.
            AsymmetricKey::SharedPtr privateKey;
            /// \brief
            /// Public \see{DH}/\see{EC} \see{AsymmetricKey} used for key exchange.
            AsymmetricKey::SharedPtr publicKey;

        public:
            /// \brief
            /// ctor. Used by the initiator of the key exchange request (client).
            /// \param[in] id \see{KeyExchange} id (see \see{KeyRing::AddKeyExchange}).
            /// \param[in] params_ \see{DH}/\see{EC} \see{Params} used for DHE
            /// \see{SymmetricKey} derivation.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] keyLength Length of the resulting \see{SymmetricKey} (in bytes).
            /// \param[in] md OpenSSL message digest to use for hashing.
            /// \param[in] count A security counter. Increment the count to slow down
            /// \see{SymmetricKey} derivation.
            /// \param[in] keyId Optional \see{SymmetricKey} id.
            /// \param[in] keyName Optional \see{SymmetricKey} name.
            /// \param[in] keyDescription Optional \see{SymmetricKey} description.
            DHEKeyExchange (
                const ID &id,
                crypto::Params::SharedPtr params_,
                const void *salt_ = 0,
                std::size_t saltLength_ = 0,
                std::size_t keyLength_ = GetCipherKeyLength (),
                const EVP_MD *md_ = THEKOGANS_CRYPTO_DEFAULT_MD,
                std::size_t count_ = 1,
                const ID &keyId_ = ID (),
                const std::string &keyName_ = std::string (),
                const std::string &keyDescription_ = std::string ());
            /// \brief
            /// ctor. Used by the receiver of the key exchange request (server).
            /// \param[in] params \see{DHEParams} containing info to create a
            /// shared \see{SymmetricKey}.
            explicit DHEKeyExchange (Params::SharedPtr params);

            /// \brief
            /// Get the parameters to send to the key exchange peer.
            /// \param[in] privateKey Optional my private \see{AsymmetricKey}
            /// used to create a signature over the parameters.
            /// \param[in] messageDigest Optional message digest used to hash
            /// the parameters.
            /// \return \see{DHEParams} to send to the key exchange peer.
            virtual Params::SharedPtr GetParams (
                AsymmetricKey::SharedPtr privateKey = nullptr,
                MessageDigest::SharedPtr messageDigest = nullptr) const override;

            /// \brief
            /// Given the peer's \see{DHEParams}, use my private key
            /// to derive the shared \see{SymmetricKey}.
            /// \param[in] params Peer's \see{DHEParams} parameters.
            /// \return Shared \see{SymmetricKey}.
            virtual SymmetricKey::SharedPtr DeriveSharedSymmetricKey (
                Params::SharedPtr params) const override;

            /// \brief
            /// DHEKeyExchange is neither copy constructable, nor assignable.
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (DHEKeyExchange)
        };

        /// \brief
        /// Implement DHEKeyExchange::DHEParams extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (DHEKeyExchange::DHEParams)

    } // namespace crypto

    namespace util {

        /// \brief
        /// Implement DHEKeyExchange::DHEParams value parser.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_VALUE_PARSER (crypto::DHEKeyExchange::DHEParams)

    } // namespace util
} // namespace thekogans

#endif // !defined (__thekogans_crypto_DHEKeyExchange_h)
