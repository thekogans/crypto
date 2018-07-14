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

        /// \struct KeyExchange KeyExchange.h thekogans/crypto/KeyExchange.h
        ///
        /// \brief
        /// A class for computing and exchanging shared \see{SymmetricKey}s using DHE.
        /// NOTE: To promote best practice, only ephemeral Diffie-Hellman (DHE) key
        /// exchange is supported. This is why the ctor only takes \see{Params}. It
        /// will use them to create an ephemeral private key to be used in the exchange.
        /// If you need to do key exchange using a precomputed private key, use
        /// \see{RSAKeyExchange}.
        /// WARNING: Unlike \see{RSAKeyExchange}, DHEKeyExchange cannot be used to
        /// exchange \see{SymmetricKey} keys in the clear securely. An authenticetion
        /// mechanism is needed to make sure you're exchanging keys with the intended
        /// peer and not a man-in-the-middle (MITM).

        struct _LIB_THEKOGANS_CRYPTO_DECL DHEKeyExchange : public KeyExchange {
        private:
            /// \struct DHEKeyExchange::DHParams DHEKeyExchange.h thekogans/crypto/DHEKeyExchange.h
            ///
            /// \brief
            /// DHE key exchange parameters.
            struct _LIB_THEKOGANS_CRYPTO_DECL DHParams : public KeyExchange::Params {
                /// \brief
                /// DHParams is a \see{util::Serializable}.
                THEKOGANS_UTIL_DECLARE_SERIALIZABLE (DHParams, util::SpinLock)

                /// \brief
                /// \see{EC} or \see{DH} key exchange params.
                crypto::Params::Ptr params;
                /// \brief
                /// Salt for \see{SymmetricKey} derivation.
                std::vector<util::ui8> salt;
                /// \brief
                /// Length of the resulting \see{SymmetricKey} (in bytes).
                util::SizeT keyLength;
                /// \brief
                /// OpenSSL message digest to use for hashing.
                std::string messageDigest;
                /// \brief
                /// A security counter. Increment the count to slow down
                /// \see{SymmetricKey} derivation.
                util::SizeT count;
                /// \brief
                /// \see{SymmetricKey} id.
                ID keyId;
                /// \brief
                /// \see{SymmetricKey} name.
                std::string name;
                /// \brief
                /// \see{SymmetricKey} description.
                std::string description;
                /// \brief
                /// Public \see{AsymmetricKey} used for key exchange.
                AsymmetricKey::Ptr publicKey;

                /// \brief
                /// ctor.
                /// \param[in] id KeyExchange id (see \see{KeyRing::AddKeyExchange}).
                /// \param[in] params_ \see{EC} or \see{DH} key exchange params.
                /// \param[in] salt_ Salt for \see{SymmetricKey} derivation.
                /// \param[in] keyLength_ Length of the resulting \see{SymmetricKey} (in bytes).
                /// \param[in] messageDigest_ OpenSSL message digest to use for hashing.
                /// \param[in] count_ A security counter. Increment the count to slow down
                /// \see{SymmetricKey} derivation.
                /// \param[in] keyId_ \see{SymmetricKey} id.
                /// \param[in] name_ \see{SymmetricKey} name.
                /// \param[in] description_ \see{SymmetricKey} description.
                /// \param[in] publicKey_ Public \see{DH} \see{AsymmetricKey} used for key exchange.
                DHParams (
                    const ID &id,
                    crypto::Params::Ptr params_,
                    const std::vector<util::ui8> &salt_,
                    std::size_t keyLength_,
                    const std::string &messageDigest_,
                    std::size_t count_,
                    const ID &keyId_,
                    const std::string &name_,
                    const std::string &description_,
                    AsymmetricKey::Ptr publicKey_) :
                    Params (id),
                    params (params_),
                    salt (salt_),
                    keyLength (keyLength_),
                    messageDigest (messageDigest_),
                    count (count_),
                    keyId (keyId_),
                    name (name_),
                    description (description_),
                    publicKey (publicKey_) {}

            protected:
                // util::Serializable
                /// \brief
                /// Return the serializable size.
                /// \return Serializable size.
                virtual std::size_t Size () const;

                /// \brief
                /// Read the serializable from the given serializer.
                /// \param[in] header \see{util::Serializable::Header}.
                /// \param[in] serializer \see{util::Serializer} to read the serializable from.
                virtual void Read (
                    const Header &header,
                    util::Serializer &serializer);
                /// \brief
                /// Write the serializable to the given serializer.
                /// \param[out] serializer \see{util::Serializer} to write the serializable to.
                virtual void Write (util::Serializer &serializer) const;
            };

            /// \brief
            /// \see{Serializable} needs access to DHParams.
            friend struct Serializable;
            /// \brief
            /// \see{KeyRing} needs access to DHParams.
            friend struct KeyRing;

            /// \brief
            /// true == Initiator of key exchange, false == Receiver of key exchange.
            const bool initiator;
            /// \brief
            /// \see{DH}/\see{EC} \see{Params} used for DHE \see{SymmetricKey} derivation.
            crypto::Params::Ptr params;
            /// \brief
            /// Salt for \see{SymmetricKey} derivation.
            std::vector<util::ui8> salt;
            /// \brief
            /// Length of the resulting \see{SymmetricKey} (in bytes).
            std::size_t keyLength;
            /// \brief
            /// OpenSSL message digest to use for hashing.
            std::string messageDigest;
            /// \brief
            /// A security counter. Increment the count to slow down
            /// \see{SymmetricKey} derivation.
            std::size_t count;
            /// \brief
            /// \see{SymmetricKey} id.
            ID keyId;
            /// \brief
            /// \see{SymmetricKey} name.
            std::string name;
            /// \brief
            /// \see{SymmetricKey} description.
            std::string description;
            /// \brief
            /// Private \see{DH}/\see{EC} \see{AsymmetricKey} used for key exchange.
            AsymmetricKey::Ptr privateKey;
            /// \brief
            /// Public \see{DH}/\see{EC} \see{AsymmetricKey} used for key exchange.
            AsymmetricKey::Ptr publicKey;

        public:
            /// \brief
            /// ctor. Used by the initiator of the key exchange request (client).
            /// \param[in] id \see{KeyExchange} id (see \see{KeyRing::AddKeyExchange}).
            /// \param[in] params_ \see{DH}/\see{EC} \see{Params} used for DHE \see{SymmetricKey} derivation.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] keyLength Length of the resulting \see{SymmetricKey} (in bytes).
            /// \param[in] md OpenSSL message digest to use for hashing.
            /// \param[in] count A security counter. Increment the count to slow down
            /// \see{SymmetricKey} derivation.
            /// \param[in] keyId Optional \see{SymmetricKey} id.
            /// \param[in] name Optional \see{SymmetricKey} name.
            /// \param[in] description Optional \see{SymmetricKey} description.
            DHEKeyExchange (
                const ID &id,
                crypto::Params::Ptr params_,
                const void *salt_ = 0,
                std::size_t saltLength_ = 0,
                std::size_t keyLength_ = GetCipherKeyLength (),
                const EVP_MD *md_ = THEKOGANS_CRYPTO_DEFAULT_MD,
                std::size_t count_ = 1,
                const ID &keyId_ = ID (),
                const std::string &name_ = std::string (),
                const std::string &description_ = std::string ());
            /// \brief
            /// ctor. Used by the receiver of the key exchange request (server).
            /// \param[in] params \see{DHParams} containing info to create a shared \see{SymmetricKey}.
            explicit DHEKeyExchange (Params::Ptr params);

            /// \brief
            /// Get the parameters to send to the key exchange peer.
            /// \return \see{DHParams} to send to the key exchange peer.
            virtual Params::Ptr GetParams () const;

            /// \brief
            /// Given the peer's \see{DHParams}, use my private key
            /// to derive the shared \see{SymmetricKey}.
            /// \param[in] params Peer's \see{DHParams} parameters.
            /// \return Shared \see{SymmetricKey}.
            virtual SymmetricKey::Ptr DeriveSharedSymmetricKey (Params::Ptr params) const;

            /// \brief
            /// DHEKeyExchange is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (DHEKeyExchange)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_DHEKeyExchange_h)
