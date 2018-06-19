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
        /// VERY IMPORTANT: The initiator (client) used the public RSA key to encrypt a
        /// random \see{SymmetricKey}. The size of the \see{SymmetricKey} + RSA padding
        /// used to encrypt it puts a lower bound on the size of RSA keys that can be used
        /// for key exchange (1536 bits).

        struct _LIB_THEKOGANS_CRYPTO_DECL RSAKeyExchange : public KeyExchange {
        private:
            /// \struct RSAKeyExchange::RSAParams RSAKeyExchange.h thekogans/crypto/RSAKeyExchange.h
            ///
            /// \brief
            /// RSA key exchange parameters.
            struct _LIB_THEKOGANS_CRYPTO_DECL RSAParams : public KeyExchange::Params {
                /// \brief
                /// RSAParams is a \see{util::Serializable}.
                THEKOGANS_UTIL_DECLARE_SERIALIZABLE (RSAParams, util::SpinLock)

                /// \brief
                /// Private/Public RSA \see{AsymmetricKey} id.
                ID keyId;
                /// \brief
                /// Encrypted \see{SymmetricKey} (client). \see{SymmetricKey} signature (server).
                util::Buffer::UniquePtr buffer;

                /// \brief
                /// ctor.
                /// \param[in] id KeyExchange id (see \see{KeyRing::AddKeyExchange}).
                /// \param[in] keyId_ Private/Public RSA \see{AsymmetricKey} id.
                /// \param[in] buffer_ Encrypted \see{SymmetricKey} (client).
                /// \see{SymmetricKey} signature (server).
                RSAParams (
                    const ID &id,
                    const ID &keyId_,
                    util::Buffer::UniquePtr buffer_) :
                    Params (id),
                    keyId (keyId_),
                    buffer (std::move (buffer_)) {}

            protected:
                // util::Serializable
                /// \brief
                /// Return the serializable size.
                /// \return Serializable size.
                virtual std::size_t Size () const;

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
            /// \see{KeyRing} needs access to RSAParams.
            friend struct KeyRing;

            /// \brief
            /// Private/public \see{AsymmetricKey} used for RSA \see{SymmetricKey} derivation.
            AsymmetricKey::Ptr key;
            /// \brief
            /// Shared \see{SymmetricKey} created by the client and signed by the server.
            SymmetricKey::Ptr symmetricKey;

        public:
            /// \enum
            /// Default secret length.
            enum {
                DEFAULT_SECRET_LENGTH = 1024
            };
            /// \brief
            /// ctor. Used by the initiator (client).
            /// \param[in] id \see{KeyExchange} id (see \see{KeyRing::AddKeyExchange}).
            /// \param[in] key_ Public \see{AsymmetricKey used for
            /// RSA \see{SymmetricKey} derivation.
            /// \param[in] secretLength Length of random data to use for
            /// \see{SymmetricKey} derivation.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] md OpenSSL message digest to use for the signing operation.
            /// \param[in] count A security counter. Increment the count to slow down
            /// key derivation.
            /// \param[in] keyId Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            RSAKeyExchange (
                const ID &id,
                AsymmetricKey::Ptr key_,
                std::size_t secretLength = DEFAULT_SECRET_LENGTH,
                const void *salt = 0,
                std::size_t saltLength = 0,
                std::size_t keyLength = GetCipherKeyLength (),
                const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD,
                std::size_t count = 1,
                const ID &keyId = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());
            /// \brief
            /// ctor. Used by receiver (server).
            /// \param[in] id \see{KeyExchange} id (see \see{KeyRing::AddKeyExchange}).
            /// \param[in] key_ Private \see{AsymmetricKey} used for RSA \see{SymmetricKey} derivation.
            /// \param[in] params \see{RSAParams} containing the encrypted \see{SymmetricKey}.
            RSAKeyExchange (
                const ID &id,
                AsymmetricKey::Ptr key_,
                Params::Ptr params);

            /// \brief
            /// Get the parameters to send to the key exchange peer.
            /// \return \see{RSAParams} to send to the key exchange peer.
            virtual Params::Ptr GetParams () const;

            /// \brief
            /// Given the peer's \see{RSAParams}, derive the shared \see{SymmetricKey}.
            /// \param[in] params Peer's \see{RSAParams} parameters.
            /// \return Shared \see{SymmetricKey}.
            virtual SymmetricKey::Ptr DeriveSharedSymmetricKey (Params::Ptr params) const;

            /// \brief
            /// RSAKeyExchange is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (RSAKeyExchange)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_RSAKeyExchange_h)
