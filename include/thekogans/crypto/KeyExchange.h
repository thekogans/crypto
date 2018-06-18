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

#if !defined (__thekogans_crypto_KeyExchange_h)
#define __thekogans_crypto_KeyExchange_h

#include <cstddef>
#include <string>
#include "thekogans/util/RefCounted.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Params.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct KeyExchange KeyExchange.h thekogans/crypto/KeyExchange.h
        ///
        /// \brief
        /// A class for computing and exchanging shared \see{SymmetricKey}s.

        struct _LIB_THEKOGANS_CRYPTO_DECL KeyExchange : public util::ThreadSafeRefCounted {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<KeyExchange>.
            typedef util::ThreadSafeRefCounted::Ptr<KeyExchange> Ptr;

            /// \struct KeyExchange::Params KeyExchange.h thekogans/crypto/KeyExchange.h
            ///
            /// \brief
            /// Key exchange parameters base.
            struct _LIB_THEKOGANS_CRYPTO_DECL Params : public util::Serializable {
                /// \brief
                /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<Params>.
                typedef util::ThreadSafeRefCounted::Ptr<Params> Ptr;

                /// \brief
                /// KeyExchange id (see \see{KeyRing::AddKeyExchange}).
                ID keyExchangeId;

                /// \brief
                /// ctor.
                /// \param[in] keyExchangeId_ KeyExchange id (see \see{KeyRing::AddKeyExchange}).
                Params (const ID &keyExchangeId_ = ID ()) :
                    keyExchangeId (keyExchangeId_) {}

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
                    const Header & /*header*/,
                    util::Serializer &serializer);
                /// \brief
                /// Write the serializable to the given serializer.
                /// \param[out] serializer \see{util::Serializer} to write the serializable to.
                virtual void Write (util::Serializer &serializer) const;
            };

            /// \struct KeyExchange::DHParams KeyExchange.h thekogans/crypto/KeyExchange.h
            ///
            /// \brief
            /// DHE key exchange parameters.
            struct _LIB_THEKOGANS_CRYPTO_DECL DHParams : public KeyExchange::Params {
                /// \brief
                /// DHParams is a \see{Serializable}.
                THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (DHParams)

                /// \brief
                /// \see{EC} or \see{DH} key exchange params.
                crypto::Params::Ptr params;
                /// \brief
                /// Public \see{AsymmetricKey} used for key exchange.
                AsymmetricKey::Ptr publicKey;

                /// \brief
                /// ctor.
                /// \param[in] keyExchangeId KeyExchange id (see \see{KeyRing::AddKeyExchange}).
                /// \param[in] params_ \see{EC} or \see{DH} key exchange params.
                /// \param[in] publicKey_ Public \see{AsymmetricKey} used for key exchange.
                DHParams (
                    const ID &keyExchangeId,
                    crypto::Params::Ptr params_,
                    AsymmetricKey::Ptr publicKey_) :
                    Params (keyExchangeId),
                    params (params_),
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

            /// \struct KeyExchange::RSAParams KeyExchange.h thekogans/crypto/KeyExchange.h
            ///
            /// \brief
            /// RSA key exchange parameters.
            struct _LIB_THEKOGANS_CRYPTO_DECL RSAParams : public KeyExchange::Params {
                /// \brief
                /// RSAParams is a \see{Serializable}.
                THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (RSAParams)

                /// \brief
                /// Private/Public RSA \see{AsymmetricKey} id.
                ID keyId;
                /// \brief
                /// Encrypted \see{SymmetricKey} (client). \see{SymmetricKey} signature (server).
                util::Buffer::UniquePtr buffer;

                /// \brief
                /// ctor.
                /// \param[in] keyExchangeId KeyExchange id (see \see{KeyRing::AddKeyExchange}).
                /// \param[in] keyId_ Private/Public RSA \see{AsymmetricKey} id.
                /// \param[in] buffer_ Encrypted \see{SymmetricKey} (client).
                /// \see{SymmetricKey} signature (server).
                RSAParams (
                    const ID &keyExchangeId,
                    const ID &keyId_,
                    util::Buffer::UniquePtr buffer_) :
                    Params (keyExchangeId),
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

        private:
            /// \brief
            /// DH/EC \see{Params} used for DHE \see{SymmetricKey} derivation.
            crypto::Params::Ptr params;
            /// \brief
            /// Private/public \see{AsymmetricKey} used for RSA \see{SymmetricKey} derivation.
            AsymmetricKey::Ptr key;
            /// \brief
            /// Shared \see{SymmetricKey} created by the client and signed by the server.
            SymmetricKey::Ptr symmetricKey;

        public:
            /// \brief
            /// ctor.
            /// \param[in] params_ DH/EC \see{Params} used for
            /// DHE \see{SymmetricKey} derivation.
            explicit KeyExchange (crypto::Params::Ptr params_);
            /// \enum
            /// Default secret length.
            enum {
                DEFAULT_SECRET_LENGTH = 1024
            };
            /// \brief
            /// ctor.
            /// \param[in] key_ Private/Public \see{AsymmetricKey used for
            /// RSA \see{SymmetricKey} derivation.
            /// \param[in] secretLength Length of random data to use for
            /// \see{SymmetricKey} derivation.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] md OpenSSL message digest to use for the signing operation.
            /// \param[in] count A security counter. Increment the count to slow down
            /// key derivation.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            KeyExchange (
                AsymmetricKey::Ptr key_,
                util::ui32 secretLength = DEFAULT_SECRET_LENGTH,
                const void *salt = 0,
                std::size_t saltLength = 0,
                std::size_t keyLength = GetCipherKeyLength (),
                const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD,
                std::size_t count = 1,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());
            /// \brief
            /// ctor.
            /// \param[in] key_ Private/public \see{AsymmetricKey} used for
            /// RSA \see{SymmetricKey} derivation.
            /// \param[in] buffer Encrypted \see{SymmetricKey} (client).
            /// \see{SymmetricKey} signature (server).
            KeyExchange (
                AsymmetricKey::Ptr key_,
                util::Buffer &buffer);

            /// \brief
            /// Get the parameters to send to the key exchange peer.
            /// \param[in] keyExchangeId KeyExchange id (see \see{KeyRing::AddKeyExchange}).
            /// \return Parameters (\see{DHParams} or \see{RSAParams}) to send to the key exchange peer.
            Params::Ptr GetParams (const ID &keyExchangeId) const;

            /// \brief
            /// Given the peer's (see \see{DHParams} and \see{RSAParams}), use my private key
            /// to derive the shared \see{SymmetricKey}.
            /// \param[in] publicKey Peer's public key.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] md OpenSSL message digest to use for the signing operation.
            /// \param[in] count A security counter. Increment the count to slow down
            /// key derivation.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Shared \see{SymmetricKey}.
            SymmetricKey::Ptr DeriveSharedSymmetricKey (
                Params::Ptr params,
                const void *salt = 0,
                std::size_t saltLength = 0,
                std::size_t keyLength = GetCipherKeyLength (),
                const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD,
                std::size_t count = 1,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// KeyExchange is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (KeyExchange)
        };

        /// \brief
        /// Implement KeyExchange::Params extraction operator.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATOR (KeyExchange::Params)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_KeyExchange_h)
