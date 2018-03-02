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

#if !defined (__thekogans_crypto_SymmetricKey_h)
#define __thekogans_crypto_SymmetricKey_h

#include <string>
#include <openssl/evp.h>
#include "thekogans/util/FixedBuffer.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Serializable.h"

namespace thekogans {
    namespace crypto {

        /// \struct SymmetricKey SymmetricKey.h thekogans/crypto/SymmetricKey.h
        ///
        /// \brief
        /// SymmetricKey is used by \see{Cipher} for bulk encryption.

        struct _LIB_THEKOGANS_CRYPTO_DECL SymmetricKey :
                public Serializable,
                public util::FixedBuffer<EVP_MAX_KEY_LENGTH> {
            /// \brief
            /// SymmetricKey is a \see{Serializable}
            THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (SymmetricKey)

            /// \brief
            /// ctor.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            SymmetricKey (
                const std::string &name = std::string (),
                const std::string &description = std::string ()) :
                Serializable (name, description) {}
            /// \brief
            /// ctor.
            /// \param[in] serializer Serializer containing the key.
            explicit SymmetricKey (util::Serializer &serializer);

            /// \brief
            /// Return the key length.
            /// \return Key length.
            inline std::size_t Length () const {
                return GetDataAvailableForReading ();
            }

            /// \brief
            /// Generate a key given secret (password) and length.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] secret Shared secret from which to derive the key.
            /// \param[in] secretLength Shared secret length.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] md OpenSSL message digest to use for hashing.
            /// \param[in] count A security counter. Increment the count to slow down
            /// key derivation.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return A new symmetric key.
            static Ptr FromSecretAndSalt (
                std::size_t keyLength,
                const void *secret,
                std::size_t secretLength,
                const void *salt = 0,
                std::size_t saltLength = 0,
                const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD,
                std::size_t count = 1,
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            enum {
                /// \brief
                /// Minimum length of random buffer to use in FromRandom.
                MIN_RANDOM_LENGTH = 256
            };

            /// \brief
            /// Generate a random key.
            /// \param[in] keyLength Length of the resulting key (in bytes).
            /// \param[in] randomLength Length of random buffer from which
            /// keying material is derived.
            /// \param[in] salt An optional buffer containing salt.
            /// \param[in] saltLength Salt length.
            /// \param[in] md OpenSSL message digest to use for hashing.
            /// \param[in] count A security counter. Increment the count to slow down
            /// key derivation.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return A new symmetric key.
            static Ptr FromRandom (
                std::size_t keyLength,
                std::size_t randomLength = MIN_RANDOM_LENGTH,
                const void *salt = 0,
                std::size_t saltLength = 0,
                const EVP_MD *md = THEKOGANS_CRYPTO_DEFAULT_MD,
                std::size_t count = 1,
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// Return the serialized key size.
            /// \return Serialized key size.
            virtual std::size_t Size () const;

            /// \brief
            /// Serialize the key to the given serializer.
            /// \param[out] serializer Serializer to serialize the key to.
            virtual void Serialize (util::Serializer &serializer) const;

        #if defined (THEKOGANS_CRYPTO_TESTING)
            /// \brief
            /// Return the XML representation of a key.
            /// ********************** WARNING **********************
            /// This is antithetical to security which is precisely
            /// why it should be used only for testing and turned off
            /// when building for production.
            /// *****************************************************
            /// \param[in] indentationLevel How far to indent the leading tag.
            /// \param[in] tagName The name of the leading tag.
            /// \return XML representation of a key.
            virtual std::string ToString (
                util::ui32 indentationLevel = 0,
                const char *tagName = TAG_SERIALIZABLE) const;
        #endif // defined (THEKOGANS_CRYPTO_TESTING)

            /// \brief
            /// SymmetricKey is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (SymmetricKey)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_SymmetricKey_h)
