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

#if !defined (__thekogans_crypto_OpenSSLAsymmetricKey_h)
#define __thekogans_crypto_OpenSSLAsymmetricKey_h

#include <cstddef>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct OpenSSLAsymmetricKey OpenSSLAsymmetricKey.h thekogans/crypto/OpenSSLAsymmetricKey.h
        ///
        /// \brief
        /// OpenSSLAsymmetricKey wraps a EVP_PKEY and provides the functionality exposed by
        /// \see{AsymmetricKey}. OpenSSLAsymmetricKey makes it very convenient to serialize
        /// OpenSSL asymmetric keys for saving to files or transferring across the network.

        struct _LIB_THEKOGANS_CRYPTO_DECL OpenSSLAsymmetricKey : public AsymmetricKey {
            /// \brief
            /// OpenSSLAsymmetricKey is a \see{OpenSSLAsymmetricKey}.
            THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (OpenSSLAsymmetricKey)

        private:
            /// \brief
            /// OpenSSL EVP_PKEY pointer.
            EVP_PKEYPtr key;

        public:
            /// \brief
            /// ctor.
            /// \param[in] key_ OpenSSL EVP_PKEY pointer.
            /// NOTE: OpenSSLAsymmetricKey takes ownership of the key and will delete
            /// it in it's dtor. If that's not what you need, make sure to call
            /// CRYPTO_add (&key_->references, 1, CRYPTO_LOCK_EVP_PKEY); before
            /// passing the EVP_PKEYPtr in to the ctor.
            /// \param[in] isPrivate true = contains both private and public keys.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            OpenSSLAsymmetricKey (
                EVP_PKEYPtr key_,
                bool isPrivate,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// Load a PEM encoded private key from a file.
            /// \param[in] path File containing a private key.
            /// \param[in] passwordCallback Provide a password if file is encrypted.
            /// \param[in] userData User data for passwordCallback.
            /// NOTE: If passwordCallback == 0 and userData != 0, OpenSSL
            /// will interpret the userData as a NULL terminated password.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Private key.
            static AsymmetricKey::Ptr LoadPrivateKeyFromFile (
                const std::string &path,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());
            /// \brief
            /// Load a PEM encoded public key from a file.
            /// \param[in] path File containing a public key.
            /// \param[in] passwordCallback Provide a password if file is encrypted.
            /// \param[in] userData User data for passwordCallback.
            /// NOTE: If passwordCallback == 0 and userData != 0, OpenSSL
            /// will interpret the userData as a NULL terminated password.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Public key.
            static AsymmetricKey::Ptr LoadPublicKeyFromFile (
                const std::string &path,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());
            /// \brief
            /// Load a public key from a certificate file.
            /// \param[in] path File containing a certificate.
            /// \param[in] passwordCallback Provide a password if file is encrypted.
            /// \param[in] userData User data for passwordCallback.
            /// NOTE: If passwordCallback == 0 and userData != 0, OpenSSL
            /// will interpret the userData as a NULL terminated password.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Public key.
            static AsymmetricKey::Ptr LoadPublicKeyFromCertificate (
                const std::string &path,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());
            /// \brief
            /// Save the key to a file.
            /// \param[in] path File name to save the key to.
            /// \param[in] cipher Optional cipher to use to encrypt the private key.
            /// \param[in] symmetricKey Optional symmetric key to use with the cipher.
            /// \param[in] symmetricKeyLength Optional symmetric key length.
            /// \param[in] passwordCallback Provide a password if file is encrypted.
            /// \param[in] userData User data for passwordCallback.
            /// NOTE: If passwordCallback == 0 and userData != 0, OpenSSL
            /// will interpret the userData as a NULL terminated password.
            void Save (
                const std::string &path,
                const EVP_CIPHER *cipher = 0,
                const void *symmetricKey = 0,
                std::size_t symmetricKeyLength = 0,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0);

            /// \brief
            /// Return the const void * representing the key bits.
            /// \return const void * representing the key bits.
            virtual const void *GetKey () const {
                return key.get ();
            }

            /// \brief
            /// Return the key type.
            /// \return Key type.
            virtual const char *GetKeyType () const {
                return EVP_PKEYtypeTostring (EVP_PKEY_base_id (key.get ()));
            }

            /// \brief
            /// Return the key length (in bits).
            /// \return Key length (in bits).
            virtual std::size_t GetKeyLength () const {
                return (std::size_t)EVP_PKEY_bits (key.get ());
            }

            /// \brief
            /// Return the public key associated with this private key.
            /// If this is a public key only, return a duplicate.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Public part of the privateKey (or duplicate of the pubilc key).
            virtual AsymmetricKey::Ptr GetPublicKey (
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ()) const;

        protected:
            // Serializable
            /// \brief
            /// Return the serialized key size.
            /// \return Serialized key size.
            virtual std::size_t Size () const;

            /// \brief
            /// Read the key from the given serializer.
            /// \param[in] header \see{util::Serializable::Header}.
            /// \param[in] serializer \see{util::Serializer} to read the key from.
            virtual void Read (
                const Header &header,
                util::Serializer &serializer);
            /// \brief
            /// Serialize the key to the given serializer.
            /// \param[out] serializer \see{util::Serializer} to serialize the key to.
            virtual void Write (util::Serializer &serializer) const;

        public:
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
                std::size_t indentationLevel = 0,
                const char *tagName = TAG_SERIALIZABLE) const;
        #endif // defined (THEKOGANS_CRYPTO_TESTING)

            /// \brief
            /// OpenSSLAsymmetricKey is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (OpenSSLAsymmetricKey)
        };

        /// \brief
        /// Implement OpenSSLAsymmetricKey extraction operator.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATOR (OpenSSLAsymmetricKey)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_OpenSSLAsymmetricKey_h)
