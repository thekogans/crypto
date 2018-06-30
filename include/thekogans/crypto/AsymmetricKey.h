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

#if !defined (__thekogans_crypto_AsymmetricKey_h)
#define __thekogans_crypto_AsymmetricKey_h

#include <cstddef>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Serializable.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct AsymmetricKey AsymmetricKey.h thekogans/crypto/AsymmetricKey.h
        ///
        /// \brief
        /// AsymmetricKey wraps a EVP_PKEY and provides the functionality exposed by
        /// \see{Serializable}. AsymmetricKey makes it very convenient to serialize
        /// asymmetric keys for saving to files or transferring across the network.

        struct _LIB_THEKOGANS_CRYPTO_DECL AsymmetricKey : public Serializable {
            /// \brief
            /// AsymmetricKey is a \see{Serializable}.
            THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (AsymmetricKey)

        private:
            /// \brief
            /// OpenSSL EVP_PKEY pointer.
            EVP_PKEYPtr key;
            /// \brief
            /// true = contains both private and public keys.
            /// false = contains only the public key.
            bool isPrivate;

        public:
            /// \brief
            /// ctor.
            /// \param[in] key_ OpenSSL EVP_PKEY pointer.
            /// NOTE: AsymmetricKey takes ownership of the key and will delete
            /// it in it's dtor. If that's not what you need, make sure to call
            /// CRYPTO_add (&key_->references, 1, CRYPTO_LOCK_EVP_PKEY); before
            /// passing the EVP_PKEYPtr in to the ctor.
            /// \param[in] isPrivate_ true = contains both private and public keys.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            AsymmetricKey (
                EVP_PKEYPtr key_,
                bool isPrivate_,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// Return the EVP_PKEY *.
            /// \return EVP_PKEY *.
            inline EVP_PKEY *Get () const {
                return key.get ();
            }

            /// \brief
            /// Return the EVP_PKEY type.
            /// NOTE: While type can be any of the OpenSSL supported EVP_PKEY types,
            /// thekogans_crypto only supports (EVP_PKEY_DH, EVP_PKEY_DSA, EVP_PKEY_EC,
            /// EVP_PKEY_RSA, EVP_PKEY_HMAC and EVP_PKEY_CMAC).
            /// \return EVP_PKEY type.
            inline util::i32 GetType () const {
                return EVP_PKEY_base_id (Get ());
            }

            /// \brief
            /// Return true if it's a private key.
            /// \return true if it's a private key.
            inline bool IsPrivate () const {
                return isPrivate;
            }

            /// \brief
            /// Return the key length (in bits).
            /// \return Key length (in bits).
            inline std::size_t Length () const {
                return (std::size_t)EVP_PKEY_bits (key.get ());
            }

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
            static Ptr LoadPrivateKeyFromFile (
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
            static Ptr LoadPublicKeyFromFile (
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
            static Ptr LoadPublicKeyFromCertificate (
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
            /// Return the public key associated with this private key.
            /// If this is a public key only, return a duplicate.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Public part of the privateKey (or duplicate of the pubilc key).
            Ptr GetPublicKey (
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
            /// "Private"
            static const char * const ATTR_PRIVATE;
            /// \brief
            /// "KeyType"
            static const char * const ATTR_KEY_TYPE;

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
            /// AsymmetricKey is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (AsymmetricKey)
        };

        /// \brief
        /// Implement AsymmetricKey extraction operator.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATOR (AsymmetricKey)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_AsymmetricKey_h)
