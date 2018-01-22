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

#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "thekogans/util/Exception.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Key.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct AsymmetricKey AsymmetricKey.h thekogans/crypto/AsymmetricKey.h
        ///
        /// \brief
        /// AsymmetricKey wraps a EVP_PKEY and provides the functionality exposed by \see{Key}.
        /// AsymmetricKey makes it very convenient to serialize asymmetric keys for saving to
        /// files or transferring across the network.

        struct _LIB_THEKOGANS_CRYPTO_DECL AsymmetricKey : public Key {
            /// \brief
            /// AsymmetricKey is a \see{Key}.
            THEKOGANS_CRYPTO_DECLARE_KEY (AsymmetricKey)

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
            /// passing the EVP_PKEY * in to the ctor.
            /// \param[in] isPrivate_ true = contains both private and public keys.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            AsymmetricKey (
                    EVP_PKEY *key_,
                    bool isPrivate_,
                    const std::string &name = std::string (),
                    const std::string &description = std::string ()) :
                    Key (name, description),
                    key (key_),
                    isPrivate (isPrivate_) {
                if (key_ == 0) {
                    THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                        THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                }
            }
            /// \brief
            /// ctor.
            /// \param[in] serializer Serializer containing the key.
            explicit AsymmetricKey (util::Serializer &serializer);

            /// \brief
            /// Return true if it's a private key.
            /// \return true if it's a private key.
            inline bool IsPrivate () const {
                return isPrivate;
            }

            /// \brief
            /// Create an \see{AsymmetricKey} (private/public) from the given parameters.
            /// \param[in] params EVP_PKEY parameters created by the DH, DSA or EC methods.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return A new AsymmetricKey key.
            static Ptr FromParams (
                EVP_PKEY &params,
                const std::string &name = std::string (),
                const std::string &description = std::string ());
            /// \brief
            /// Load a PEM encoded private key from a file.
            /// \param[in] path File containing a private key.
            /// \param[in] passwordCallback Provide a password if file is encrypted.
            /// \param[in] userData User data for passwordCallback.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Private key.
            static Ptr LoadPrivateKeyFromFile (
                const std::string &path,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0,
                const std::string &name = std::string (),
                const std::string &description = std::string ());
            /// \brief
            /// Load a PEM encoded public key from a file.
            /// \param[in] path File containing a public key.
            /// \param[in] passwordCallback Provide a password if file is encrypted.
            /// \param[in] userData User data for passwordCallback.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Public key.
            static Ptr LoadPublicKeyFromFile (
                const std::string &path,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0,
                const std::string &name = std::string (),
                const std::string &description = std::string ());
            /// \brief
            /// Load a public key from a certificate file.
            /// \param[in] path File containing a certificate.
            /// \param[in] passwordCallback Provide a password if file is encrypted.
            /// \param[in] userData User data for passwordCallback.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Public key.
            static Ptr LoadPublicKeyFromCertificate (
                const std::string &path,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0,
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// Return the EVP_PKEY *.
            /// \return EVP_PKEY *.
            inline EVP_PKEY *Get () const {
                return key.get ();
            }

            /// \brief
            /// Return the public key associated with this private key.
            /// If this is a public key only, return a duplicate.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return Public part of the privateKey (or duplicate of the pubilc key).
            Ptr GetPublicKey (
                const std::string &name = std::string (),
                const std::string &description = std::string ()) const;

            /// \brief
            /// Return the serialized key size.
            /// \param[in] includeType true = include key's type in size calculation.
            /// \return Serialized key size.
            virtual std::size_t Size (bool includeType = true) const;

            /// \brief
            /// Serialize the key to the given serializer.
            /// \param[out] serializer Serializer to serialize the key to.
            /// \param[in] includeType true = Serialize key's type to be used by Get above.
            virtual void Serialize (
                util::Serializer &serializer,
                bool includeType = true) const;

        #if defined (THEKOGANS_CRYPTO_TESTING)
            /// \brief
            /// "KeyType"
            static const char * const ATTR_KEY_TYPE;
            /// \brief
            /// "Private"
            static const char * const ATTR_PRIVATE;

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
                const char *tagName = TAG_KEY) const;
        #endif // defined (THEKOGANS_CRYPTO_TESTING)

            /// \brief
            /// AsymmetricKey is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (AsymmetricKey)
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_AsymmetricKey_h)
