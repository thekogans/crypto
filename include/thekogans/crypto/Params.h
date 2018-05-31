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

#if !defined (__thekogans_crypto_Params_h)
#define __thekogans_crypto_Params_h

#include <cstddef>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Serializable.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/AsymmetricKey.h"

namespace thekogans {
    namespace crypto {

        /// \struct Params Params.h thekogans/crypto/Params.h
        ///
        /// \brief
        /// Params wraps a EVP_PKEY containing parameters of type EVP_PKEY_DH, EVP_PKEY_DSA
        /// and EVP_PKEY_EC, and provides the functionality exposed by \see{Serializable}.
        /// Params makes it very convenient to serialize asymmetric key parameters for saving
        /// to files or transferring across the network.

        struct _LIB_THEKOGANS_CRYPTO_DECL Params : public Serializable {
            /// \brief
            /// Params is a \see{Serializable}.
            THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (Params)

        private:
            /// \brief
            /// OpenSSL EVP_PKEY pointer.
            EVP_PKEYPtr params;

        public:
            /// \brief
            /// ctor.
            /// \param[in] params_ OpenSSL EVP_PKEY pointer.
            /// NOTE: Params takes ownership of the params and will delete
            /// it in it's dtor. If that's not what you need, make sure to call
            /// CRYPTO_add (&key_->references, 1, CRYPTO_LOCK_EVP_PKEY); before
            /// passing the EVP_PKEYPtr in to the ctor.
            /// \param[in] id Optional parameters id.
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            Params (
                EVP_PKEYPtr params_,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());
            /// \brief
            /// ctor.
            /// \param[in] serializer Serializer containing the parameters.
            explicit Params (util::Serializer &serializer);

            /// \brief
            /// Load a PEM encoded private key parameters from a file.
            /// \param[in] path File containing the private key parameters.
            /// \param[in] type EVP_PKEY_DH, EVP_PKEY_DSA or EVP_PKEY_EC
            /// \param[in] passwordCallback Provide a password if file is encrypted.
            /// \param[in] userData User data for passwordCallback.
            /// NOTE: If passwordCallback == 0 and userData != 0, OpenSSL
            /// will interpret the userData as a NULL terminated password.
            /// \param[in] id Optional parameters id.
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            /// \return Private key parameters.
            static Ptr LoadFromFile (
                const std::string &path,
                util::i32 type,
                pem_password_cb *passwordCallback = 0,
                void *userData = 0,
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());
            /// \brief
            /// Save the PEM encoded key parameters.
            /// \param[in] path File path to save to.
            void Save (const std::string &path) const;

            /// \brief
            /// Return the EVP_PKEY *.
            /// \return EVP_PKEY *.
            inline EVP_PKEY *Get () const {
                return params.get ();
            }

            /// \brief
            /// Return the EVP_PKEY type.
            /// NOTE: While type can be any of the OpenSSL supported EVP_PKEY types,
            /// thekogans_crypto only supports (EVP_PKEY_DH, EVP_PKEY_DSA, EVP_PKEY_EC).
            /// \return EVP_PKEY type.
            inline util::i32 GetType () const {
                return EVP_PKEY_base_id (params.get ());
            }

            /// \brief
            /// Create an \see{AsymmetricKey} based on parameters.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return \see{AsymmetricKey} based on parameters.
            AsymmetricKey::Ptr CreateKey (
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ()) const;

        protected:
            // Serializable
            /// \brief
            /// Return the serialized params size.
            /// \return Serialized params size.
            virtual std::size_t Size () const;

            /// \brief
            /// Read the parameters from the given serializer.
            /// \param[in] header \see{util::Serializable::Header}.
            /// \param[in] serializer \see{util::Serializer} to read the parameters from.
            virtual void Read (
                const Header &header,
                util::Serializer &serializer);
            /// \brief
            /// Write the parameters to the given serializer.
            /// \param[out] serializer \see{util::Serializer} to write the parameters to.
            virtual void Write (util::Serializer &serializer) const;

        public:
        #if defined (THEKOGANS_CRYPTO_TESTING)
            /// \brief
            /// "ParamsType"
            static const char * const ATTR_PARAMS_TYPE;

            /// \brief
            /// Return the XML representation of parameters.
            /// \param[in] indentationLevel How far to indent the leading tag.
            /// \param[in] tagName The name of the leading tag.
            /// \return XML representation of parameters.
            virtual std::string ToString (
                util::ui32 indentationLevel = 0,
                const char *tagName = TAG_SERIALIZABLE) const;
        #endif // defined (THEKOGANS_CRYPTO_TESTING)

            /// \brief
            /// Params is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (Params)
        };

        /// \brief
        /// Implement Params extraction operator.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATOR (Params)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Params_h)
