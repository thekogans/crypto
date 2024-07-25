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

#if !defined (__thekogans_crypto_OpenSSLParams_h)
#define __thekogans_crypto_OpenSSLParams_h

#include <cstddef>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Params.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/AsymmetricKey.h"

namespace thekogans {
    namespace crypto {

        /// \struct OpenSSLParams OpenSSLParams.h thekogans/crypto/OpenSSLParams.h
        ///
        /// \brief
        /// OpenSSLParams wraps a EVP_PKEY containing parameters of type EVP_PKEY_DH,
        /// EVP_PKEY_DSA or EVP_PKEY_EC, and provides the functionality exposed by
        /// \see{Serializable}. OpenSSLParams makes it very convenient to serialize
        /// asymmetric key parameters for saving to files or transferring across the
        /// network.

        struct _LIB_THEKOGANS_CRYPTO_DECL OpenSSLParams : public Params {
            /// \brief
            /// OpenSSLParams is a \see{Serializable}.
            THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (OpenSSLParams)

        private:
            /// \brief
            /// OpenSSL EVP_PKEY pointer.
            EVP_PKEYPtr params;

        public:
            /// \brief
            /// ctor.
            /// \param[in] params_ OpenSSL EVP_PKEY pointer.
            /// NOTE: OpenSSLParams takes ownership of the params and will delete
            /// it in it's dtor. If that's not what you need, make sure to call
            /// CRYPTO_add (&key_->references, 1, CRYPTO_LOCK_EVP_PKEY); before
            /// passing the EVP_PKEYPtr in to the ctor.
            /// \param[in] id Optional parameters id.
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            OpenSSLParams (
                EVP_PKEYPtr params_ = EVP_PKEYPtr (),
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// Return the EVP_PKEY *.
            /// \return EVP_PKEY *.
            inline EVP_PKEY *Get () const {
                return params.get ();
            }

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
            static SharedPtr LoadFromFile (
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
            /// Return the key type.
            /// \return Key type.
            virtual const char *GetKeyType () const override {
                return EVP_PKEYtypeTostring (EVP_PKEY_base_id (Get ()));
            }

            /// \brief
            /// Create an \see{AsymmetricKey} based on parameters.
            /// \param[in] id Optional key id.
            /// \param[in] name Optional key name.
            /// \param[in] description Optional key description.
            /// \return \see{AsymmetricKey} based on parameters.
            virtual AsymmetricKey::SharedPtr CreateKey (
                const ID &id = ID (),
                const std::string &name = std::string (),
                const std::string &description = std::string ()) const override;

            // Serializable
            /// \brief
            /// Return the serialized params size.
            /// \return Serialized params size.
            virtual std::size_t Size () const override;

            /// \brief
            /// Read the parameters from the given serializer.
            /// \param[in] header \see{util::Serializable::BinHeader}.
            /// \param[in] serializer \see{util::Serializer} to read the parameters from.
            virtual void Read (
                const BinHeader &header,
                util::Serializer &serializer) override;
            /// \brief
            /// Write the parameters to the given serializer.
            /// \param[out] serializer \see{util::Serializer} to write the parameters to.
            virtual void Write (util::Serializer &serializer) const override;

            /// \brief
            /// "ParamsType"
            static const char * const ATTR_PARAMS_TYPE;
            /// \brief
            /// "Params"
            static const char * const ATTR_PARAMS;

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

            /// \brief
            /// OpenSSLParams is neither copy constructable, nor assignable.
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (OpenSSLParams)
        };

        /// \brief
        /// Implement OpenSSLParams extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (OpenSSLParams)

    } // namespace crypto

    namespace util {

        /// \brief
        /// Implement OpenSSLParams value parser.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_VALUE_PARSER (crypto::OpenSSLParams)

    } // namespace util
} // namespace thekogans

#endif // !defined (__thekogans_crypto_OpenSSLParams_h)
