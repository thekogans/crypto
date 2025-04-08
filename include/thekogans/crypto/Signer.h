// Copyright 2011 Boris Kogan (boris@thekogans.net)
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

#if !defined (__thekogans_crypto_Signer_h)
#define __thekogans_crypto_Signer_h

#include <cstddef>
#include <memory>
#include "thekogans/util/Exception.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/DynamicCreatable.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/MessageDigest.h"

namespace thekogans {
    namespace crypto {

        /// \struct Signer Signer.h thekogans/crypto/Signer.h
        ///
        /// \brief
        /// Signer is an abstract base for public key sign operation.
        /// It defines the API a concrete signer needs to implement.

        struct _LIB_THEKOGANS_CRYPTO_DECL Signer : public util::DynamicCreatable {
            /// \brief
            /// Signer is a \see{util::DynamicCreatable} abstract base.
            THEKOGANS_UTIL_DECLARE_DYNAMIC_CREATABLE_ABSTRACT_BASE (Signer)

            /// \struct Signer::Parameters Signer.h thekogans/crypto/Signer.h
            ///
            /// \brief
            /// Pass these parameters to DynamicCreatable::CreateType to
            /// parametarize the new instance.
            struct Parameters : public util::DynamicCreatable::Parameters {
                /// \brief
                /// Private key.
                AsymmetricKey::SharedPtr privateKey;
                /// \brief
                /// Message digest.
                MessageDigest::SharedPtr messageDigest;

                /// \brief
                /// ctor.
                /// \param[in] privateKey_ Private key.
                /// \param[in] messageDigest_ Message digest.
                Parameters (
                        AsymmetricKey::SharedPtr privateKey_,
                        MessageDigest::SharedPtr messageDigest_) :
                        privateKey (privateKey_),
                        messageDigest (messageDigest_) {
                    if (privateKey == nullptr || !privateKey->IsPrivate () ||
                            messageDigest == nullptr) {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                    }
                }

                /// \brief
                /// Apply the encapsulated parameters to the passed in instance.
                /// \param[in] dynamicCreatable Signer instance to apply the
                /// encapsulated parameters to.
                virtual void Apply (DynamicCreatable::SharedPtr dynamicCreatable) override {
                    Signer::SharedPtr signer = dynamicCreatable;
                    if (signer != nullptr) {
                        signer->Init (privateKey, messageDigest);
                    }
                    else {
                        THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                            THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
                    }
                }
            };

        protected:
            /// \brief
            /// Private key.
            AsymmetricKey::SharedPtr privateKey;
            /// \brief
            /// Message digest.
            MessageDigest::SharedPtr messageDigest;

        public:
            /// \brief
            /// ctor.
            /// \param[in] privateKey_ Private key.
            /// \param[in] messageDigest_ Message digest.
            Signer (
                AsymmetricKey::SharedPtr privateKey_ = nullptr,
                MessageDigest::SharedPtr messageDigest_ = nullptr) :
                privateKey (privateKey_),
                messageDigest (messageDigest_) {}

        #if defined (THEKOGANS_CRYPTO_TYPE_Static)
            /// \brief
            /// Because Signer uses dynamic initialization, when using
            /// it in static builds call this method to have the Signer
            /// explicitly include all internal signer types. Without
            /// calling this api, the only signers that will be available
            /// to your application are the ones you explicitly link to.
            static void StaticInit ();
        #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

            /// \brief
            /// Used for Verifier dynamic discovery and creation.
            /// \param[in] publicKey Public \see{AsymmetricKey} used for signing.
            /// \param[in] messageDigest Message digest object.
            /// \return A Verifier based on the passed in publicKey type.
            static SharedPtr CreateSigner (
                AsymmetricKey::SharedPtr privateKey,
                MessageDigest::SharedPtr messageDigest);

            /// \brief
            /// Return the signer private key.
            /// \return \see{AsymmetricKey} private key used for signing.
            inline AsymmetricKey::SharedPtr GetPrivateKey () const {
                return privateKey;
            }
            /// \brief
            /// Return the signer message digest.
            /// \return \see{AsymmetricKey} message digest used for hashing.
            inline MessageDigest::SharedPtr GetMessageDigest () const {
                return messageDigest;
            }

            /// \brief
            /// Return true if the given keyType is supported by the signer.
            /// \param[in] keyType Key type to check for support.
            /// \return true if keyType is supported.
            virtual bool HasKeyType (const std::string &keyType) = 0;

            /// \brief
            /// Initialize the signer and get it ready for the next signature.
            /// \param[in] privateKey_ Private key.
            /// \param[in] messageDigest_ Message digest.
            virtual void Init (
                AsymmetricKey::SharedPtr privateKey_ = nullptr,
                MessageDigest::SharedPtr messageDigest_ = nullptr) = 0;
            /// \brief
            /// Call this method 1 or more time to sign the buffers.
            /// \param[in] buffer Buffer whose signature to create.
            /// \param[in] bufferLength Buffer length.
            virtual void Update (
                const void * /*buffer*/,
                std::size_t /*bufferLength*/) = 0;
            /// \brief
            /// Finalize the signing operation and return the signature.
            /// \param[out] signature Where to write the signature.
            /// \return Number of bytes written to signature.
            virtual std::size_t Final (util::ui8 * /*signature*/) = 0;

            /// \brief
            /// Finalize the signing operation and return the signature.
            /// \return \see{util::Buffer} containing the signature.
            util::Buffer::SharedPtr Final ();
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Signer_h)
