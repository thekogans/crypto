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

#if !defined (__thekogans_crypto_Verifier_h)
#define __thekogans_crypto_Verifier_h

#include <cstddef>
#include <memory>
#include "thekogans/util/RefCounted.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/MessageDigest.h"

namespace thekogans {
    namespace crypto {

        /// \struct Verifier Verifier.h thekogans/crypto/Verifier.h
        ///
        /// \brief
        /// Verifier is a base for public key signature verification operation. It defines the API
        /// a concrete verifier needs to implement.

        struct _LIB_THEKOGANS_CRYPTO_DECL Verifier : public util::DynamicCreatable {
            /// \brief
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_DYNAMIC_CREATABLE_BASE (Verifier)

            struct Parameters : public util::DynamicCreatable::Parameters {
                /// \brief
                /// Public key.
                AsymmetricKey::SharedPtr publicKey;
                /// \brief
                /// Message digest.
                MessageDigest::SharedPtr messageDigest;

                /// \brief
                /// ctor.
                /// \param[in] publicKey_ Public key.
                /// \param[in] messageDigest_ Message digest.
                Parameters (
                    AsymmetricKey::SharedPtr publicKey_,
                    MessageDigest::SharedPtr messageDigest_) :
                    publicKey (publicKey_),
                    messageDigest (messageDigest_) {}

                virtual void Apply (DynamicCreatable &dynamicCreatable) override {
                    static_cast<Verifier *> (&dynamicCreatable)->Init (publicKey, messageDigest);
                }
            };

        protected:
            /// \brief
            /// Public key.
            AsymmetricKey::SharedPtr publicKey;
            /// \brief
            /// Message digest object.
            MessageDigest::SharedPtr messageDigest;

        public:
            /// \brief
            /// ctor.
            /// \param[in] publicKey_ Public key.
            /// \param[in] messageDigest_ Message digest object.
            Verifier (
                AsymmetricKey::SharedPtr publicKey_ = nullptr,
                MessageDigest::SharedPtr messageDigest_ = nullptr) :
                publicKey (publicKey_),
                messageDigest (messageDigest_) {}
            /// \brief
            /// dtor.
            virtual ~Verifier () {}

            /// \brief
            /// Used for Verifier dynamic discovery and creation.
            /// \param[in] publicKey Public \see{AsymmetricKey} used for signing.
            /// \param[in] messageDigest Message digest object.
            /// \return A Verifier based on the passed in publicKey type.
            static SharedPtr CreateVerifier (
                AsymmetricKey::SharedPtr publicKey,
                MessageDigest::SharedPtr messageDigest);
        #if defined (THEKOGANS_CRYPTO_TYPE_Static)
            /// \brief
            /// Because Verifier uses dynamic initialization, when using
            /// it in static builds call this method to have the Verifier
            /// explicitly include all internal verifier types. Without
            /// calling this api, the only verifiers that will be available
            /// to your application are the ones you explicitly link to.
            static void StaticInit ();
        #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

            /// \brief
            /// Return the verifier public key.
            /// \return \see{AsymmetricKey} public key used for signature verification.
            inline AsymmetricKey::SharedPtr GetPublicKey () const {
                return publicKey;
            }
            /// \brief
            /// Return the verifieer message digest.
            /// \return \see{AsymmetricKey} message digest used for hashing.
            inline MessageDigest::SharedPtr GetMessageDigest () const {
                return messageDigest;
            }

            virtual bool HasKeyType (const std::string &keyType) = 0;

            /// \brief
            /// Initialize the verifier and get it ready for the next signature verification.
            /// \param[in] publicKey_ Public key.
            /// \param[in] messageDigest_ Message digest object.
            virtual void Init (
                AsymmetricKey::SharedPtr publicKey_ = nullptr,
                MessageDigest::SharedPtr messageDigest_ = nullptr) = 0;
            /// \brief
            /// Call this method 1 or more time to verify the buffers.
            /// \param[in] buffer Buffer whose signature to verify.
            /// \param[in] bufferLength Buffer length.
            virtual void Update (
                const void * /*buffer*/,
                std::size_t /*bufferLength*/) = 0;
            /// \brief
            /// Finalize the verification operation.
            /// \param[in] signature Signature to verify.
            /// \param[in] signatureLength Signature length.
            /// \return true == signature matches, false == signature does not match..
            virtual bool Final (
                const void * /*signature*/,
                std::size_t /*signatureLength*/) = 0;
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Verifier_h)
