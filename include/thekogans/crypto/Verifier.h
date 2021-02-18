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

        struct _LIB_THEKOGANS_CRYPTO_DECL Verifier : public virtual util::RefCounted {
            /// \brief
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Verifier)

        protected:
            /// \brief
            /// typedef for the Verifier factory function.
            typedef SharedPtr (*Factory) (
                AsymmetricKey::SharedPtr publicKey,
                MessageDigest::SharedPtr messageDigest);
            /// \brief
            /// typedef for the Verifier map.
            typedef std::map<std::string, Factory> Map;
            /// \brief
            /// Controls Map's lifetime.
            /// \return Verifier map.
            static Map &GetMap ();

        public:
            /// \struct Verifier::MapInitializer Verifier.h thekogans/crypto/Verifier.h
            ///
            /// \brief
            /// MapInitializer is used to initialize the Verifier::map.
            /// It should not be used directly, and instead is included
            /// in THEKOGANS_CRYPTO_DECLARE_VERIFIER/THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER.
            /// If you are deriving a verifierer from Verifier, and you want
            /// it to be dynamically discoverable/creatable, add
            /// THEKOGANS_CRYPTO_DECLARE_VERIFIER to it's declaration,
            /// and one or more THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER to
            /// it's definition.
            struct _LIB_THEKOGANS_CRYPTO_DECL MapInitializer {
                /// \brief
                /// ctor. Add verifier of type, and factory for creating it
                /// to the Verifier::map
                /// \param[in] keyType Verifier key type.
                /// \param[in] factory Verifier creation factory.
                MapInitializer (
                    const std::string &keyType,
                    Factory factory);
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
                AsymmetricKey::SharedPtr publicKey_,
                MessageDigest::SharedPtr messageDigest_);
            /// \brief
            /// dtor.
            virtual ~Verifier () {}

            /// \brief
            /// Used for Verifier dynamic discovery and creation.
            /// \param[in] publicKey Public \see{AsymmetricKey} used for signing.
            /// \param[in] messageDigest Message digest object.
            /// \return A Verifier based on the passed in publicKey type.
            static SharedPtr Get (
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

            /// \brief
            /// Initialize the verifier and get it ready for the next signature verification.
            virtual void Init () = 0;
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

        /// \def THEKOGANS_CRYPTO_DECLARE_VERIFIER_COMMON(type)
        /// Common code used by both Static and Shared builds.
        #define THEKOGANS_CRYPTO_DECLARE_VERIFIER_COMMON(type)\
        public:\
            static thekogans::crypto::Verifier::SharedPtr Create (\
                    thekogans::crypto::AsymmetricKey::SharedPtr publicKey,\
                    thekogans::crypto::MessageDigest::SharedPtr messageDigest) {\
                return thekogans::crypto::Verifier::SharedPtr (new type (publicKey, messageDigest));\
            }

    #if defined (THEKOGANS_CRYPTO_TYPE_Static)
        /// \def THEKOGANS_CRYPTO_DECLARE_VERIFIER(type)
        /// Dynamic discovery macro. Add this to your class declaration.
        /// Example:
        /// \code{.cpp}
        /// struct _LIB_THEKOGANS_CRYPTO_DECL OpenSSLVerifier : public Verifier {
        ///     THEKOGANS_CRYPTO_DECLARE_VERIFIER (OpenSSLVerifier)
        ///     ...
        /// };
        /// \endcode
        #define THEKOGANS_CRYPTO_DECLARE_VERIFIER(type)\
            THEKOGANS_CRYPTO_DECLARE_VERIFIER_COMMON (type)\
            static void StaticInit (const char *keyType) {\
                std::pair<Map::iterator, bool> result =\
                    GetMap ().insert (Map::value_type (keyType, type::Create));\
                if (!result.second) {\
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (\
                        "'%s' is already registered.", keyType);\
                }\
            }

        /// \def THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER(type, keyType)
        /// Dynamic discovery macro. Instantiate one or more of these in the class cpp file.
        /// Example:
        /// \code{.cpp}
        /// THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER (OpenSSLVerifier, OPENSSL_PKEY_RSA)
        /// THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER (OpenSSLVerifier, OPENSSL_PKEY_DSA)
        /// THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER (OpenSSLVerifier, OPENSSL_PKEY_EC)
        /// THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER (Ed25519Verifier, Ed25519AsymmetricKey::KEY_TYPE)
        /// \endcode
        #define THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER(type, keyType)
    #else // defined (THEKOGANS_CRYPTO_TYPE_Static)
        /// \def THEKOGANS_CRYPTO_DECLARE_VERIFIER(type)
        /// Dynamic discovery macro. Add this to your class declaration.
        /// Example:
        /// \code{.cpp}
        /// struct _LIB_THEKOGANS_CRYPTO_DECL OpenSSLVerifier : public Verifier {
        ///     THEKOGANS_CRYPTO_DECLARE_VERIFIER (OpenSSLVerifier)
        ///     ...
        /// };
        /// \endcode
        #define THEKOGANS_CRYPTO_DECLARE_VERIFIER(type)\
            THEKOGANS_CRYPTO_DECLARE_VERIFIER_COMMON (type)

        /// \def THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER(type, keyType)
        /// Dynamic discovery macro. Instantiate one or more of these in the class cpp file.
        /// Example:
        /// \code{.cpp}
        /// THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER (OpenSSLVerifier, OPENSSL_PKEY_RSA)
        /// THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER (OpenSSLVerifier, OPENSSL_PKEY_DSA)
        /// THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER (OpenSSLVerifier, OPENSSL_PKEY_EC)
        /// THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER (Ed25519Verifier, Ed25519AsymmetricKey::KEY_TYPE)
        /// \endcode
        #define THEKOGANS_CRYPTO_IMPLEMENT_VERIFIER(type, keyType)\
        namespace {\
            const thekogans::crypto::Verifier::MapInitializer THEKOGANS_UTIL_UNIQUE_NAME (mapInitializer) (\
                keyType, type::Create);\
        }
    #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Verifier_h)
