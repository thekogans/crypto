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
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/MessageDigest.h"

namespace thekogans {
    namespace crypto {

        /// \struct Signer Signer.h thekogans/crypto/Signer.h
        ///
        /// \brief
        /// Signer is a base for public key sign operation. It defines the API
        /// a concrete signer needs to implement.

        struct _LIB_THEKOGANS_CRYPTO_DECL Signer {
            /// \brief
            /// Convenient typedef for std::unique_ptr<Signer>.
            typedef std::unique_ptr<Signer> Ptr;

        protected:
            /// \brief
            /// typedef for the Signer factory method.
            typedef Ptr (*Factory) (
                AsymmetricKey::Ptr privateKey,
                MessageDigest::Ptr messageDigest);
            /// \brief
            /// typedef for the Signer map.
            typedef std::map<std::string, Factory> Map;
            /// \brief
            /// Controls Map's lifetime.
            /// \return Signer map.
            static Map &GetMap ();

        public:
            /// \struct Signer::MapInitializer Signer.h thekogans/crypto/Signer.h
            ///
            /// \brief
            /// MapInitializer is used to initialize the Signer::map.
            /// It should not be used directly, and instead is included
            /// in THEKOGANS_CRYPTO_DECLARE_SIGNER/THEKOGANS_CRYPTO_IMPLEMENT_SIGNER.
            /// If you are deriving a signerer from Signer, and you want
            /// it to be dynamically discoverable/creatable, add
            /// THEKOGANS_CRYPTO_DECLARE_SIGNER to it's declaration,
            /// and one or more THEKOGANS_CRYPTO_IMPLEMENT_SIGNER to
            /// it's definition.
            struct _LIB_THEKOGANS_CRYPTO_DECL MapInitializer {
                /// \brief
                /// ctor. Add signer of type, and factory for creating it
                /// to the Signer::map
                /// \param[in] keyType Signer key type.
                /// \param[in] factory Signer creation factory.
                MapInitializer (
                    const std::string &keyType,
                    Factory factory);
            };

        protected:
            /// \brief
            /// Private key.
            AsymmetricKey::Ptr privateKey;
            /// \brief
            /// Message digest.
            MessageDigest::Ptr messageDigest;

        public:
            /// \brief
            /// ctor.
            /// \param[in] privateKey_ Private key.
            /// \param[in] messageDigest_ Message digest.
            Signer (
                AsymmetricKey::Ptr privateKey_,
                MessageDigest::Ptr messageDigest_);
            /// \brief
            /// dtor.
            virtual ~Signer () {}

            /// \brief
            /// Used for Signer dynamic discovery and creation.
            /// \param[in] privateKey Private \see{AsymmetricKey} used for signing.
            /// \param[in] messageDigest Message digest.
            /// \return A Signer based on the passed in privateKey type.
            static Ptr Get (
                AsymmetricKey::Ptr privateKey,
                MessageDigest::Ptr messageDigest);
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
            /// Return the signer private key.
            /// \return \see{AsymmetricKey} private key used for signing.
            inline AsymmetricKey::Ptr GetPrivateKey () const {
                return privateKey;
            }
            /// \brief
            /// Return the signer message digest.
            /// \return \see{AsymmetricKey} message digest used for hashing.
            inline MessageDigest::Ptr GetMessageDigest () const {
                return messageDigest;
            }

            /// \brief
            /// Initialize the signer and get it ready for the next signature.
            virtual void Init () = 0;
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
            /// \return Signature.
            util::Buffer Final ();
        };

        /// \def THEKOGANS_CRYPTO_DECLARE_SIGNER_COMMON(type)
        /// Common code used by both Static and Shared builds.
        #define THEKOGANS_CRYPTO_DECLARE_SIGNER_COMMON(type)\
        public:\
            static thekogans::crypto::Signer::Ptr Create (\
                    thekogans::crypto::AsymmetricKey::Ptr privateKey,\
                    thekogans::crypto::MessageDigest::Ptr messageDigest) {\
                return thekogans::crypto::Signer::Ptr (new type (privateKey, messageDigest));\
            }

    #if defined (THEKOGANS_CRYPTO_TYPE_Static)
        /// \def THEKOGANS_CRYPTO_DECLARE_SIGNER(type)
        /// Dynamic discovery macro. Add this to your class declaration.
        /// Example:
        /// \code{.cpp}
        /// struct _LIB_THEKOGANS_CRYPTO_DECL OpenSSLSigner : public Signer {
        ///     THEKOGANS_CRYPTO_DECLARE_SIGNER (OpenSSLSigner)
        ///     ...
        /// };
        /// \endcode
        #define THEKOGANS_CRYPTO_DECLARE_SIGNER(type)\
            THEKOGANS_CRYPTO_DECLARE_SIGNER_COMMON (type)\
            static void StaticInit (const char *keyType) {\
                std::pair<Map::iterator, bool> result =\
                    GetMap ().insert (Map::value_type (keyType, type::Create));\
                if (!result.second) {\
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (\
                        "'%s' is already registered.", keyType);\
                }\
            }

        /// \def THEKOGANS_CRYPTO_IMPLEMENT_SIGNER(type, keyType)
        /// Dynamic discovery macro. Instantiate one or more of these in the class cpp file.
        /// Example:
        /// \code{.cpp}
        /// THEKOGANS_CRYPTO_IMPLEMENT_SIGNER (OpenSSLSigner, OPENSSL_PKEY_RSA)
        /// THEKOGANS_CRYPTO_IMPLEMENT_SIGNER (OpenSSLSigner, OPENSSL_PKEY_DSA)
        /// THEKOGANS_CRYPTO_IMPLEMENT_SIGNER (OpenSSLSigner, OPENSSL_PKEY_EC)
        /// THEKOGANS_CRYPTO_IMPLEMENT_SIGNER (Ed25519Verifier, Ed25519AsymmetricKey::KEY_TYPE)
        /// \endcode
        #define THEKOGANS_CRYPTO_IMPLEMENT_SIGNER(type, keyType)
    #else // defined (THEKOGANS_CRYPTO_TYPE_Static)
        /// \def THEKOGANS_CRYPTO_DECLARE_SIGNER(type)
        /// Dynamic discovery macro. Add this to your class declaration.
        /// Example:
        /// \code{.cpp}
        /// struct _LIB_THEKOGANS_CRYPTO_DECL OpenSSLSigner : public Signer {
        ///     THEKOGANS_CRYPTO_DECLARE_SIGNER (OpenSSLSigner)
        ///     ...
        /// };
        /// \endcode
        #define THEKOGANS_CRYPTO_DECLARE_SIGNER(type)\
            THEKOGANS_CRYPTO_DECLARE_SIGNER_COMMON (type)

        /// \def THEKOGANS_CRYPTO_IMPLEMENT_SIGNER(type, keyType)
        /// Dynamic discovery macro. Instantiate one or more of these in the class cpp file.
        /// Example:
        /// \code{.cpp}
        /// THEKOGANS_CRYPTO_IMPLEMENT_SIGNER (OpenSSLSigner, OPENSSL_PKEY_RSA)
        /// THEKOGANS_CRYPTO_IMPLEMENT_SIGNER (OpenSSLSigner, OPENSSL_PKEY_DSA)
        /// THEKOGANS_CRYPTO_IMPLEMENT_SIGNER (OpenSSLSigner, OPENSSL_PKEY_EC)
        /// THEKOGANS_CRYPTO_IMPLEMENT_SIGNER (Ed25519Verifier, Ed25519AsymmetricKey::KEY_TYPE)
        /// \endcode
        #define THEKOGANS_CRYPTO_IMPLEMENT_SIGNER(type, keyType)\
        namespace {\
            const thekogans::crypto::Signer::MapInitializer THEKOGANS_UTIL_UNIQUE_NAME (mapInitializer) (\
                keyType, type::Create);\
        }
    #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Signer_h)
