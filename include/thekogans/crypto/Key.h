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

#if !defined (__thekogans_crypto_Key_h)
#define __thekogans_crypto_Key_h

#include <string>
#include "thekogans/util/Types.h"
#include "thekogans/util/Heap.h"
#include "thekogans/util/RefCounted.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/ID.h"

namespace thekogans {
    namespace crypto {

        /// \struct Key Key.h thekogans/crypto/Key.h
        ///
        /// \brief
        /// Key is an abstract base for all supported key types (See \see{SymmetricKey}
        /// and \see{AsymmetricKey}). It exposes a globally unique key id (See \see{ID})
        /// that can be used to locate keys in the \see{KeyRing}. Keys can also be looked
        /// up by name.

        struct _LIB_THEKOGANS_CRYPTO_DECL Key : public util::ThreadSafeRefCounted {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<Key>.
            typedef util::ThreadSafeRefCounted::Ptr<Key> Ptr;

            /// \brief
            /// typedef for the Key factory function.
            typedef Ptr (*Factory) (util::Serializer &serializer);
            /// \brief
            /// typedef for the Key map.
            typedef std::map<std::string, Factory> Map;
            /// \brief
            /// Controls Map's lifetime.
            static Map &GetMap ();
            /// \brief
            /// Used for Key dynamic discovery and creation.
            /// \param[in] serializer Serializer containing the Key.
            /// \return A deserialized key.
            static Ptr Get (util::Serializer &serializer);
            /// \struct Key::MapInitializer Key.h thekogans/crypto/Key.h
            ///
            /// \brief
            /// MapInitializer is used to initialize the Key::map.
            /// It should not be used directly, and instead is included
            /// in THEKOGANS_CRYPTO_DECLARE_KEY/THEKOGANS_CRYPTO_IMPLEMENT_KEY.
            /// If you are deriving a key from Key, and you want
            /// it to be dynamically discoverable/creatable, add
            /// THEKOGANS_CRYPTO_DECLARE_KEY to it's declaration,
            /// and THEKOGANS_CRYPTO_IMPLEMENT_KEY to it's definition.
            struct _LIB_THEKOGANS_CRYPTO_DECL MapInitializer {
                /// \brief
                /// ctor. Add key of type, and factory for creating it
                /// to the Key::map
                /// \param[in] type Key type (it's class name).
                /// \param[in] factory Key creation factory.
                MapInitializer (
                    const std::string &type,
                    Factory factory);
            };

        protected:
            /// \brief
            /// key id.
            ID id;
            /// \brief
            /// Optional key name.
            std::string name;
            /// \brief
            /// Optional key description.
            std::string description;

        public:
            /// \brief
            /// ctor.
            /// \param[in] name_ Optional key name.
            /// \param[in] description_ Optional key description.
            Key (
                const std::string &name_ = std::string (),
                const std::string &description_ = std::string ()) :
                name (name_),
                description (description_) {}
            /// \brief
            /// ctor.
            /// \param[in] serializer Serializer containing the key.
            explicit Key (util::Serializer &serializer);
            /// \brief
            /// dtor.
            virtual ~Key () {}

            /// Return the key id.
            /// \return key id.
            inline const ID &GetId () const {
                return id;
            }

            /// Return the key name.
            /// \return Key name.
            inline const std::string &GetName () const {
                return name;
            }

            /// Return the key description.
            /// \return Key description.
            inline const std::string &GetDescription () const {
                return description;
            }

            /// \brief
            /// Return key type (it's class name).
            /// \return Key type.
            virtual std::string Type () const = 0;

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
            /// "Key"
            static const char * const TAG_KEY;
            /// \brief
            /// "Type"
            static const char * const ATTR_TYPE;
            /// \brief
            /// "Id"
            static const char * const ATTR_ID;
            /// \brief
            /// "Name"
            static const char * const ATTR_NAME;
            /// \brief
            /// "Description"
            static const char * const ATTR_DESCRIPTION;

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
                const char *tagName = TAG_KEY) const = 0;
        #endif // defined (THEKOGANS_CRYPTO_TESTING)
        };

        /// \def THEKOGANS_CRYPTO_DECLARE_KEY_COMMON(type)
        /// Common code used by Static and Shared versions THEKOGANS_CRYPTO_DECLARE_KEY.
        #define THEKOGANS_CRYPTO_DECLARE_KEY_COMMON(type)\
            typedef thekogans::util::ThreadSafeRefCounted::Ptr<type> Ptr;\
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (type, thekogans::util::SpinLock)\
        public:\
            static thekogans::crypto::Key::Ptr Create (thekogans::util::Serializer &serializer) {\
                return thekogans::crypto::Key::Ptr (new type (serializer));\
            }\
            virtual std::string Type () const {\
                return #type;\
            }

        /// \def THEKOGANS_CRYPTO_IMPLEMENT_KEY_COMMON(type)
        /// Common code used by Static and Shared versions THEKOGANS_CRYPTO_IMPLEMENT_KEY.
        #define THEKOGANS_CRYPTO_IMPLEMENT_KEY_COMMON(type, minKeysInPage)\
            THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK_EX_AND_ALLOCATOR (\
                type,\
                thekogans::util::SpinLock,\
                minKeysInPage,\
                thekogans::util::SecureAllocator::Global)

    #if defined (TOOLCHAIN_TYPE_Static)
        /// \def THEKOGANS_CRYPTO_DECLARE_KEY(type)
        /// Dynamic discovery macro. Add this to your class declaration.
        /// Example:
        /// \code{.cpp}
        /// struct _LIB_THEKOGANS_CRYPTO_DECL SymmetricKey : public Key {
        ///     THEKOGANS_CRYPTO_DECLARE_KEY (SymmetricKey)
        ///     ...
        /// };
        /// \endcode
        #define THEKOGANS_CRYPTO_DECLARE_KEY(type)\
            THEKOGANS_CRYPTO_DECLARE_KEY_COMMON (type)\
            static void StaticInit () {\
                std::pair<Map::iterator, bool> result =\
                    GetMap ().insert (Map::value_type (#type, type::Create));\
                if (!result.second) {\
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (\
                        "'%s' is already registered.", #type);\
                }\
            }

        /// \def THEKOGANS_CRYPTO_IMPLEMENT_KEY(type, minKeysInPage)
        /// Dynamic discovery macro. Instantiate one of these in the class cpp file.
        /// Example:
        /// \code{.cpp}
        /// #if !defined (THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        ///     #define THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE 16
        /// #endif // !defined (THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        ///
        /// THEKOGANS_CRYPTO_IMPLEMENT_KEY (SymmetricKey, THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        /// \endcode
        #define THEKOGANS_CRYPTO_IMPLEMENT_KEY(type, minKeysInPage)\
            THEKOGANS_CRYPTO_IMPLEMENT_KEY_COMMON (type, minKeysInPage)
    #else // defined (TOOLCHAIN_TYPE_Static)
        /// \def THEKOGANS_CRYPTO_DECLARE_KEY(type)
        /// Dynamic discovery macro. Add this to your class declaration.
        /// Example:
        /// \code{.cpp}
        /// struct _LIB_THEKOGANS_CRYPTO_DECL SymmetricKey : public Key {
        ///     THEKOGANS_CRYPTO_DECLARE_KEY (SymmetricKey)
        ///     ...
        /// };
        /// \endcode
        #define THEKOGANS_CRYPTO_DECLARE_KEY(type)\
            THEKOGANS_CRYPTO_DECLARE_KEY_COMMON (type)\
            static thekogans::crypto::Key::MapInitializer mapInitializer;

        /// \def THEKOGANS_CRYPTO_IMPLEMENT_KEY(type, minKeysInPage)
        /// Dynamic discovery macro. Instantiate one of these in the class cpp file.
        /// Example:
        /// \code{.cpp}
        /// #if !defined (THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        ///     #define THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE 16
        /// #endif // !defined (THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        ///
        /// THEKOGANS_CRYPTO_IMPLEMENT_KEY (SymmetricKey, THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        /// \endcode
        #define THEKOGANS_CRYPTO_IMPLEMENT_KEY(type, minKeysInPage)\
            THEKOGANS_CRYPTO_IMPLEMENT_KEY_COMMON (type, minKeysInPage)\
            thekogans::crypto::Key::MapInitializer type::mapInitializer (\
                #type, type::Create);
    #endif // defined (TOOLCHAIN_TYPE_Static)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Key_h)
