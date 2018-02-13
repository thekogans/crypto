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

#if !defined (__thekogans_crypto_Serializable_h)
#define __thekogans_crypto_Serializable_h

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

        /// \struct Serializable Serializable.h thekogans/crypto/Serializable.h
        ///
        /// \brief
        /// Serializable is an abstract base for all supported serializable types (See
        /// \see{KeyRing}, \see{Params}, \see{SymmetricKey} and \see{AsymmetricKey}).
        /// It exposes a globally unique id (See \see{ID}) that can be used to locate
        /// objects in the \see{KeyRing}.

        struct _LIB_THEKOGANS_CRYPTO_DECL Serializable : public util::ThreadSafeRefCounted {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<Serializable>.
            typedef util::ThreadSafeRefCounted::Ptr<Serializable> Ptr;

            /// \brief
            /// typedef for the Serializable factory function.
            typedef Ptr (*Factory) (util::Serializer &serializer);
            /// \brief
            /// typedef for the Serializable map.
            typedef std::map<std::string, Factory> Map;
            /// \brief
            /// Controls Map's lifetime.
            /// \return Serializable map.
            static Map &GetMap ();
            /// \brief
            /// Used for Serializable dynamic discovery and creation.
            /// \param[in] serializer Serializer containing the Serializable.
            /// \return A deserialized serializable.
            static Ptr Get (util::Serializer &serializer);
            /// \struct Serializable::MapInitializer Serializable.h thekogans/crypto/Serializable.h
            ///
            /// \brief
            /// MapInitializer is used to initialize the Serializable::map.
            /// It should not be used directly, and instead is included
            /// in THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE/THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE.
            /// If you are deriving a serializable from Serializable, and you want
            /// it to be dynamically discoverable/creatable, add
            /// THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE to it's declaration,
            /// and THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE to it's definition.
            struct _LIB_THEKOGANS_CRYPTO_DECL MapInitializer {
                /// \brief
                /// ctor. Add serializable of type, and factory for creating it
                /// to the Serializable::map
                /// \param[in] type Serializable type (it's class name).
                /// \param[in] factory Serializable creation factory.
                MapInitializer (
                    const std::string &type,
                    Factory factory);
            };

        protected:
            /// \brief
            /// Serializable id.
            ID id;
            /// \brief
            /// Optional serializable name.
            std::string name;
            /// \brief
            /// Optional serializable description.
            std::string description;

        public:
            /// \brief
            /// ctor.
            /// \param[in] name_ Optional serializable name.
            /// \param[in] description_ Optional serializable description.
            Serializable (
                const std::string &name_ = std::string (),
                const std::string &description_ = std::string ()) :
                name (name_),
                description (description_) {}
            /// \brief
            /// ctor.
            /// \param[in] serializer Serializer containing the serializable.
            explicit Serializable (util::Serializer &serializer);
            /// \brief
            /// dtor.
            virtual ~Serializable () {}

            /// \brief
            /// Return the serializable id.
            /// \return Serializable id.
            inline const ID &GetId () const {
                return id;
            }

            /// \brief
            /// Return the serializable name.
            /// \return Serializable name.
            inline const std::string &GetName () const {
                return name;
            }
            /// \brief
            /// Set the serializable name.
            /// \param[in] name_ New name to set.
            inline void SetName (const std::string &name_) {
                name = name_;
            }

            /// \brief
            /// Return the serializable description.
            /// \return Serializable description.
            inline const std::string &GetDescription () const {
                return description;
            }
            /// \brief
            /// Set the serializable description.
            /// \param[in] description_ New description to set.
            inline void SetDescription (const std::string &description_) {
                description = description_;
            }

            /// \brief
            /// Return serializable type (it's class name).
            /// \return Serializable type.
            virtual std::string Type () const = 0;

            /// \brief
            /// Return the serializable size.
            /// \param[in] includeType true = include serializable's type in size calculation.
            /// \return Serializable size.
            virtual std::size_t Size (bool includeType = true) const;

            /// \brief
            /// Write the serializable to the given serializer.
            /// \param[out] serializer Serializer to write the serializable to.
            /// \param[in] includeType true = Serialize serializable's type to be used by Get above.
            virtual void Serialize (
                util::Serializer &serializer,
                bool includeType = true) const;

        #if defined (THEKOGANS_CRYPTO_TESTING)
            /// \brief
            /// "Serializable"
            static const char * const TAG_SERIALIZABLE;
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
            /// Return the XML representation of a serializable.
            /// ********************** WARNING **********************
            /// This is antithetical to security which is precisely
            /// why it should be used only for testing and turned off
            /// when building for production.
            /// *****************************************************
            /// \param[in] indentationLevel How far to indent the leading tag.
            /// \param[in] tagName The name of the leading tag.
            /// \return XML representation of a serializable.
            virtual std::string ToString (
                util::ui32 indentationLevel = 0,
                const char *tagName = TAG_SERIALIZABLE) const = 0;
        #endif // defined (THEKOGANS_CRYPTO_TESTING)
        };

        /// \def THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE_COMMON(type)
        /// Common code used by Static and Shared versions THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE.
        #define THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE_COMMON(type)\
            typedef thekogans::util::ThreadSafeRefCounted::Ptr<type> Ptr;\
            THEKOGANS_UTIL_DECLARE_HEAP_WITH_LOCK (type, thekogans::util::SpinLock)\
        public:\
            static thekogans::crypto::Serializable::Ptr Create (thekogans::util::Serializer &serializer) {\
                return thekogans::crypto::Serializable::Ptr (new type (serializer));\
            }\
            static const char *TYPE;\
            virtual std::string Type () const {\
                return TYPE;\
            }

        /// \def THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE_COMMON(type)
        /// Common code used by Static and Shared versions THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE.
        #define THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE_COMMON(type, minSerializablesInPage)\
            const char *type::TYPE = #type;\
            THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK_EX_AND_ALLOCATOR (\
                type,\
                thekogans::util::SpinLock,\
                minSerializablesInPage,\
                thekogans::util::SecureAllocator::Global)

    #if defined (TOOLCHAIN_TYPE_Static)
        /// \def THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE(type)
        /// Dynamic discovery macro. Add this to your class declaration.
        /// Example:
        /// \code{.cpp}
        /// struct _LIB_THEKOGANS_CRYPTO_DECL SymmetricKey : public Serializable {
        ///     THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (SymmetricKey)
        ///     ...
        /// };
        /// \endcode
        #define THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE(type)\
            THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE_COMMON (type)\
            static void StaticInit () {\
                std::pair<Map::iterator, bool> result =\
                    GetMap ().insert (Map::value_type (#type, type::Create));\
                if (!result.second) {\
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (\
                        "'%s' is already registered.", #type);\
                }\
            }

        /// \def THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE(type, minSerializablesInPage)
        /// Dynamic discovery macro. Instantiate one of these in the class cpp file.
        /// Example:
        /// \code{.cpp}
        /// #if !defined (THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        ///     #define THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE 16
        /// #endif // !defined (THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        ///
        /// THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
        ///     SymmetricKey,
        ///     THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        /// \endcode
        #define THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE(type, minSerializablesInPage)\
            THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE_COMMON (type, minSerializablesInPage)
    #else // defined (TOOLCHAIN_TYPE_Static)
        /// \def THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE(type)
        /// Dynamic discovery macro. Add this to your class declaration.
        /// Example:
        /// \code{.cpp}
        /// struct _LIB_THEKOGANS_CRYPTO_DECL SymmetricKey : public Serializable {
        ///     THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE (SymmetricKey)
        ///     ...
        /// };
        /// \endcode
        #define THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE(type)\
            THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE_COMMON (type)\
            static thekogans::crypto::Serializable::MapInitializer mapInitializer;

        /// \def THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE(type, minSerializablesInPage)
        /// Dynamic discovery macro. Instantiate one of these in the class cpp file.
        /// Example:
        /// \code{.cpp}
        /// #if !defined (THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        ///     #define THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE 16
        /// #endif // !defined (THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        ///
        /// THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
        ///     SymmetricKey,
        ///     THEKOGANS_CRYPTO_MIN_SYMMETRIC_SERIALIZABLES_IN_PAGE)
        /// \endcode
        #define THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE(type, minSerializablesInPage)\
            THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE_COMMON (type, minSerializablesInPage)\
            thekogans::crypto::Serializable::MapInitializer type::mapInitializer (\
                #type, type::Create);
    #endif // defined (TOOLCHAIN_TYPE_Static)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Serializable_h)
