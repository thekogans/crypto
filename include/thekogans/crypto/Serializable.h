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
#if defined (THEKOGANS_CRYPTO_TESTING)
    #include "thekogans/util/Types.h"
#endif // defined (THEKOGANS_CRYPTO_TESTING)
#include "thekogans/util/Serializable.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/ID.h"

namespace thekogans {
    namespace crypto {

        /// \struct Serializable Serializable.h thekogans/crypto/Serializable.h
        ///
        /// \brief
        /// Serializable extends the \see{util::Serializable} to add id, name and description.
        /// It's the base class for all crypto serializables (See \see{KeyRing}, \see{Params},
        /// \see{SymmetricKey} and \see{AsymmetricKey}).

        struct _LIB_THEKOGANS_CRYPTO_DECL Serializable : public util::Serializable {
            /// \brief
            /// Convenient typedef for util::ThreadSafeRefCounted::Ptr<Serializable>.
            typedef util::ThreadSafeRefCounted::Ptr<Serializable> Ptr;

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
            /// \param[in] id_ Optional serializable id.
            /// \param[in] name_ Optional serializable name.
            /// \param[in] description_ Optional serializable description.
            Serializable (
                const ID &id_ = ID (),
                const std::string &name_ = std::string (),
                const std::string &description_ = std::string ()) :
                id (id_),
                name (name_),
                description (description_) {}

        #if defined (TOOLCHAIN_TYPE_Static)
            /// \brief
            /// Because Serializable uses dynamic initialization, when using
            /// it in static builds call this method to have the Serializable
            /// explicitly include all internal serializable types. Without
            /// calling this api, the only serializables that will be available
            /// to your application are the ones you explicitly link to.
            static void StaticInit ();
        #endif // defined (TOOLCHAIN_TYPE_Static)

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

        protected:
            // util::Serializable
            /// \brief
            /// Return the serializable size.
            /// \return Serializable size.
            virtual std::size_t Size () const;

            /// \brief
            /// Read the serializable from the given serializer.
            /// \param[in] header \see{util::Serializable::Header}.
            /// \param[in] serializer \see{util::Serializer} to read the serializable from.
            virtual void Read (
                const Header &header,
                util::Serializer &serializer);
            /// \brief
            /// Write the serializable to the given serializer.
            /// \param[out] serializer \see{util::Serializer} to write the serializable to.
            virtual void Write (util::Serializer &serializer) const;

        public:
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
            THEKOGANS_UTIL_DECLARE_SERIALIZABLE (type, thekogans::util::SpinLock)

        /// \def THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE(type, version, minSerializablesInPage)
        /// Dynamic discovery macro. Instantiate one of these in the class cpp file.
        /// Example:
        /// \code{.cpp}
        /// #if !defined (THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        ///     #define THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE 16
        /// #endif // !defined (THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        ///
        /// THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
        ///     SymmetricKey,
        ///     1,
        ///     THEKOGANS_CRYPTO_MIN_SYMMETRIC_KEYS_IN_PAGE)
        /// \endcode
        #define THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE(type, version, minSerializablesInPage)\
            THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (\
                type,\
                version,\
                thekogans::util::SpinLock,\
                minSerializablesInPage,\
                thekogans::util::SecureAllocator::Global)

        /// \brief
        /// Implement Serializable extraction operator.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATOR (Serializable)

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Serializable_h)
