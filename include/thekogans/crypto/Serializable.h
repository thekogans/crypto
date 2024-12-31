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
            /// Declare \see{RefCounted} pointers.
            THEKOGANS_UTIL_DECLARE_DYNAMIC_CREATABLE_BASE (Serializable)

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

        #if defined (THEKOGANS_CRYPTO_TYPE_Static)
            /// \brief
            /// Because Serializable uses dynamic initialization, when using
            /// it in static builds call this method to have the Serializable
            /// explicitly include all internal serializable types. Without
            /// calling this api, the only serializables that will be available
            /// to your application are the ones you explicitly link to.
            /// NOTE: If you're using OpenSSLInit, this call is done for you.
            static void StaticInit ();
        #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

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

            // util::Serializable
            /// \brief
            /// Return the serializable size (without the header).
            /// \return Serializable size.
            virtual std::size_t Size () const override;

            /// \brief
            /// Read the serializable from the given serializer.
            /// \param[in] header \see{util::Serializable::BinHeader}.
            /// \param[in] serializer \see{util::Serializer} to read the serializable from.
            virtual void Read (
                const BinHeader & /*header*/,
                util::Serializer &serializer) override;
            /// \brief
            /// Write the serializable to the given serializer.
            /// \param[out] serializer \see{util::Serializer} to write the serializable to.
            virtual void Write (util::Serializer &serializer) const override;

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
            /// Read the Serializable from an XML DOM.
            /// \param[in] header \see{util::Serializable::TextHeader}.
            /// \param[in] node XML DOM representation of a Serializable.
            virtual void Read (
                const TextHeader & /*header*/,
                const pugi::xml_node &node) override;
            /// \brief
            /// Write the Serializable to the XML DOM.
            /// \param[out] node Parent node.
            virtual void Write (pugi::xml_node &node) const override;

            /// \brief
            /// Read a Serializable from an JSON DOM.
            /// \param[in] node JSON DOM representation of a Serializable.
            virtual void Read (
                const TextHeader & /*header*/,
                const util::JSON::Object &object) override;
            /// \brief
            /// Write a Serializable to the JSON DOM.
            /// \param[out] node Parent node.
            virtual void Write (util::JSON::Object &object) const override;
        };

        /// \brief
        /// Implement Serializable::SharedPtr extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_PTR_EXTRACTION_OPERATORS (Serializable)

        /// \def THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE(_T)
        /// Common declarations used by all Serializable derivatives.
        #define THEKOGANS_CRYPTO_DECLARE_SERIALIZABLE(_T)\
            THEKOGANS_UTIL_DECLARE_SERIALIZABLE (_T)\
            THEKOGANS_UTIL_DECLARE_STD_ALLOCATOR_FUNCTIONS

        /// \def THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE(_T, _B, version, minItemsInPage)
        /// Common implementations used by all Value derivatives.
        #define THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE(_T, _B, version, minItemsInPage)\
            THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (_T, _B, version)\
            THEKOGANS_UTIL_IMPLEMENT_HEAP_FUNCTIONS_EX (\
                _T,\
                thekogans::util::SpinLock,\
                minItemsInPage,\
                thekogans::util::SecureAllocator::Instance ())

    } // namespace crypto

    namespace util {

        /// \brief
        /// Implement Serializable::SharedPtr value parser.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_PTR_VALUE_PARSER (crypto::Serializable)

    } // namespace util
} // namespace thekogans

#endif // !defined (__thekogans_crypto_Serializable_h)
