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

#if !defined (__thekogans_crypto_OpenSSLAllocator_h)
#define __thekogans_crypto_OpenSSLAllocator_h

#include <cstddef>
#include "thekogans/util/Allocator.h"
#include "thekogans/crypto/Config.h"

namespace thekogans {
    namespace crypto {

        /// \struct OpenSSLAllocator OpenSSLAllocator.h thekogans/crypto/OpenSSLAllocator.h
        ///
        /// \brief
        /// Wraps OPENSSL_malloc/free to allow OpenSSL allocated objects
        /// to be used with thekogans.net allocator machinery.

        struct _LIB_THEKOGANS_CRYPTO_DECL OpenSSLAllocator : public util::Allocator {
            /// \brief
            /// OpenSSLAllocator participates in the \see{util::Allocator} dynamic
            /// discovery and creation.
            THEKOGANS_UTIL_DECLARE_ALLOCATOR (OpenSSLAllocator)

            /// \brief
            /// Global OpenSSLAllocator.
            static OpenSSLAllocator Global;

            /// \brief
            /// ctor.
            OpenSSLAllocator () {}

            /// \brief
            /// Allocate a block.
            /// NOTE: Allocator policy is to return (void *)0 if size == 0.
            /// if size > 0 and an error occurs, Allocator will throw an exception.
            /// \param[in] size Size of block to allocate.
            /// \return Pointer to the allocated block ((void *)0 if size == 0).
            virtual void *Alloc (std::size_t size);
            /// \brief
            /// Free a previously Alloc(ated) block.
            /// NOTE: Allocator policy is to do nothing if ptr == 0.
            /// \param[in] ptr Pointer to the block returned by Alloc.
            /// \param[in] size Same size parameter previously passed in to Alloc.
            virtual void Free (
                void *ptr,
                std::size_t /*size*/);

            /// \brief
            /// OpenSSLAllocator is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (OpenSSLAllocator)
        };

        /// \def THEKOGANS_CRYPTO_IMPLEMENT_OPEN_SSL_ALLOCATOR_FUNCTIONS(type)
        /// Macro to implement OpenSSLAllocator functions.
        #define THEKOGANS_CRYPTO_IMPLEMENT_OPEN_SSL_ALLOCATOR_FUNCTIONS(type)\
        void *type::operator new (std::size_t size) {\
            assert (size == sizeof (type));\
            return thekogans::crypto::OpenSSLAllocator::Global.Alloc (size);\
        }\
        void *type::operator new (\
                std::size_t size,\
                std::nothrow_t) throw () {\
            assert (size == sizeof (type));\
            return thekogans::crypto::OpenSSLAllocator::Global.Alloc (size);\
        }\
        void *type::operator new (\
                std::size_t size,\
                void *ptr) {\
            assert (size == sizeof (type));\
            return ptr;\
        }\
        void type::operator delete (void *ptr) {\
            thekogans::crypto::OpenSSLAllocator::Global.Free (ptr, sizeof (type));\
        }\
        void type::operator delete (\
                void *ptr,\
                std::nothrow_t) throw () {\
            thekogans::crypto::OpenSSLAllocator::Global.Free (ptr, sizeof (type));\
        }\
        void type::operator delete (\
            void *,\
            void *) {}

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_OpenSSLAllocator_h)
