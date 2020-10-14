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

#include <openssl/crypto.h>
#include "thekogans/crypto/OpenSSLAllocator.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_UTIL_IMPLEMENT_ALLOCATOR (OpenSSLAllocator)

        OpenSSLAllocator &OpenSSLAllocator::Instance () {
            static OpenSSLAllocator *instance = new OpenSSLAllocator;
            return *instance;
        }

        void *OpenSSLAllocator::Alloc (std::size_t size) {
            return size > 0 ? OPENSSL_malloc (size) : 0;
        }

        void OpenSSLAllocator::Free (
                void *ptr,
                std::size_t /*size*/) {
            if (ptr != 0) {
                OPENSSL_free (ptr);
            }
        }

    } // namespace crypto
} // namespace thekogans
