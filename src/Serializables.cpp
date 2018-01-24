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

#include "thekogans/util/SpinLock.h"
#include "thekogans/util/LockGuard.h"
#include "thekogans/crypto/KeyRing.h"
#include "thekogans/crypto/Params.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/Serializables.h"

namespace thekogans {
    namespace crypto {

    #if defined (TOOLCHAIN_TYPE_Static)
        void Serializables::StaticInit () {
            static volatile bool registered = false;
            static util::SpinLock spinLock;
            util::LockGuard<util::SpinLock> guard (spinLock);
            if (!registered) {
                KeyRing::StaticInit ();
                Params::StaticInit ();
                SymmetricKey::StaticInit ();
                AsymmetricKey::StaticInit ();
                registered = true;
            }
        }
    #endif // defined (TOOLCHAIN_TYPE_Static)

    } // namespace crypto
} // namespace thekogans
