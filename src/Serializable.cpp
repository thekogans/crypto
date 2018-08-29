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
#include "thekogans/crypto/OpenSSLParams.h"
#include "thekogans/crypto/Ed25519Params.h"
#include "thekogans/crypto/X25519Params.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/OpenSSLAsymmetricKey.h"
#include "thekogans/crypto/Ed25519AsymmetricKey.h"
#include "thekogans/crypto/X25519AsymmetricKey.h"
#include "thekogans/crypto/DHEKeyExchange.h"
#include "thekogans/crypto/RSAKeyExchange.h"
#include "thekogans/crypto/Serializable.h"

namespace thekogans {
    namespace crypto {

    #if defined (TOOLCHAIN_TYPE_Static)
        void Serializable::StaticInit () {
            static volatile bool registered = false;
            static util::SpinLock spinLock;
            util::LockGuard<util::SpinLock> guard (spinLock);
            if (!registered) {
                KeyRing::StaticInit ();
                OpenSSLParams::StaticInit ();
                Ed25519Params::StaticInit ();
                X25519Params::StaticInit ();
                SymmetricKey::StaticInit ();
                OpenSSLAsymmetricKey::StaticInit ();
                Ed25519AsymmetricKey::StaticInit ();
                X25519AsymmetricKey::StaticInit ();
                DHEKeyExchange::DHEParams::StaticInit ();
                RSAKeyExchange::RSAParams::StaticInit ();
                registered = true;
            }
        }
    #endif // defined (TOOLCHAIN_TYPE_Static)

        std::size_t Serializable::Size () const {
            return
                util::Serializer::Size (id) +
                util::Serializer::Size (name) +
                util::Serializer::Size (description);
        }

        void Serializable::Read (
                const Header & /*header*/,
                util::Serializer &serializer) {
            serializer >> id >> name >> description;
        }

        void Serializable::Write (util::Serializer &serializer) const {
            serializer << id << name << description;
        }

        const char * const Serializable::TAG_SERIALIZABLE = "Serializable";
        const char * const Serializable::ATTR_TYPE = "Type";
        const char * const Serializable::ATTR_ID = "Id";
        const char * const Serializable::ATTR_NAME = "Name";
        const char * const Serializable::ATTR_DESCRIPTION = "Description";

    } // namespace crypto
} // namespace thekogans
