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

#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/KeyExchange.h"

namespace thekogans {
    namespace crypto {

        std::size_t KeyExchange::Params::Size () const {
            return
                util::Serializer::Size (id) +
                util::Serializer::Size (signature) +
                util::Serializer::Size (signatureKeyId) +
                util::Serializer::Size (signatureMessageDigestName);
        }

        void KeyExchange::Params::Read (
                const Header & /*header*/,
                util::Serializer &serializer) {
            serializer >> id >> signature >> signatureKeyId >> signatureMessageDigestName;
        }

        void KeyExchange::Params::Write (util::Serializer &serializer) const {
            serializer << id << signature << signatureKeyId << signatureMessageDigestName;
        }

    } // namespace crypto
} // namespace thekogans
