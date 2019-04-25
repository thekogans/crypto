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
#include "thekogans/util/StringUtils.h"
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
                const BinHeader & /*header*/,
                util::Serializer &serializer) {
            serializer >> id >> signature >> signatureKeyId >> signatureMessageDigestName;
        }

        void KeyExchange::Params::Write (util::Serializer &serializer) const {
            serializer << id << signature << signatureKeyId << signatureMessageDigestName;
        }

        const char * const KeyExchange::Params::ATTR_ID = "Id";
        const char * const KeyExchange::Params::ATTR_SIGNATURE = "Signature";
        const char * const KeyExchange::Params::ATTR_SIGNATURE_KEY_ID = "SignatureKeyId";
        const char * const KeyExchange::Params::ATTR_SIGNATURE_MESSAGE_DIGEST_NAME = "SignatureMessageDigestName";

        void KeyExchange::Params::Read (
                const TextHeader & /*header*/,
                const pugi::xml_node &node) {
            id = node.attribute (ATTR_ID).value ();
            signature = util::HexDecodestring (node.attribute (ATTR_SIGNATURE).value ());
            signatureKeyId = node.attribute (ATTR_SIGNATURE_KEY_ID).value ();
            signatureMessageDigestName = node.attribute (ATTR_SIGNATURE_MESSAGE_DIGEST_NAME).value ();
        }

        void KeyExchange::Params::Write (pugi::xml_node &node) const {
            node.append_attribute (ATTR_ID).set_value (id.ToString ().c_str ());
            node.append_attribute (ATTR_SIGNATURE).set_value (
                util::HexEncodeBuffer (signature.data (), signature.size ()).c_str ());
            node.append_attribute (ATTR_SIGNATURE_KEY_ID).set_value (signatureKeyId.ToString ().c_str ());
            node.append_attribute (ATTR_SIGNATURE_MESSAGE_DIGEST_NAME).set_value (signatureMessageDigestName.c_str ());
        }

    } // namespace crypto
} // namespace thekogans
