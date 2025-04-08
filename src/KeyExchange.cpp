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
#if defined (THEKOGANS_CRYPTO_TYPE_Static)
    #include "thekogans/crypto/DHEKeyExchange.h"
    #include "thekogans/crypto/RSAKeyExchange.h"
#endif // defined (THEKOGANS_CRYPTO_TYPE_Static)
#include "thekogans/crypto/KeyExchange.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_UTIL_IMPLEMENT_DYNAMIC_CREATABLE_ABSTRACT_BASE (
            thekogans::crypto::KeyExchange::Params)

    #if defined (THEKOGANS_CRYPTO_TYPE_Static)
        void KeyExchange::Params::StaticInit () {
            DHEKeyExchange::DHEParams::StaticInit ();
            RSAKeyExchange::RSAParams::StaticInit ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TYPE_Static)

        std::size_t KeyExchange::Params::Size () const noexcept {
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

        namespace {
            const char * const ATTR_ID = "Id";
            const char * const ATTR_SIGNATURE = "Signature";
            const char * const ATTR_SIGNATURE_KEY_ID = "SignatureKeyId";
            const char * const ATTR_SIGNATURE_MESSAGE_DIGEST_NAME = "SignatureMessageDigestName";
        }

        void KeyExchange::Params::Read (
                const Header & /*header*/,
                const pugi::xml_node &node) {
            id = ID::FromHexString (node.attribute (ATTR_ID).value ());
            signature = util::HexDecodestring (node.attribute (ATTR_SIGNATURE).value ());
            signatureKeyId = ID::FromHexString (node.attribute (ATTR_SIGNATURE_KEY_ID).value ());
            signatureMessageDigestName = node.attribute (ATTR_SIGNATURE_MESSAGE_DIGEST_NAME).value ();
        }

        void KeyExchange::Params::Write (pugi::xml_node &node) const {
            node.append_attribute (ATTR_ID).set_value (id.ToHexString ().c_str ());
            node.append_attribute (ATTR_SIGNATURE).set_value (
                util::HexEncodeBuffer (signature.data (), signature.size ()).c_str ());
            node.append_attribute (ATTR_SIGNATURE_KEY_ID).set_value (
                signatureKeyId.ToHexString ().c_str ());
            node.append_attribute (ATTR_SIGNATURE_MESSAGE_DIGEST_NAME).set_value (
                signatureMessageDigestName.c_str ());
        }

        void KeyExchange::Params::Read (
                const Header & /*header*/,
                const util::JSON::Object &object) {
            id = ID::FromHexString (object.Get<util::JSON::String> (ATTR_ID)->value);
            signature = util::HexDecodestring (
                object.Get<util::JSON::String> (ATTR_SIGNATURE)->value);
            signatureKeyId = ID::FromHexString (
                object.Get<util::JSON::String> (ATTR_SIGNATURE_KEY_ID)->value);
            signatureMessageDigestName =
                object.Get<util::JSON::String> (ATTR_SIGNATURE_MESSAGE_DIGEST_NAME)->value;
        }

        void KeyExchange::Params::Write (util::JSON::Object &object) const {
            object.Add<const std::string &> (
                ATTR_ID,
                id.ToHexString ());
            object.Add<const std::string &> (
                ATTR_SIGNATURE,
                util::HexEncodeBuffer (signature.data (), signature.size ()));
            object.Add<const std::string &> (
                ATTR_SIGNATURE_KEY_ID,
                signatureKeyId.ToHexString ());
            object.Add<const std::string &> (
                ATTR_SIGNATURE_MESSAGE_DIGEST_NAME,
                signatureMessageDigestName);
        }

    } // namespace crypto
} // namespace thekogans
