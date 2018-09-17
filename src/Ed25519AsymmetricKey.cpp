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

#include <cstring>
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/Ed25519AsymmetricKey.h"

namespace thekogans {
    namespace crypto {

        #if !defined (THEKOGANS_CRYPTO_MIN_ED25519_ASYMMETRIC_KEYS_IN_PAGE)
            #define THEKOGANS_CRYPTO_MIN_ED25519_ASYMMETRIC_KEYS_IN_PAGE 16
        #endif // !defined (THEKOGANS_CRYPTO_MIN_ED25519_ASYMMETRIC_KEYS_IN_PAGE)

        THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
            Ed25519AsymmetricKey,
            1,
            THEKOGANS_CRYPTO_MIN_ED25519_ASYMMETRIC_KEYS_IN_PAGE)

        Ed25519AsymmetricKey::Ed25519AsymmetricKey (
                const util::ui8 *key_,
                bool isPrivate,
                const ID &id,
                const std::string &name,
                const std::string &description) :
                AsymmetricKey (isPrivate, id, name, description) {
            if (key_ != 0) {
                if (isPrivate) {
                    memcpy (key.privateKey, key_, Ed25519::PRIVATE_KEY_LENGTH);
                }
                else {
                    memset (key.publicKey.pad, 0, Ed25519::PRIVATE_KEY_LENGTH - Ed25519::PUBLIC_KEY_LENGTH);
                    memcpy (key.publicKey.value, key_, Ed25519::PUBLIC_KEY_LENGTH);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        const char * const Ed25519AsymmetricKey::KEY_TYPE = "Ed25519";

        AsymmetricKey::Ptr Ed25519AsymmetricKey::GetPublicKey (
                const ID &id,
                const std::string &name,
                const std::string &description) const {
            return AsymmetricKey::Ptr (
                new Ed25519AsymmetricKey (
                    key.publicKey.value,
                    false,
                    id,
                    name,
                    description));
        }

        std::size_t Ed25519AsymmetricKey::Size () const {
            return AsymmetricKey::Size () + GetKeyLength ();
        }

        void Ed25519AsymmetricKey::Read (
                const Header &header,
                util::Serializer &serializer) {
            AsymmetricKey::Read (header, serializer);
            if (IsPrivate ()) {
                if (serializer.Read (key.privateKey, X25519::PRIVATE_KEY_LENGTH) != X25519::PRIVATE_KEY_LENGTH) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Read (key.privateKey, %u) != %u",
                        X25519::PRIVATE_KEY_LENGTH,
                        X25519::PRIVATE_KEY_LENGTH);
                }
            }
            else {
                if (serializer.Read (key.publicKey.value, X25519::PUBLIC_KEY_LENGTH) != X25519::PUBLIC_KEY_LENGTH) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Read (key.publicKey.value, %u) != %u",
                        X25519::PUBLIC_KEY_LENGTH,
                        X25519::PUBLIC_KEY_LENGTH);
                }
            }
        }

        void Ed25519AsymmetricKey::Write (util::Serializer &serializer) const {
            AsymmetricKey::Write (serializer);
            if (IsPrivate ()) {
                if (serializer.Write (key.privateKey, X25519::PRIVATE_KEY_LENGTH) != X25519::PRIVATE_KEY_LENGTH) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Write (key.privateKey, %u) != %u",
                        X25519::PRIVATE_KEY_LENGTH,
                        X25519::PRIVATE_KEY_LENGTH);
                }
            }
            else {
                if (serializer.Write (key.publicKey.value, X25519::PUBLIC_KEY_LENGTH) != X25519::PUBLIC_KEY_LENGTH) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Write (key.publicKey.value, %u) != %u",
                        X25519::PUBLIC_KEY_LENGTH,
                        X25519::PUBLIC_KEY_LENGTH);
                }
            }
        }

        const char * const Ed25519AsymmetricKey::ATTR_KEY = "Key";

        std::string Ed25519AsymmetricKey::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            util::Attributes attributes;
            attributes.push_back (util::Attribute (ATTR_TYPE, Type ()));
            attributes.push_back (util::Attribute (ATTR_ID, id.ToString ()));
            attributes.push_back (util::Attribute (ATTR_NAME, name));
            attributes.push_back (util::Attribute (ATTR_DESCRIPTION, description));
            attributes.push_back (util::Attribute (ATTR_PRIVATE, util::boolTostring (IsPrivate ())));
            attributes.push_back (util::Attribute (ATTR_KEY_TYPE, GetKeyType ()));
            attributes.push_back (util::Attribute (ATTR_KEY_LENGTH, util::size_tTostring (GetKeyLength ())));
            attributes.push_back (
                util::Attribute (
                    ATTR_KEY,
                    util::HexEncodeBuffer (
                        IsPrivate () ? key.privateKey : key.publicKey.value,
                        GetKeyLength ())));
            return util::OpenTag (indentationLevel, tagName, attributes, true, true);
        }

    } // namespace crypto
} // namespace thekogans
