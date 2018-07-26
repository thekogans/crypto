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

#include "thekogans/crypto/X25519AsymmetricKey.h"

namespace thekogans {
    namespace crypto {

        #if !defined (THEKOGANS_CRYPTO_MIN_X25519_ASYMMETRIC_KEYS_IN_PAGE)
            #define THEKOGANS_CRYPTO_MIN_X25519_ASYMMETRIC_KEYS_IN_PAGE 16
        #endif // !defined (THEKOGANS_CRYPTO_MIN_X25519_ASYMMETRIC_KEYS_IN_PAGE)

        THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
            X25519AsymmetricKey,
            1,
            THEKOGANS_CRYPTO_MIN_X25519_ASYMMETRIC_KEYS_IN_PAGE)

        X25519AsymmetricKey::X25519AsymmetricKey (
                const util::ui8 *key_,
                bool isPrivate,
                const ID &id,
                const std::string &name,
                const std::string &description) :
                AsymmetricKey (isPrivate, id, name, description) {
            if (key_ != 0) {
                key.Write (key_, X25519::KEY_LENGTH);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        const char * const X25519AsymmetricKey::KEY_TYPE = "X25519";

        AsymmetricKey::Ptr X25519AsymmetricKey::GetPublicKey (
                const ID &id,
                const std::string &name,
                const std::string &description) const {
            util::ui8 publicKey[X25519::PUBLIC_KEY_LENGTH];
            if (IsPrivate ()) {
                X25519::GetPublicKey (key.GetReadPtr (), publicKey);
            }
            else {
                memcpy (publicKey, key.GetReadPtr (), X25519::PUBLIC_KEY_LENGTH);
            }
            return AsymmetricKey::Ptr (
                new X25519AsymmetricKey (
                    publicKey,
                    false,
                    id,
                    name,
                    description));
        }

        std::size_t X25519AsymmetricKey::Size () const {
            return AsymmetricKey::Size () + X25519::KEY_LENGTH;
        }

        void X25519AsymmetricKey::Read (
                const Header &header,
                util::Serializer &serializer) {
            AsymmetricKey::Read (header, serializer);
            if (key.AdvanceWriteOffset (
                    serializer.Read (key.GetWritePtr (), X25519::KEY_LENGTH)) != X25519::KEY_LENGTH) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Read (key, %u) != %u",
                    X25519::KEY_LENGTH,
                    X25519::KEY_LENGTH);
            }
        }

        void X25519AsymmetricKey::Write (util::Serializer &serializer) const {
            AsymmetricKey::Write (serializer);
            if (serializer.Write (key.GetReadPtr (), X25519::KEY_LENGTH) != X25519::KEY_LENGTH) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Write (key, %u) != %u",
                    X25519::KEY_LENGTH,
                    X25519::KEY_LENGTH);
            }
        }

    #if defined (THEKOGANS_CRYPTO_TESTING)
        const char * const X25519AsymmetricKey::ATTR_KEY = "Key";

        std::string X25519AsymmetricKey::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            util::Attributes attributes;
            attributes.push_back (util::Attribute (ATTR_TYPE, Type ()));
            attributes.push_back (util::Attribute (ATTR_ID, id.ToString ()));
            attributes.push_back (util::Attribute (ATTR_NAME, name));
            attributes.push_back (util::Attribute (ATTR_DESCRIPTION, description));
            attributes.push_back (util::Attribute (ATTR_PRIVATE, util::boolTostring (IsPrivate ())));
            attributes.push_back (util::Attribute (ATTR_KEY_TYPE, GetKeyType ()));
            attributes.push_back (util::Attribute (ATTR_KEY, util::HexEncodeBuffer (GetKey (), GetKeyLength ())));
            return util::OpenTag (indentationLevel, tagName, attributes, true, true);
        }
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

    } // namespace crypto
} // namespace thekogans