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
            if (key_ != nullptr) {
                key.Write (key_, X25519::KEY_LENGTH);
            }
        }

        const char * const X25519AsymmetricKey::KEY_TYPE = "X25519";

        AsymmetricKey::SharedPtr X25519AsymmetricKey::GetPublicKey (
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
            return AsymmetricKey::SharedPtr (
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
                const BinHeader &header,
                util::Serializer &serializer) {
            AsymmetricKey::Read (header, serializer);
            key.Rewind ();
            if (key.AdvanceWriteOffset (
                    serializer.Read (key.GetWritePtr (), X25519::KEY_LENGTH)) != X25519::KEY_LENGTH) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Read (key, " THEKOGANS_UTIL_SIZE_T_FORMAT ") != " THEKOGANS_UTIL_SIZE_T_FORMAT,
                    X25519::KEY_LENGTH,
                    X25519::KEY_LENGTH);
            }
        }

        void X25519AsymmetricKey::Write (util::Serializer &serializer) const {
            AsymmetricKey::Write (serializer);
            if (serializer.Write (key.GetReadPtr (), X25519::KEY_LENGTH) != X25519::KEY_LENGTH) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Write (key, " THEKOGANS_UTIL_SIZE_T_FORMAT ") != " THEKOGANS_UTIL_SIZE_T_FORMAT,
                    X25519::KEY_LENGTH,
                    X25519::KEY_LENGTH);
            }
        }

        const char * const X25519AsymmetricKey::ATTR_KEY = "Key";

        void X25519AsymmetricKey::Read (
                const TextHeader &header,
                const pugi::xml_node &node) {
            AsymmetricKey::Read (header, node);
            util::SecureString hexKey = node.attribute (ATTR_KEY).value ();
            if (hexKey.size () == X25519::PRIVATE_KEY_LENGTH * 2) {
                key.Rewind ();
                if (key.AdvanceWriteOffset (
                        util::HexDecodeBuffer (
                            hexKey.data (),
                            hexKey.size (),
                            key.GetWritePtr ())) != X25519::KEY_LENGTH) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Read (key, " THEKOGANS_UTIL_SIZE_T_FORMAT ") != " THEKOGANS_UTIL_SIZE_T_FORMAT,
                        X25519::KEY_LENGTH,
                        X25519::KEY_LENGTH);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Wrong key length. Expected " THEKOGANS_UTIL_SIZE_T_FORMAT
                    ", received " THEKOGANS_UTIL_SIZE_T_FORMAT ".",
                    X25519::KEY_LENGTH * 2,
                    hexKey.size ());
            }
        }

        void X25519AsymmetricKey::Write (pugi::xml_node &node) const {
            AsymmetricKey::Write (node);
            node.append_attribute (ATTR_KEY).set_value (
                util::HexEncodeBuffer (key.GetReadPtr (), X25519::KEY_LENGTH).c_str ());
        }

        void X25519AsymmetricKey::Read (
                const TextHeader &header,
                const util::JSON::Object &object) {
            AsymmetricKey::Read (header, object);
            util::SecureString hexKey = object.Get<util::JSON::String> (ATTR_KEY)->value.c_str ();
            if (hexKey.size () == X25519::PRIVATE_KEY_LENGTH * 2) {
                key.Rewind ();
                if (key.AdvanceWriteOffset (
                        util::HexDecodeBuffer (
                            hexKey.data (),
                            hexKey.size (),
                            key.GetWritePtr ())) != X25519::KEY_LENGTH) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Read (key, " THEKOGANS_UTIL_SIZE_T_FORMAT ") != " THEKOGANS_UTIL_SIZE_T_FORMAT,
                        X25519::KEY_LENGTH,
                        X25519::KEY_LENGTH);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Wrong key length. Expected " THEKOGANS_UTIL_SIZE_T_FORMAT
                    ", received " THEKOGANS_UTIL_SIZE_T_FORMAT ".",
                    X25519::KEY_LENGTH * 2,
                    hexKey.size ());
            }
        }

        void X25519AsymmetricKey::Write (util::JSON::Object &object) const {
            AsymmetricKey::Write (object);
            object.Add<const std::string &> (
                ATTR_KEY,
                util::HexEncodeBuffer (key.GetReadPtr (), X25519::KEY_LENGTH));
        }

    } // namespace crypto
} // namespace thekogans
