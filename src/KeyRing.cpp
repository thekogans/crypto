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

#if defined (THEKOGANS_CRYPTO_TESTING)
    #include <sstream>
#endif // defined (THEKOGANS_CRYPTO_TESTING)
#include "thekogans/util/Types.h"
#include "thekogans/util/File.h"
#include "thekogans/util/ByteSwap.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/Exception.h"
#if defined (THEKOGANS_CRYPTO_TESTING)
    #include "thekogans/util/XMLUtils.h"
#endif // defined (THEKOGANS_CRYPTO_TESTING)
#include "thekogans/crypto/KeyRing.h"

namespace thekogans {
    namespace crypto {

        #if !defined (THEKOGANS_CRYPTO_MIN_KEY_RINGS_IN_PAGE)
            #define THEKOGANS_CRYPTO_MIN_KEY_RINGS_IN_PAGE 16
        #endif // !defined (THEKOGANS_CRYPTO_MIN_KEY_RINGS_IN_PAGE)

        THEKOGANS_UTIL_IMPLEMENT_HEAP_WITH_LOCK_EX (
            KeyRing,
            util::SpinLock,
            THEKOGANS_CRYPTO_MIN_KEY_RINGS_IN_PAGE)

        KeyRing::KeyRing (util::Serializer &serializer) {
            serializer >> id >> name >> description;
            bool haveMasterKey;
            serializer >> haveMasterKey;
            masterKey = haveMasterKey ? Key::Get (serializer) : Key::Ptr ();
            util::ui32 activeKeyCount;
            serializer >> activeKeyCount;
            activeKeyMap.clear ();
            while (activeKeyCount-- > 0) {
                Key::Ptr key = Key::Get (serializer);
                std::pair<KeyMap::iterator, bool> result =
                    activeKeyMap.insert (KeyMap::value_type (key->GetId (), key));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert active key: %s", key->GetName ().c_str ());
                }
            }
            util::ui32 retiredKeyCount;
            serializer >> retiredKeyCount;
            retiredKeyMap.clear ();
            while (retiredKeyCount-- > 0) {
                Key::Ptr key = Key::Get (serializer);
                std::pair<KeyMap::iterator, bool> result =
                    retiredKeyMap.insert (KeyMap::value_type (key->GetId (), key));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert retired key: %s", key->GetName ().c_str ());
                }
            }
            util::ui32 subringCount;
            serializer >> subringCount;
            subrings.clear ();
            while (subringCount-- > 0) {
                Ptr subring (new KeyRing (serializer));
                std::pair<KeyRingMap::iterator, bool> result =
                    subrings.insert (KeyRingMap::value_type (subring->GetId (), subring));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert subring: %s", subring->GetName ().c_str ());
                }
            }
        }

        KeyRing::Ptr KeyRing::Load (
                const std::string &path,
                Cipher::Ptr cipher,
                const void *associatedData,
                std::size_t associatedDataLength) {
            util::ReadOnlyFile file (util::NetworkEndian, path);
            util::Buffer::UniquePtr buffer (
                new util::Buffer (util::NetworkEndian, (util::ui32)file.GetSize ()));
            buffer->AdvanceWriteOffset (
                file.Read (buffer->GetWritePtr (), buffer->GetDataAvailableForWriting ()));
            if (cipher.Get () != 0) {
                buffer = cipher->Decrypt (
                    buffer->GetReadPtr (),
                    buffer->GetDataAvailableForReading (),
                    associatedData,
                    associatedDataLength,
                    true);
            }
            return KeyRing::Ptr (new KeyRing (*buffer));
        }

        void KeyRing::Save (
                const std::string &path,
                Cipher::Ptr cipher,
                const void *associatedData,
                std::size_t associatedDataLength) {
            util::Buffer::UniquePtr buffer (
                new util::SecureBuffer (util::NetworkEndian, (util::ui32)Size ()));
            Serialize (*buffer);
            if (cipher.Get () != 0) {
                buffer = cipher->Encrypt (
                    buffer->GetReadPtr (),
                    buffer->GetDataAvailableForReading (),
                    associatedData,
                    associatedDataLength);
            }
            util::SimpleFile file (
                util::NetworkEndian,
                path,
                util::SimpleFile::ReadWrite |
                util::SimpleFile::Create |
                util::SimpleFile::Truncate);
            file.Write (
                buffer->GetReadPtr (),
                buffer->GetDataAvailableForReading ());
        }

        Key::Ptr KeyRing::GetKey (
                const ID &keyId,
                bool recursive) const {
            if (masterKey.Get () != 0 && masterKey->GetId () == keyId) {
                return masterKey;
            }
            KeyMap::const_iterator it = activeKeyMap.find (keyId);
            if (it != activeKeyMap.end ()) {
                return it->second;
            }
            it = retiredKeyMap.find (keyId);
            if (it != retiredKeyMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subrings.begin (),
                        end = subrings.end (); it != end; ++it) {
                    Key::Ptr key = it->second->GetKey (keyId, recursive);
                    if (key.Get () != 0) {
                        return key;
                    }
                }
            }
            return Key::Ptr ();
        }

        bool KeyRing::AddActiveKey (Key::Ptr key) {
            if (key.Get () != 0) {
                std::pair<KeyMap::iterator, bool> result = activeKeyMap.insert (
                    KeyMap::value_type (key->GetId (), key));
                return result.second;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool KeyRing::RetireActiveKey (
                const ID &keyId,
                bool recursive) {
            KeyMap::iterator it = activeKeyMap.find (keyId);
            if (it != activeKeyMap.end ()) {
                std::pair<KeyMap::iterator, bool> result = retiredKeyMap.insert (
                    KeyMap::value_type (keyId, it->second));
                if (result.second) {
                    activeKeyMap.erase (it);
                    return true;
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to add retired key; %s.",
                        keyId.ToString ().c_str ());
                }
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subrings.begin (),
                        end = subrings.end (); it != end; ++it) {
                    if (it->second->RetireActiveKey (keyId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        bool KeyRing::DropActiveKey (
                const ID &keyId,
                bool recursive) {
            KeyMap::iterator it = activeKeyMap.find (keyId);
            if (it != activeKeyMap.end ()) {
                activeKeyMap.erase (it);
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subrings.begin (),
                        end = subrings.end (); it != end; ++it) {
                    if (it->second->DropActiveKey (keyId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropActiveKeys (bool recursive) {
            activeKeyMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subrings.begin (),
                        end = subrings.end (); it != end; ++it) {
                    it->second->DropActiveKeys (recursive);
                }
            }
        }

        bool KeyRing::DropRetiredKey (
                const ID &keyId,
                bool recursive) {
            KeyMap::iterator it = retiredKeyMap.find (keyId);
            if (it != retiredKeyMap.end ()) {
                retiredKeyMap.erase (it);
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subrings.begin (),
                        end = subrings.end (); it != end; ++it) {
                    if (it->second->DropRetiredKey (keyId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropRetiredKeys (bool recursive) {
            retiredKeyMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subrings.begin (),
                        end = subrings.end (); it != end; ++it) {
                    it->second->DropRetiredKeys (recursive);
                }
            }
        }

        void KeyRing::DropAllKeys (bool recursive) {
            activeKeyMap.clear ();
            retiredKeyMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subrings.begin (),
                        end = subrings.end (); it != end; ++it) {
                    it->second->DropAllKeys (recursive);
                }
            }
        }

        KeyRing::Ptr KeyRing::GetSubring (
                const ID &subringId,
                bool recursive) const {
            KeyRingMap::const_iterator it = subrings.find (subringId);
            if (it != subrings.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subrings.begin (),
                        end = subrings.end (); it != end; ++it) {
                    Ptr subring = it->second->GetSubring (subringId, recursive);
                    if (subring.Get () != 0) {
                        return subring;
                    }
                }
            }
            return Ptr ();
        }

        bool KeyRing::AddSubring (Ptr subring) {
            if (subring.Get () != 0) {
                std::pair<KeyRingMap::iterator, bool> result = subrings.insert (
                    KeyRingMap::value_type (subring->GetId (), subring));
                return result.second;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool KeyRing::DropSubring (
                const ID &subringId,
                bool recursive) {
            KeyRingMap::iterator it = subrings.find (subringId);
            if (it != subrings.end ()) {
                subrings.erase (it);
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subrings.begin (),
                        end = subrings.end (); it != end; ++it) {
                    if (it->second->DropSubring (subringId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropAllSubrings () {
            subrings.clear ();
        }

        void KeyRing::Clear () {
            activeKeyMap.clear ();
            retiredKeyMap.clear ();
            subrings.clear ();
        }

        std::size_t KeyRing::Size () const {
            std::size_t size =
                id.Size () +
                util::Serializer::Size (name) +
                util::Serializer::Size (description);
            bool haveMasterKey = masterKey.Get () != 0;
            size +=
                util::Serializer::Size (haveMasterKey) +
                (haveMasterKey ? masterKey->Size () : 0) +
                util::UI32_SIZE;
            for (KeyMap::const_iterator
                    it = activeKeyMap.begin (),
                    end = activeKeyMap.end (); it != end; ++it) {
                size += it->second->Size ();
            }
            size += util::UI32_SIZE;
            for (KeyMap::const_iterator
                    it = retiredKeyMap.begin (),
                    end = retiredKeyMap.end (); it != end; ++it) {
                size += it->second->Size ();
            }
            size += util::UI32_SIZE;
            for (KeyRingMap::const_iterator
                    it = subrings.begin (),
                    end = subrings.end (); it != end; ++it) {
                size += it->second->Size ();
            }
            return size;
        }

        void KeyRing::Serialize (util::Serializer &serializer) const {
            serializer << id << name << description;
            bool haveMasterKey = masterKey.Get () != 0;
            serializer << haveMasterKey;
            if (haveMasterKey) {
                masterKey->Serialize (serializer);
            }
            serializer << (util::ui32)activeKeyMap.size ();
            for (KeyMap::const_iterator
                    it = activeKeyMap.begin (),
                    end = activeKeyMap.end (); it != end; ++it) {
                it->second->Serialize (serializer);
            }
            serializer << (util::ui32)retiredKeyMap.size ();
            for (KeyMap::const_iterator
                    it = retiredKeyMap.begin (),
                    end = retiredKeyMap.end (); it != end; ++it) {
                it->second->Serialize (serializer);
            }
            serializer << (util::ui32)subrings.size ();
            for (KeyRingMap::const_iterator
                    it = subrings.begin (),
                    end = subrings.end (); it != end; ++it) {
                it->second->Serialize (serializer);
            }
        }

    #if defined (THEKOGANS_CRYPTO_TESTING)
        void KeyRing::Dump () const {
            std::cout << ToString ();
        }

        const char * const KeyRing::TAG_KEY_RING = "KeyRing";
        const char * const KeyRing::ATTR_ID = "Id";
        const char * const KeyRing::ATTR_NAME = "Name";
        const char * const KeyRing::ATTR_DESCRIPTION = "Description";
        const char * const KeyRing::TAG_MASTER_KEY = "MasterKey";
        const char * const KeyRing::TAG_ACTIVE_KEYS = "ActiveKeys";
        const char * const KeyRing::TAG_ACTIVE_KEY = "ActiveKey";
        const char * const KeyRing::TAG_RETIRED_KEYS = "RetiredKeys";
        const char * const KeyRing::TAG_RETIRED_KEY = "RetiredKey";
        const char * const KeyRing::TAG_SUB_RINGS = "SubRings";
        const char * const KeyRing::TAG_SUB_RING = "SubRing";

        std::string KeyRing::ToString (
                util::ui32 indentationLevel,
                const char *tagName) const {
            std::stringstream stream;
            util::Attributes attributes;
            attributes.push_back (util::Attribute (ATTR_ID, id.ToString ()));
            attributes.push_back (util::Attribute (ATTR_NAME, name));
            attributes.push_back (util::Attribute (ATTR_DESCRIPTION, description));
            stream <<
                util::OpenTag (indentationLevel, tagName, attributes, false, true) <<
                (masterKey.Get () != 0 ? masterKey->ToString (indentationLevel + 1, TAG_MASTER_KEY) : std::string ()) <<
                util::OpenTag (indentationLevel + 1, TAG_ACTIVE_KEYS, util::Attributes (), false, true);
            for (KeyMap::const_iterator
                    it = activeKeyMap.begin (),
                    end = activeKeyMap.end (); it != end; ++it) {
                stream << it->second->ToString (indentationLevel + 2, TAG_ACTIVE_KEY);
            }
            stream <<
                util::CloseTag (indentationLevel + 1, TAG_ACTIVE_KEYS) <<
                util::OpenTag (indentationLevel + 1, TAG_RETIRED_KEYS, util::Attributes (), false, true);
            for (KeyMap::const_iterator
                    it = retiredKeyMap.begin (),
                    end = retiredKeyMap.end (); it != end; ++it) {
                stream << it->second->ToString (indentationLevel + 2, TAG_RETIRED_KEY);
            }
            stream <<
                util::CloseTag (indentationLevel + 1, TAG_RETIRED_KEYS) <<
                util::OpenTag (indentationLevel + 1, TAG_SUB_RINGS, util::Attributes (), false, true);
            for (KeyRingMap::const_iterator
                    it = subrings.begin (),
                    end = subrings.end (); it != end; ++it) {
                stream << it->second->ToString (indentationLevel + 2, TAG_SUB_RING);
            }
            stream <<
                util::CloseTag (indentationLevel + 1, TAG_SUB_RINGS) <<
                util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

    } // namespace crypto
} // namespace thekogans
