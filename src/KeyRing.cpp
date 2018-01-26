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

        THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
            KeyRing,
            THEKOGANS_CRYPTO_MIN_KEY_RINGS_IN_PAGE)

        KeyRing::KeyRing (
            const CipherSuite &cipherSuite_,
            const std::string &name,
            const std::string &description) :
            Serializable (name, description),
            cipherSuite (cipherSuite_),
            cipherMasterKey (
                SymmetricKey::FromRandom (
                    Cipher::GetKeyLength (
                        CipherSuite::GetOpenSSLCipher (cipherSuite.cipher)))) {}

        KeyRing::KeyRing (util::Serializer &serializer) :
                Serializable (serializer) {
            serializer >> cipherSuite;
            util::ui32 keyExchangeParamsCount;
            serializer >> keyExchangeParamsCount;
            keyExchangeParamsMap.clear ();
            while (keyExchangeParamsCount-- > 0) {
                Params::Ptr params (new Params (serializer));
                std::pair<ParamsMap::iterator, bool> result =
                    keyExchangeParamsMap.insert (
                        ParamsMap::value_type (params->GetId (), params));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert KeyExchange params: %s",
                        params->GetName ().c_str ());
                }
            }
            util::ui32 keyExchangeKeyCount;
            serializer >> keyExchangeKeyCount;
            keyExchangeKeyMap.clear ();
            while (keyExchangeKeyCount-- > 0) {
                AsymmetricKey::Ptr key (new AsymmetricKey (serializer));
                std::pair<AsymmetricKeyMap::iterator, bool> result =
                    keyExchangeKeyMap.insert (
                        AsymmetricKeyMap::value_type (key->GetId (), key));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert KeyExchange key: %s",
                        key->GetName ().c_str ());
                }
            }
            util::ui32 authenticatorParamsCount;
            serializer >> authenticatorParamsCount;
            authenticatorParamsMap.clear ();
            while (authenticatorParamsCount-- > 0) {
                Params::Ptr params (new Params (serializer));
                std::pair<ParamsMap::iterator, bool> result =
                    authenticatorParamsMap.insert (
                        ParamsMap::value_type (params->GetId (), params));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert Authenticator params: %s",
                        params->GetName ().c_str ());
                }
            }
            util::ui32 authenticatorKeyCount;
            serializer >> authenticatorKeyCount;
            authenticatorKeyMap.clear ();
            while (authenticatorKeyCount-- > 0) {
                AsymmetricKey::Ptr key (new AsymmetricKey (serializer));
                std::pair<AsymmetricKeyMap::iterator, bool> result =
                    authenticatorKeyMap.insert (
                        AsymmetricKeyMap::value_type (key->GetId (), key));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert Authenticator key: %s",
                        key->GetName ().c_str ());
                }
            }
            cipherMasterKey.Reset (new SymmetricKey (serializer));
            util::ui32 cipherActiveKeyCount;
            serializer >> cipherActiveKeyCount;
            cipherActiveKeyMap.clear ();
            while (cipherActiveKeyCount-- > 0) {
                SymmetricKey::Ptr key (new SymmetricKey (serializer));
                std::pair<SymmetricKeyMap::iterator, bool> result =
                    cipherActiveKeyMap.insert (
                        SymmetricKeyMap::value_type (key->GetId (), key));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert Cipher active key: %s",
                        key->GetName ().c_str ());
                }
            }
            util::ui32 cipherRetiredKeyCount;
            serializer >> cipherRetiredKeyCount;
            cipherRetiredKeyMap.clear ();
            while (cipherRetiredKeyCount-- > 0) {
                SymmetricKey::Ptr key (new SymmetricKey (serializer));
                std::pair<SymmetricKeyMap::iterator, bool> result =
                    cipherRetiredKeyMap.insert (
                        SymmetricKeyMap::value_type (key->GetId (), key));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert Cipher retired key: %s",
                        key->GetName ().c_str ());
                }
            }
            util::ui32 macKeyCount;
            serializer >> macKeyCount;
            macKeyMap.clear ();
            while (macKeyCount-- > 0) {
                AsymmetricKey::Ptr key (new AsymmetricKey (serializer));
                std::pair<AsymmetricKeyMap::iterator, bool> result =
                    macKeyMap.insert (
                        AsymmetricKeyMap::value_type (key->GetId (), key));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert MAC key: %s",
                        key->GetName ().c_str ());
                }
            }
            util::ui32 subringCount;
            serializer >> subringCount;
            subringsMap.clear ();
            while (subringCount-- > 0) {
                Ptr subring (new KeyRing (serializer));
                std::pair<KeyRingMap::iterator, bool> result =
                    subringsMap.insert (KeyRingMap::value_type (subring->GetId (), subring));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert subring: %s", subring->GetName ().c_str ());
                }
            }
        }

        KeyRing::Ptr KeyRing::Load (
                const std::string &path,
                Cipher *cipher,
                const void *associatedData,
                std::size_t associatedDataLength) {
            util::ReadOnlyFile file (util::NetworkEndian, path);
            util::Buffer::UniquePtr buffer (
                new util::Buffer (util::NetworkEndian, (util::ui32)file.GetSize ()));
            buffer->AdvanceWriteOffset (
                file.Read (buffer->GetWritePtr (), buffer->GetDataAvailableForWriting ()));
            if (cipher != 0) {
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
                Cipher *cipher,
                const void *associatedData,
                std::size_t associatedDataLength) {
            util::Buffer::UniquePtr buffer (
                new util::SecureBuffer (util::NetworkEndian, (util::ui32)Size (false)));
            Serialize (*buffer, false);
            if (cipher != 0) {
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

        Params::Ptr KeyRing::GetKeyExchangeParams (
                const ID &paramsId,
                bool recursive) const {
            ParamsMap::const_iterator it = keyExchangeParamsMap.find (paramsId);
            if (it != keyExchangeParamsMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    Params::Ptr params = it->second->GetKeyExchangeParams (paramsId, recursive);
                    if (params.Get () != 0) {
                        return params;
                    }
                }
            }
            return Params::Ptr ();
        }

        bool KeyRing::AddKeyExchangeParams (Params::Ptr params) {
            if (params.Get () != 0) {
                std::pair<ParamsMap::iterator, bool> result = keyExchangeParamsMap.insert (
                    ParamsMap::value_type (params->GetId (), params));
                return result.second;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool KeyRing::DropKeyExchangeParams (
                const ID &paramsId,
                bool recursive) {
            ParamsMap::iterator it = keyExchangeParamsMap.find (paramsId);
            if (it != keyExchangeParamsMap.end ()) {
                keyExchangeParamsMap.erase (it);
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    if (it->second->DropKeyExchangeParams (paramsId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropAllKeyExchangeParams (bool recursive) {
            keyExchangeParamsMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    it->second->DropAllKeyExchangeParams (recursive);
                }
            }
        }

        AsymmetricKey::Ptr KeyRing::GetKeyExchangeKey (
                const ID &keyId,
                bool recursive) const {
            AsymmetricKeyMap::const_iterator it = keyExchangeKeyMap.find (keyId);
            if (it != keyExchangeKeyMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    AsymmetricKey::Ptr key = it->second->GetKeyExchangeKey (keyId, recursive);
                    if (key.Get () != 0) {
                        return key;
                    }
                }
            }
            return AsymmetricKey::Ptr ();
        }

        bool KeyRing::AddKeyExchangeKey (AsymmetricKey::Ptr key) {
            if (key.Get () != 0) {
                std::pair<AsymmetricKeyMap::iterator, bool> result = keyExchangeKeyMap.insert (
                    AsymmetricKeyMap::value_type (key->GetId (), key));
                return result.second;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool KeyRing::DropKeyExchangeKey (
                const ID &keyId,
                bool recursive) {
            AsymmetricKeyMap::iterator it = keyExchangeKeyMap.find (keyId);
            if (it != keyExchangeKeyMap.end ()) {
                keyExchangeKeyMap.erase (it);
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    if (it->second->DropKeyExchangeKey (keyId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropAllKeyExchangeKeys (bool recursive) {
            keyExchangeKeyMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    it->second->DropAllKeyExchangeKeys (recursive);
                }
            }
        }

        Params::Ptr KeyRing::GetAuthenticatorParams (
                const ID &paramsId,
                bool recursive) const {
            ParamsMap::const_iterator it = authenticatorParamsMap.find (paramsId);
            if (it != authenticatorParamsMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    Params::Ptr params = it->second->GetAuthenticatorParams (paramsId, recursive);
                    if (params.Get () != 0) {
                        return params;
                    }
                }
            }
            return Params::Ptr ();
        }

        bool KeyRing::AddAuthenticatorParams (Params::Ptr params) {
            if (params.Get () != 0) {
                std::pair<ParamsMap::iterator, bool> result = authenticatorParamsMap.insert (
                    ParamsMap::value_type (params->GetId (), params));
                return result.second;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool KeyRing::DropAuthenticatorParams (
                const ID &paramsId,
                bool recursive) {
            ParamsMap::iterator it = authenticatorParamsMap.find (paramsId);
            if (it != authenticatorParamsMap.end ()) {
                authenticatorParamsMap.erase (it);
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    if (it->second->DropAuthenticatorParams (paramsId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropAllAuthenticatorParams (bool recursive) {
            authenticatorParamsMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    it->second->DropAllAuthenticatorParams (recursive);
                }
            }
        }

        AsymmetricKey::Ptr KeyRing::GetAuthenticatorKey (
                const ID &keyId,
                bool recursive) const {
            AsymmetricKeyMap::const_iterator it = authenticatorKeyMap.find (keyId);
            if (it != authenticatorKeyMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    AsymmetricKey::Ptr key = it->second->GetAuthenticatorKey (keyId, recursive);
                    if (key.Get () != 0) {
                        return key;
                    }
                }
            }
            return AsymmetricKey::Ptr ();
        }

        bool KeyRing::AddAuthenticatorKey (AsymmetricKey::Ptr key) {
            if (key.Get () != 0) {
                std::pair<AsymmetricKeyMap::iterator, bool> result = authenticatorKeyMap.insert (
                    AsymmetricKeyMap::value_type (key->GetId (), key));
                return result.second;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool KeyRing::DropAuthenticatorKey (
                const ID &keyId,
                bool recursive) {
            AsymmetricKeyMap::iterator it = authenticatorKeyMap.find (keyId);
            if (it != authenticatorKeyMap.end ()) {
                authenticatorKeyMap.erase (it);
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    if (it->second->DropAuthenticatorKey (keyId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropAllAuthenticatorKeys (bool recursive) {
            authenticatorKeyMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    it->second->DropAllAuthenticatorKeys (recursive);
                }
            }
        }

        void KeyRing::SetCipherMasterKey (SymmetricKey::Ptr cipherMasterKey_) {
            if (cipherMasterKey_.Get () != 0) {
                cipherMasterKey = cipherMasterKey_;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        SymmetricKey::Ptr KeyRing::GetCipherKey (
                const ID &keyId,
                bool recursive) const {
            if (cipherMasterKey.Get () != 0 && cipherMasterKey->GetId () == keyId) {
                return cipherMasterKey;
            }
            SymmetricKeyMap::const_iterator it = cipherActiveKeyMap.find (keyId);
            if (it != cipherActiveKeyMap.end ()) {
                return it->second;
            }
            it = cipherRetiredKeyMap.find (keyId);
            if (it != cipherRetiredKeyMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    SymmetricKey::Ptr key = it->second->GetCipherKey (keyId, recursive);
                    if (key.Get () != 0) {
                        return key;
                    }
                }
            }
            return SymmetricKey::Ptr ();
        }

        bool KeyRing::AddCipherActiveKey (SymmetricKey::Ptr key) {
            if (key.Get () != 0) {
                std::pair<SymmetricKeyMap::iterator, bool> result = cipherActiveKeyMap.insert (
                    SymmetricKeyMap::value_type (key->GetId (), key));
                return result.second;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool KeyRing::RetireCipherActiveKey (
                const ID &keyId,
                bool recursive) {
            SymmetricKeyMap::iterator it = cipherActiveKeyMap.find (keyId);
            if (it != cipherActiveKeyMap.end ()) {
                std::pair<SymmetricKeyMap::iterator, bool> result = cipherRetiredKeyMap.insert (
                    SymmetricKeyMap::value_type (keyId, it->second));
                if (result.second) {
                    cipherActiveKeyMap.erase (it);
                    return true;
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to add Cipher retired key; %s.",
                        keyId.ToString ().c_str ());
                }
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    if (it->second->RetireCipherActiveKey (keyId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        bool KeyRing::DropCipherActiveKey (
                const ID &keyId,
                bool recursive) {
            SymmetricKeyMap::iterator it = cipherActiveKeyMap.find (keyId);
            if (it != cipherActiveKeyMap.end ()) {
                cipherActiveKeyMap.erase (it);
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    if (it->second->DropCipherActiveKey (keyId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropCipherActiveKeys (bool recursive) {
            cipherActiveKeyMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    it->second->DropCipherActiveKeys (recursive);
                }
            }
        }

        bool KeyRing::DropCipherRetiredKey (
                const ID &keyId,
                bool recursive) {
            SymmetricKeyMap::iterator it = cipherRetiredKeyMap.find (keyId);
            if (it != cipherRetiredKeyMap.end ()) {
                cipherRetiredKeyMap.erase (it);
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    if (it->second->DropCipherRetiredKey (keyId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropCipherRetiredKeys (bool recursive) {
            cipherRetiredKeyMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    it->second->DropCipherRetiredKeys (recursive);
                }
            }
        }

        void KeyRing::DropAllCipherKeys (bool recursive) {
            cipherActiveKeyMap.clear ();
            cipherRetiredKeyMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    it->second->DropAllCipherKeys (recursive);
                }
            }
        }

        AsymmetricKey::Ptr KeyRing::GetMACKey (
                const ID &keyId,
                bool recursive) const {
            AsymmetricKeyMap::const_iterator it = macKeyMap.find (keyId);
            if (it != macKeyMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    AsymmetricKey::Ptr key = it->second->GetMACKey (keyId, recursive);
                    if (key.Get () != 0) {
                        return key;
                    }
                }
            }
            return AsymmetricKey::Ptr ();
        }

        bool KeyRing::AddMACKey (AsymmetricKey::Ptr key) {
            if (key.Get () != 0) {
                std::pair<AsymmetricKeyMap::iterator, bool> result = macKeyMap.insert (
                    AsymmetricKeyMap::value_type (key->GetId (), key));
                return result.second;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool KeyRing::DropMACKey (
                const ID &keyId,
                bool recursive) {
            AsymmetricKeyMap::iterator it = macKeyMap.find (keyId);
            if (it != macKeyMap.end ()) {
                macKeyMap.erase (it);
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    if (it->second->DropMACKey (keyId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropAllMACKeys (bool recursive) {
            macKeyMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    it->second->DropAllMACKeys (recursive);
                }
            }
        }

        KeyRing::Ptr KeyRing::GetSubring (
                const ID &subringId,
                bool recursive) const {
            KeyRingMap::const_iterator it = subringsMap.find (subringId);
            if (it != subringsMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    Ptr subring = it->second->GetSubring (subringId, recursive);
                    if (subring.Get () != 0) {
                        return subring;
                    }
                }
            }
            return Ptr ();
        }

        bool KeyRing::AddSubring (Ptr subring) {
            std::pair<KeyRingMap::iterator, bool> result = subringsMap.insert (
                KeyRingMap::value_type (subring->GetId (), subring));
            return result.second;
        }

        bool KeyRing::DropSubring (
                const ID &subringId,
                bool recursive) {
            KeyRingMap::iterator it = subringsMap.find (subringId);
            if (it != subringsMap.end ()) {
                subringsMap.erase (it);
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    if (it->second->DropSubring (subringId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropAllSubrings () {
            subringsMap.clear ();
        }

        void KeyRing::Clear () {
            keyExchangeParamsMap.clear ();
            keyExchangeParamsMap.clear ();
            authenticatorKeyMap.clear ();
            authenticatorKeyMap.clear ();
            cipherActiveKeyMap.clear ();
            cipherRetiredKeyMap.clear ();
            macKeyMap.clear ();
            subringsMap.clear ();
        }

        std::size_t KeyRing::Size (bool includeType) const {
            std::size_t size =
                Serializable::Size (includeType) +
                cipherSuite.Size ();
            size += util::UI32_SIZE;
            for (ParamsMap::const_iterator
                    it = keyExchangeParamsMap.begin (),
                    end = keyExchangeParamsMap.end (); it != end; ++it) {
                size += it->second->Size (false);
            }
            size += util::UI32_SIZE;
            for (AsymmetricKeyMap::const_iterator
                    it = keyExchangeKeyMap.begin (),
                    end = keyExchangeKeyMap.end (); it != end; ++it) {
                size += it->second->Size (false);
            }
            size += util::UI32_SIZE;
            for (ParamsMap::const_iterator
                    it = authenticatorParamsMap.begin (),
                    end = authenticatorParamsMap.end (); it != end; ++it) {
                size += it->second->Size (false);
            }
            size += util::UI32_SIZE;
            for (AsymmetricKeyMap::const_iterator
                    it = authenticatorKeyMap.begin (),
                    end = authenticatorKeyMap.end (); it != end; ++it) {
                size += it->second->Size (false);
            }
            size += cipherMasterKey->Size (false);
            size += util::UI32_SIZE;
            for (SymmetricKeyMap::const_iterator
                    it = cipherActiveKeyMap.begin (),
                    end = cipherActiveKeyMap.end (); it != end; ++it) {
                size += it->second->Size (false);
            }
            size += util::UI32_SIZE;
            for (SymmetricKeyMap::const_iterator
                    it = cipherRetiredKeyMap.begin (),
                    end = cipherRetiredKeyMap.end (); it != end; ++it) {
                size += it->second->Size (false);
            }
            size += util::UI32_SIZE;
            for (AsymmetricKeyMap::const_iterator
                    it = macKeyMap.begin (),
                    end = macKeyMap.end (); it != end; ++it) {
                size += it->second->Size (false);
            }
            size += util::UI32_SIZE;
            for (KeyRingMap::const_iterator
                    it = subringsMap.begin (),
                    end = subringsMap.end (); it != end; ++it) {
                size += it->second->Size (false);
            }
            return size;
        }

        void KeyRing::Serialize (
                util::Serializer &serializer,
                bool includeType) const {
            Serializable::Serialize (serializer, includeType);
            serializer << cipherSuite;
            serializer << (util::ui32)keyExchangeParamsMap.size ();
            for (ParamsMap::const_iterator
                    it = keyExchangeParamsMap.begin (),
                    end = keyExchangeParamsMap.end (); it != end; ++it) {
                it->second->Serialize (serializer, false);
            }
            serializer << (util::ui32)keyExchangeKeyMap.size ();
            for (AsymmetricKeyMap::const_iterator
                    it = keyExchangeKeyMap.begin (),
                    end = keyExchangeKeyMap.end (); it != end; ++it) {
                it->second->Serialize (serializer, false);
            }
            serializer << (util::ui32)authenticatorParamsMap.size ();
            for (ParamsMap::const_iterator
                    it = authenticatorParamsMap.begin (),
                    end = authenticatorParamsMap.end (); it != end; ++it) {
                it->second->Serialize (serializer, false);
            }
            serializer << (util::ui32)authenticatorKeyMap.size ();
            for (AsymmetricKeyMap::const_iterator
                    it = authenticatorKeyMap.begin (),
                    end = authenticatorKeyMap.end (); it != end; ++it) {
                it->second->Serialize (serializer, false);
            }
            cipherMasterKey->Serialize (serializer, false);
            serializer << (util::ui32)cipherActiveKeyMap.size ();
            for (SymmetricKeyMap::const_iterator
                    it = cipherActiveKeyMap.begin (),
                    end = cipherActiveKeyMap.end (); it != end; ++it) {
                it->second->Serialize (serializer, false);
            }
            serializer << (util::ui32)cipherRetiredKeyMap.size ();
            for (SymmetricKeyMap::const_iterator
                    it = cipherRetiredKeyMap.begin (),
                    end = cipherRetiredKeyMap.end (); it != end; ++it) {
                it->second->Serialize (serializer, false);
            }
            serializer << (util::ui32)macKeyMap.size ();
            for (AsymmetricKeyMap::const_iterator
                    it = macKeyMap.begin (),
                    end = macKeyMap.end (); it != end; ++it) {
                it->second->Serialize (serializer, false);
            }
            serializer << (util::ui32)subringsMap.size ();
            for (KeyRingMap::const_iterator
                    it = subringsMap.begin (),
                    end = subringsMap.end (); it != end; ++it) {
                it->second->Serialize (serializer, false);
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
        const char * const KeyRing::ATTR_CIPHER_SUITE = "CipherSuite";
        const char * const KeyRing::TAG_KEY_EXCHANGE_PARAMS = "KeyExchangeParams";
        const char * const KeyRing::TAG_KEY_EXCHANGE_PARAM = "KeyExchangeParam";
        const char * const KeyRing::TAG_KEY_EXCHANGE_KEYS = "KeyExchangeKeys";
        const char * const KeyRing::TAG_KEY_EXCHANGE_KEY = "KeyExchangeKey";
        const char * const KeyRing::TAG_AUTHENTICATOR_PARAMS = "AuthenticatorParams";
        const char * const KeyRing::TAG_AUTHENTICATOR_PARAM = "AuthenticatorParam";
        const char * const KeyRing::TAG_AUTHENTICATOR_KEYS = "AuthenticatorKeys";
        const char * const KeyRing::TAG_AUTHENTICATOR_KEY = "AuthenticatorKey";
        const char * const KeyRing::TAG_CIPHER_MASTER_KEY = "CipherMasterKey";
        const char * const KeyRing::TAG_CIPHER_ACTIVE_KEYS = "CipherActiveKeys";
        const char * const KeyRing::TAG_CIPHER_ACTIVE_KEY = "CipherActiveKey";
        const char * const KeyRing::TAG_CIPHER_RETIRED_KEYS = "CipherRetiredKeys";
        const char * const KeyRing::TAG_CIPHER_RETIRED_KEY = "CipherRetiredKey";
        const char * const KeyRing::TAG_MAC_KEYS = "MACKeys";
        const char * const KeyRing::TAG_MAC_KEY = "MACKey";
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
            attributes.push_back (util::Attribute (ATTR_CIPHER_SUITE, cipherSuite.ToString ()));
            stream << util::OpenTag (indentationLevel, tagName, attributes, false, true);
            {
                stream << util::OpenTag (indentationLevel + 1, TAG_KEY_EXCHANGE_PARAMS, util::Attributes (), false, true);
                for (ParamsMap::const_iterator
                        it = keyExchangeParamsMap.begin (),
                        end = keyExchangeParamsMap.end (); it != end; ++it) {
                    stream << it->second->ToString (indentationLevel + 2, TAG_KEY_EXCHANGE_PARAM);
                }
                stream << util::CloseTag (indentationLevel + 1, TAG_KEY_EXCHANGE_PARAMS);
            }
            {
                stream << util::OpenTag (indentationLevel + 1, TAG_KEY_EXCHANGE_KEYS, util::Attributes (), false, true);
                for (AsymmetricKeyMap::const_iterator
                        it = keyExchangeKeyMap.begin (),
                        end = keyExchangeKeyMap.end (); it != end; ++it) {
                    stream << it->second->ToString (indentationLevel + 2, TAG_KEY_EXCHANGE_KEY);
                }
                stream << util::CloseTag (indentationLevel + 1, TAG_KEY_EXCHANGE_KEYS);
            }
            {
                stream << util::OpenTag (indentationLevel + 1, TAG_AUTHENTICATOR_PARAMS, util::Attributes (), false, true);
                for (ParamsMap::const_iterator
                        it = authenticatorParamsMap.begin (),
                        end = authenticatorParamsMap.end (); it != end; ++it) {
                    stream << it->second->ToString (indentationLevel + 2, TAG_AUTHENTICATOR_PARAM);
                }
                stream << util::CloseTag (indentationLevel + 1, TAG_AUTHENTICATOR_PARAMS);
            }
            {
                stream << util::OpenTag (indentationLevel + 1, TAG_AUTHENTICATOR_KEYS, util::Attributes (), false, true);
                for (AsymmetricKeyMap::const_iterator
                        it = authenticatorKeyMap.begin (),
                        end = authenticatorKeyMap.end (); it != end; ++it) {
                    stream << it->second->ToString (indentationLevel + 2, TAG_AUTHENTICATOR_KEY);
                }
                stream << util::CloseTag (indentationLevel + 1, TAG_AUTHENTICATOR_KEYS);
            }
            stream << cipherMasterKey->ToString (indentationLevel + 1, TAG_CIPHER_MASTER_KEY);
            {
                stream << util::OpenTag (indentationLevel + 1, TAG_CIPHER_ACTIVE_KEYS, util::Attributes (), false, true);
                for (SymmetricKeyMap::const_iterator
                        it = cipherActiveKeyMap.begin (),
                        end = cipherActiveKeyMap.end (); it != end; ++it) {
                    stream << it->second->ToString (indentationLevel + 2, TAG_CIPHER_ACTIVE_KEY);
                }
                stream << util::CloseTag (indentationLevel + 1, TAG_CIPHER_ACTIVE_KEYS);
            }
            {
                stream << util::OpenTag (indentationLevel + 1, TAG_CIPHER_RETIRED_KEYS, util::Attributes (), false, true);
                for (SymmetricKeyMap::const_iterator
                         it = cipherRetiredKeyMap.begin (),
                         end = cipherRetiredKeyMap.end (); it != end; ++it) {
                    stream << it->second->ToString (indentationLevel + 2, TAG_CIPHER_RETIRED_KEY);
                }
                stream << util::CloseTag (indentationLevel + 1, TAG_CIPHER_RETIRED_KEYS);
            }
            {
                stream << util::OpenTag (indentationLevel + 1, TAG_MAC_KEYS, util::Attributes (), false, true);
                for (AsymmetricKeyMap::const_iterator
                        it = macKeyMap.begin (),
                        end = macKeyMap.end (); it != end; ++it) {
                    stream << it->second->ToString (indentationLevel + 2, TAG_MAC_KEY);
                }
                stream << util::CloseTag (indentationLevel + 1, TAG_AUTHENTICATOR_KEYS);
            }
            {
                stream << util::OpenTag (indentationLevel + 1, TAG_SUB_RINGS, util::Attributes (), false, true);
                for (KeyRingMap::const_iterator
                        it = subringsMap.begin (),
                        end = subringsMap.end (); it != end; ++it) {
                    stream << it->second->ToString (indentationLevel + 2, TAG_SUB_RING);
                }
                stream << util::CloseTag (indentationLevel + 1, TAG_SUB_RINGS);
            }
            stream << util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

    } // namespace crypto
} // namespace thekogans
