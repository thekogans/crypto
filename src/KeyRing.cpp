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

#include <iterator>
#include "thekogans/util/Types.h"
#include "thekogans/util/File.h"
#include "thekogans/util/ByteSwap.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/crypto/DHEKeyExchange.h"
#include "thekogans/crypto/RSA.h"
#include "thekogans/crypto/KeyRing.h"

namespace thekogans {
    namespace crypto {

        #if !defined (THEKOGANS_CRYPTO_MIN_KEY_RINGS_IN_PAGE)
            #define THEKOGANS_CRYPTO_MIN_KEY_RINGS_IN_PAGE 16
        #endif // !defined (THEKOGANS_CRYPTO_MIN_KEY_RINGS_IN_PAGE)

        THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
            thekogans::crypto::KeyRing,
            1,
            THEKOGANS_CRYPTO_MIN_KEY_RINGS_IN_PAGE)

        KeyRing::SharedPtr KeyRing::Load (
                const std::string &path,
                Cipher *cipher,
                const void *associatedData,
                std::size_t associatedDataLength) {
            util::ReadOnlyFile file (util::NetworkEndian, path);
            util::Buffer::SharedPtr buffer (
                new util::NetworkBuffer ((std::size_t)file.GetSize ()));
            buffer->AdvanceWriteOffset (
                file.Read (
                    buffer->GetWritePtr (),
                    buffer->GetDataAvailableForWriting ()));
            if (cipher != nullptr) {
                buffer = cipher->Decrypt (
                    buffer->GetReadPtr (),
                    buffer->GetDataAvailableForReading (),
                    associatedData,
                    associatedDataLength,
                    true);
            }
            SharedPtr keyRing;
            *buffer >> keyRing;
            return keyRing;
        }

        void KeyRing::Save (
                const std::string &path,
                Cipher *cipher,
                const void *associatedData,
                std::size_t associatedDataLength) {
            util::Buffer::SharedPtr buffer (new util::NetworkBuffer (GetSize ()));
            *buffer << *this;
            if (cipher != nullptr) {
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

        Params::SharedPtr KeyRing::GetKeyExchangeParams (
                const ID &paramsId,
                bool recursive) const {
            ParamsMap::const_iterator it = keyExchangeParamsMap.find (paramsId);
            if (it != keyExchangeParamsMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    Params::SharedPtr params =
                        it->second->GetKeyExchangeParams (paramsId, recursive);
                    if (params != nullptr) {
                        return params;
                    }
                }
            }
            return nullptr;
        }

        Params::SharedPtr KeyRing::GetKeyExchangeParams (
                const EqualityTest<Params> &equalityTest,
                bool recursive) const {
            for (ParamsMap::const_iterator
                    it = keyExchangeParamsMap.begin (),
                    end = keyExchangeParamsMap.end (); it != end; ++it) {
                if (equalityTest (*it->second)) {
                    return it->second;
                }
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    Params::SharedPtr params =
                        it->second->GetKeyExchangeParams (equalityTest, recursive);
                    if (params != nullptr) {
                        return params;
                    }
                }
            }
            return nullptr;
        }

        Params::SharedPtr KeyRing::GetRandomKeyExchangeParams () const {
            Params::SharedPtr params;
            if (!keyExchangeParamsMap.empty ()) {
                ParamsMap::const_iterator it = keyExchangeParamsMap.begin ();
                if (keyExchangeParamsMap.size () > 1) {
                    std::advance (
                        it,
                        util::RandomSource::Instance ()->Getui32 () %
                            keyExchangeParamsMap.size ());
                }
                params = it->second;
            }
            return params;
        }

        bool KeyRing::AddKeyExchangeParams (Params::SharedPtr params) {
            if (params != nullptr &&
                    cipherSuite.VerifyKeyExchangeParams (*params)) {
                std::pair<ParamsMap::iterator, bool> result =
                    keyExchangeParamsMap.insert (
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
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
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
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    it->second->DropAllKeyExchangeParams (recursive);
                }
            }
        }

        AsymmetricKey::SharedPtr KeyRing::GetKeyExchangeKey (
                const ID &keyId,
                bool recursive) const {
            AsymmetricKeyMap::const_iterator it = keyExchangeKeyMap.find (keyId);
            if (it != keyExchangeKeyMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    AsymmetricKey::SharedPtr key =
                        it->second->GetKeyExchangeKey (keyId, recursive);
                    if (key != nullptr) {
                        return key;
                    }
                }
            }
            return nullptr;
        }

        AsymmetricKey::SharedPtr KeyRing::GetKeyExchangeKey (
                const EqualityTest<AsymmetricKey> &equalityTest,
                bool recursive) const {
            for (AsymmetricKeyMap::const_iterator
                    it = keyExchangeKeyMap.begin (),
                    end = keyExchangeKeyMap.end (); it != end; ++it) {
                if (equalityTest (*it->second)) {
                    return it->second;
                }
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    AsymmetricKey::SharedPtr key =
                        it->second->GetKeyExchangeKey (equalityTest, recursive);
                    if (key != nullptr) {
                        return key;
                    }
                }
            }
            return nullptr;
        }

        bool KeyRing::AddKeyExchangeKey (AsymmetricKey::SharedPtr key) {
            if (key != nullptr && cipherSuite.VerifyKeyExchangeKey (*key)) {
                std::pair<AsymmetricKeyMap::iterator, bool> result =
                    keyExchangeKeyMap.insert (
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
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
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
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    it->second->DropAllKeyExchangeKeys (recursive);
                }
            }
        }

        KeyExchange::SharedPtr KeyRing::AddKeyExchange (
                const ID &paramsOrKeyId,
                std::size_t secretLength,
                const void *salt,
                std::size_t saltLength,
                std::size_t count,
                const ID &keyId,
                const std::string &name,
                const std::string &description,
                bool recursive) {
            KeyExchange::SharedPtr keyExchange;
            if (cipherSuite.keyExchange == CipherSuite::KEY_EXCHANGE_ECDHE ||
                    cipherSuite.keyExchange == CipherSuite::KEY_EXCHANGE_DHE) {
                Params::SharedPtr params = paramsOrKeyId != ID::Empty ?
                    GetKeyExchangeParams (paramsOrKeyId) :
                    GetRandomKeyExchangeParams ();
                if (params != nullptr) {
                    keyExchange.Reset (
                        new DHEKeyExchange (
                            ID (),
                            params,
                            salt,
                            saltLength,
                            GetCipherKeyLength (cipherSuite.GetOpenSSLCipher ()),
                            cipherSuite.GetOpenSSLMessageDigest (),
                            count,
                            keyId,
                            name,
                            description));
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to get params for id: %s",
                        paramsOrKeyId.ToHexString ().c_str ());
                }
            }
            else if (cipherSuite.keyExchange == CipherSuite::KEY_EXCHANGE_RSA) {
                AsymmetricKey::SharedPtr key = GetKeyExchangeKey (paramsOrKeyId);
                if (key != nullptr && !key->IsPrivate ()) {
                    keyExchange.Reset (
                        new RSAKeyExchange (
                            ID (),
                            key,
                            secretLength,
                            salt,
                            saltLength,
                            GetCipherKeyLength (cipherSuite.GetOpenSSLCipher ()),
                            cipherSuite.GetOpenSSLMessageDigest (),
                            count,
                            keyId,
                            name,
                            description));
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to get key for id: %s",
                        paramsOrKeyId.ToHexString ().c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unknown key exchange type: %s",
                    cipherSuite.keyExchange.c_str ());
            }
            if (keyExchange != nullptr) {
                std::pair<KeyExchangeMap::iterator, bool> result =
                    keyExchangeMap.insert (
                        KeyExchangeMap::value_type (keyExchange->GetId (), keyExchange));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to add a KeyExchange: %s.",
                        keyExchange->GetId ().ToHexString ().c_str ());
                }
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    keyExchange =
                        it->second->AddKeyExchange (
                            paramsOrKeyId,
                            secretLength,
                            salt,
                            saltLength,
                            count,
                            keyId,
                            name,
                            description,
                            recursive);
                    if (keyExchange != nullptr) {
                        break;
                    }
                }
            }
            return keyExchange;
        }

        KeyExchange::SharedPtr KeyRing::CreateKeyExchange (
                KeyExchange::Params::SharedPtr params,
                bool recursive) {
            if (params != nullptr) {
                // Validate the parameters signature (if one was provided).
                if (!params->signature.empty ()) {
                    AsymmetricKey::SharedPtr publicKey =
                        GetAuthenticatorKey (params->signatureKeyId, recursive);
                    if (publicKey != nullptr && !publicKey->IsPrivate ()) {
                        MessageDigest::SharedPtr messageDigest (
                            new MessageDigest (
                                CipherSuite::GetOpenSSLMessageDigestByName (
                                    params->signatureMessageDigestName)));
                        if (messageDigest != nullptr) {
                            if (!params->ValidateSignature (publicKey, messageDigest)) {
                                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                    "Params failed signature validation: %s",
                                    params->id.ToHexString ().c_str ());
                            }
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to get message digest for name: %s",
                                params->signatureMessageDigestName.c_str ());
                        }
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to get public key for id: %s",
                            params->signatureKeyId.ToHexString ().c_str ());
                    }
                }
                if (cipherSuite.keyExchange == CipherSuite::KEY_EXCHANGE_ECDHE ||
                        cipherSuite.keyExchange == CipherSuite::KEY_EXCHANGE_DHE) {
                    return KeyExchange::SharedPtr (new DHEKeyExchange (params));
                }
                else if (cipherSuite.keyExchange == CipherSuite::KEY_EXCHANGE_RSA) {
                    RSAKeyExchange::RSAParams::SharedPtr rsaParams =
                        util::dynamic_refcounted_sharedptr_cast<RSAKeyExchange::RSAParams> (params);
                    if (rsaParams != nullptr) {
                        AsymmetricKey::SharedPtr key =
                            GetKeyExchangeKey (rsaParams->keyId, recursive);
                        if (key != nullptr) {
                            return KeyExchange::SharedPtr (new RSAKeyExchange (key, params));
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to get key for id: %s",
                                rsaParams->keyId.ToHexString ().c_str ());
                        }
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Incorrect key exchange parameters type: %s, "
                            "expected RSAKeyExchange::RSAParams.",
                            params->Type ());
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unknown key exchange type: %s",
                        cipherSuite.keyExchange.c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        KeyExchange::SharedPtr KeyRing::GetKeyExchange (
                const ID &keyExchangeId,
                bool recursive) {
            KeyExchange::SharedPtr keyExchange;
            KeyExchangeMap::iterator it = keyExchangeMap.find (keyExchangeId);
            if (it != keyExchangeMap.end ()) {
                keyExchange = it->second;
            }
            if (keyExchange != nullptr) {
                keyExchangeMap.erase (it);
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    keyExchange =
                        it->second->GetKeyExchange (keyExchangeId, recursive);
                    if (keyExchange != nullptr) {
                        break;
                    }
                }
            }
            return keyExchange;
        }

        Params::SharedPtr KeyRing::GetAuthenticatorParams (
                const ID &paramsId,
                bool recursive) const {
            ParamsMap::const_iterator it = authenticatorParamsMap.find (paramsId);
            if (it != authenticatorParamsMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    Params::SharedPtr params =
                        it->second->GetAuthenticatorParams (paramsId, recursive);
                    if (params != nullptr) {
                        return params;
                    }
                }
            }
            return nullptr;
        }

        Params::SharedPtr KeyRing::GetAuthenticatorParams (
                const EqualityTest<Params> &equalityTest,
                bool recursive) const {
            for (ParamsMap::const_iterator
                    it = authenticatorParamsMap.begin (),
                    end = authenticatorParamsMap.end (); it != end; ++it) {
                if (equalityTest (*it->second)) {
                    return it->second;
                }
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    Params::SharedPtr params =
                        it->second->GetAuthenticatorParams (equalityTest, recursive);
                    if (params != nullptr) {
                        return params;
                    }
                }
            }
            return nullptr;
        }

        bool KeyRing::AddAuthenticatorParams (Params::SharedPtr params) {
            if (params != nullptr && cipherSuite.VerifyAuthenticatorParams (*params)) {
                std::pair<ParamsMap::iterator, bool> result =
                    authenticatorParamsMap.insert (
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
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
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
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    it->second->DropAllAuthenticatorParams (recursive);
                }
            }
        }

        AsymmetricKey::SharedPtr KeyRing::GetAuthenticatorKey (
                const ID &keyId,
                bool recursive) const {
            AsymmetricKeyMap::const_iterator it = authenticatorKeyMap.find (keyId);
            if (it != authenticatorKeyMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    AsymmetricKey::SharedPtr key =
                        it->second->GetAuthenticatorKey (keyId, recursive);
                    if (key != nullptr) {
                        return key;
                    }
                }
            }
            return nullptr;
        }

        AsymmetricKey::SharedPtr KeyRing::GetAuthenticatorKey (
                const EqualityTest<AsymmetricKey> &equalityTest,
                bool recursive) const {
            for (AsymmetricKeyMap::const_iterator
                    it = authenticatorKeyMap.begin (),
                    end = authenticatorKeyMap.end (); it != end; ++it) {
                if (equalityTest (*it->second)) {
                    return it->second;
                }
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    AsymmetricKey::SharedPtr key =
                        it->second->GetAuthenticatorKey (equalityTest, recursive);
                    if (key != nullptr) {
                        return key;
                    }
                }
            }
            return nullptr;
        }

        Authenticator::SharedPtr KeyRing::GetAuthenticator (
                const ID &keyId,
                bool recursive) {
            AuthenticatorMap::const_iterator it = authenticatorMap.find (keyId);
            if (it != authenticatorMap.end ()) {
                return it->second;
            }
            AsymmetricKey::SharedPtr key = GetAuthenticatorKey (keyId, false);
            if (key != nullptr) {
                Authenticator::SharedPtr authenticator =
                    cipherSuite.GetAuthenticator (key);
                std::pair<AuthenticatorMap::iterator, bool> result =
                    authenticatorMap.insert (
                        AuthenticatorMap::value_type (keyId, authenticator));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to add an Authenticator: %s.",
                        keyId.ToHexString ().c_str ());
                }
                return authenticator;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    Authenticator::SharedPtr authenticator =
                        it->second->GetAuthenticator (keyId, recursive);
                    if (authenticator != nullptr) {
                        return authenticator;
                    }
                }
            }
            return nullptr;
        }

        bool KeyRing::AddAuthenticatorKey (
                AsymmetricKey::SharedPtr key,
                Authenticator::SharedPtr authenticator) {
            if (key != nullptr && cipherSuite.VerifyAuthenticatorKey (*key)) {
                std::pair<AsymmetricKeyMap::iterator, bool> result =
                    authenticatorKeyMap.insert (
                        AsymmetricKeyMap::value_type (key->GetId (), key));
                if (result.second && authenticator != nullptr) {
                    std::pair<AuthenticatorMap::iterator, bool> result =
                        authenticatorMap.insert (
                            AuthenticatorMap::value_type (
                                key->GetId (),
                                authenticator));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to add an Authenticator: %s.",
                            key->GetId ().ToHexString ().c_str ());
                    }
                }
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
                AuthenticatorMap::iterator it = authenticatorMap.find (keyId);
                if (it != authenticatorMap.end ()) {
                    authenticatorMap.erase (it);
                }
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    if (it->second->DropAuthenticatorKey (keyId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropAllAuthenticatorKeys (bool recursive) {
            authenticatorKeyMap.clear ();
            authenticatorMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    it->second->DropAllAuthenticatorKeys (recursive);
                }
            }
        }

        SymmetricKey::SharedPtr KeyRing::GetCipherKey (
                const ID &keyId,
                bool recursive) const {
            SymmetricKeyMap::const_iterator it = cipherKeyMap.find (keyId);
            if (it != cipherKeyMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    SymmetricKey::SharedPtr key =
                        it->second->GetCipherKey (keyId, recursive);
                    if (key != nullptr) {
                        return key;
                    }
                }
            }
            return nullptr;
        }

        SymmetricKey::SharedPtr KeyRing::GetCipherKey (
                const EqualityTest<SymmetricKey> &equalityTest,
                bool recursive) const {
            for (SymmetricKeyMap::const_iterator
                    it = cipherKeyMap.begin (),
                    end = cipherKeyMap.end (); it != end; ++it) {
                if (equalityTest (*it->second)) {
                    return it->second;
                }
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    SymmetricKey::SharedPtr key =
                        it->second->GetCipherKey (equalityTest, recursive);
                    if (key != nullptr) {
                        return key;
                    }
                }
            }
            return nullptr;
        }

        Cipher::SharedPtr KeyRing::GetCipher (
                const ID &keyId,
                bool recursive) {
            CipherMap::const_iterator it = cipherMap.find (keyId);
            if (it != cipherMap.end ()) {
                return it->second;
            }
            SymmetricKey::SharedPtr key = GetCipherKey (keyId, false);
            if (key != nullptr) {
                Cipher::SharedPtr cipher =
                    cipherSuite.GetCipher (key);
                std::pair<CipherMap::iterator, bool> result =
                    cipherMap.insert (
                        CipherMap::value_type (keyId, cipher));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to add a Cipher: %s.",
                        keyId.ToHexString ().c_str ());
                }
                return cipher;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    Cipher::SharedPtr cipher =
                        it->second->GetCipher (keyId, recursive);
                    if (cipher != nullptr) {
                        return cipher;
                    }
                }
            }
            return nullptr;
        }

        Cipher::SharedPtr KeyRing::GetRandomCipher () {
            Cipher::SharedPtr cipher;
            if (!cipherKeyMap.empty ()) {
                SymmetricKeyMap::const_iterator keyIt = cipherKeyMap.begin ();
                if (cipherKeyMap.size () > 1) {
                    std::advance (
                        keyIt,
                        util::RandomSource::Instance ()->Getui32 () % cipherKeyMap.size ());
                }
                CipherMap::iterator cipherIt = cipherMap.find (keyIt->second->GetId ());
                if (cipherIt == cipherMap.end ()) {
                    cipher = cipherSuite.GetCipher (keyIt->second);
                    std::pair<CipherMap::iterator, bool> result =
                        cipherMap.insert (
                            CipherMap::value_type (keyIt->second->GetId (), cipher));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to add a Cipher: %s.",
                            keyIt->second->GetId ().ToHexString ().c_str ());
                    }
                }
                else {
                    cipher = cipherIt->second;
                }
            }
            return cipher;
        }

        bool KeyRing::AddCipherKey (
                SymmetricKey::SharedPtr key,
                Cipher::SharedPtr cipher) {
            if (key != nullptr && cipherSuite.VerifyCipherKey (*key)) {
                std::pair<SymmetricKeyMap::iterator, bool> result =
                    cipherKeyMap.insert (
                        SymmetricKeyMap::value_type (key->GetId (), key));
                if (result.second && cipher != nullptr) {
                    std::pair<CipherMap::iterator, bool> result =
                        cipherMap.insert (
                            CipherMap::value_type (key->GetId (), cipher));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to add a Cipher: %s.",
                            key->GetId ().ToHexString ().c_str ());
                    }
                }
                return result.second;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool KeyRing::DropCipherKey (
                const ID &keyId,
                bool recursive) {
            SymmetricKeyMap::iterator it = cipherKeyMap.find (keyId);
            if (it != cipherKeyMap.end ()) {
                cipherKeyMap.erase (it);
                CipherMap::iterator it = cipherMap.find (keyId);
                if (it != cipherMap.end ()) {
                    cipherMap.erase (it);
                }
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    if (it->second->DropCipherKey (keyId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropAllCipherKeys (bool recursive) {
            cipherKeyMap.clear ();
            cipherMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    it->second->DropAllCipherKeys (recursive);
                }
            }
        }

        SymmetricKey::SharedPtr KeyRing::GetMACKey (
                const ID &keyId,
                bool recursive) const {
            SymmetricKeyMap::const_iterator it = macKeyMap.find (keyId);
            if (it != macKeyMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    SymmetricKey::SharedPtr key =
                        it->second->GetMACKey (keyId, recursive);
                    if (key != nullptr) {
                        return key;
                    }
                }
            }
            return nullptr;
        }

        SymmetricKey::SharedPtr KeyRing::GetMACKey (
                const EqualityTest<SymmetricKey> &equalityTest,
                bool recursive) const {
            for (SymmetricKeyMap::const_iterator
                    it = macKeyMap.begin (),
                    end = macKeyMap.end (); it != end; ++it) {
                if (equalityTest (*it->second)) {
                    return it->second;
                }
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    SymmetricKey::SharedPtr key =
                        it->second->GetMACKey (equalityTest, recursive);
                    if (key != nullptr) {
                        return key;
                    }
                }
            }
            return nullptr;
        }

        MAC::SharedPtr KeyRing::GetMAC (
                const ID &keyId,
                bool recursive) {
            MACMap::const_iterator it = macMap.find (keyId);
            if (it != macMap.end ()) {
                return it->second;
            }
            SymmetricKey::SharedPtr key = GetMACKey (keyId, false);
            if (key != nullptr) {
                MAC::SharedPtr mac = cipherSuite.GetHMAC (key);
                std::pair<MACMap::iterator, bool> result =
                    macMap.insert (
                        MACMap::value_type (keyId, mac));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to add a MAC: %s.",
                        keyId.ToHexString ().c_str ());
                }
                return mac;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    MAC::SharedPtr mac =
                        it->second->GetMAC (keyId, recursive);
                    if (mac != nullptr) {
                        return mac;
                    }
                }
            }
            return nullptr;
        }

        bool KeyRing::AddMACKey (
                SymmetricKey::SharedPtr key,
                MAC::SharedPtr mac) {
            if (key != nullptr && cipherSuite.VerifyMACKey (*key, true)) {
                std::pair<SymmetricKeyMap::iterator, bool> result =
                    macKeyMap.insert (
                        SymmetricKeyMap::value_type (key->GetId (), key));
                if (result.second && mac != nullptr) {
                    std::pair<MACMap::iterator, bool> result =
                        macMap.insert (MACMap::value_type (key->GetId (), mac));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to add a MAC: %s.",
                            key->GetId ().ToHexString ().c_str ());
                    }
                }
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
            SymmetricKeyMap::iterator it = macKeyMap.find (keyId);
            if (it != macKeyMap.end ()) {
                macKeyMap.erase (it);
                MACMap::iterator it = macMap.find (keyId);
                if (it != macMap.end ()) {
                    macMap.erase (it);
                }
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    if (it->second->DropMACKey (keyId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropAllMACKeys (bool recursive) {
            macKeyMap.clear ();
            macMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    it->second->DropAllMACKeys (recursive);
                }
            }
        }

        Serializable::SharedPtr KeyRing::GetUserData (
                const ID &id,
                bool recursive) const {
            SerializableMap::const_iterator it = userDataMap.find (id);
            if (it != userDataMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    Serializable::SharedPtr userData =
                        it->second->GetUserData (id, recursive);
                    if (userData != nullptr) {
                        return userData;
                    }
                }
            }
            return nullptr;
        }

        Serializable::SharedPtr KeyRing::GetUserData (
                const EqualityTest<Serializable> &equalityTest,
                bool recursive) const {
            for (SerializableMap::const_iterator
                    it = userDataMap.begin (),
                    end = userDataMap.end (); it != end; ++it) {
                if (equalityTest (*it->second)) {
                    return it->second;
                }
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    Serializable::SharedPtr userData =
                        it->second->GetUserData (equalityTest, recursive);
                    if (userData != nullptr) {
                        return userData;
                    }
                }
            }
            return nullptr;
        }

        bool KeyRing::AddUserData (Serializable::SharedPtr userData) {
            if (userData != nullptr) {
                std::pair<SerializableMap::iterator, bool> result =
                    userDataMap.insert (
                        SerializableMap::value_type (userData->GetId (), userData));
                return result.second;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool KeyRing::DropUserData (
                const ID &id,
                bool recursive) {
            SerializableMap::iterator it = userDataMap.find (id);
            if (it != userDataMap.end ()) {
                userDataMap.erase (it);
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    if (it->second->DropUserData (id, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropAllUserData (bool recursive) {
            userDataMap.clear ();
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    it->second->DropAllUserData (recursive);
                }
            }
        }

        KeyRing::SharedPtr KeyRing::GetSubring (
                const ID &subringId,
                bool recursive) const {
            KeyRingMap::const_iterator it = subringMap.find (subringId);
            if (it != subringMap.end ()) {
                return it->second;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    SharedPtr subring = it->second->GetSubring (subringId, recursive);
                    if (subring != nullptr) {
                        return subring;
                    }
                }
            }
            return nullptr;
        }

        KeyRing::SharedPtr KeyRing::GetSubring (
                const EqualityTest<KeyRing> &equalityTest,
                bool recursive) const {
            for (KeyRingMap::const_iterator
                    it = subringMap.begin (),
                    end = subringMap.end (); it != end; ++it) {
                if (equalityTest (*it->second)) {
                    return it->second;
                }
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    SharedPtr subring = it->second->GetSubring (equalityTest, recursive);
                    if (subring != nullptr) {
                        return subring;
                    }
                }
            }
            return nullptr;
        }

        bool KeyRing::AddSubring (SharedPtr subring) {
            if (subring != nullptr) {
                std::pair<KeyRingMap::iterator, bool> result =
                    subringMap.insert (
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
            KeyRingMap::iterator it = subringMap.find (subringId);
            if (it != subringMap.end ()) {
                subringMap.erase (it);
                return true;
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    if (it->second->DropSubring (subringId, recursive)) {
                        return true;
                    }
                }
            }
            return false;
        }

        void KeyRing::DropAllSubrings () {
            subringMap.clear ();
        }

        void KeyRing::Clear () {
            keyExchangeParamsMap.clear ();
            keyExchangeKeyMap.clear ();
            keyExchangeMap.clear ();
            authenticatorParamsMap.clear ();
            authenticatorKeyMap.clear ();
            authenticatorMap.clear ();
            cipherKeyMap.clear ();
            cipherMap.clear ();
            macKeyMap.clear ();
            macMap.clear ();
            userDataMap.clear ();
            subringMap.clear ();
        }

        std::size_t KeyRing::Size () const noexcept {
            std::size_t size = Serializable::Size () + cipherSuite.Size ();
            size += util::SizeT (keyExchangeParamsMap.size ()).Size ();
            for (ParamsMap::const_iterator
                    it = keyExchangeParamsMap.begin (),
                    end = keyExchangeParamsMap.end (); it != end; ++it) {
                size += it->second->GetSize ();
            }
            size += util::SizeT (keyExchangeKeyMap.size ()).Size ();
            for (AsymmetricKeyMap::const_iterator
                    it = keyExchangeKeyMap.begin (),
                    end = keyExchangeKeyMap.end (); it != end; ++it) {
                size += it->second->GetSize ();
            }
            size += util::SizeT (authenticatorParamsMap.size ()).Size ();
            for (ParamsMap::const_iterator
                    it = authenticatorParamsMap.begin (),
                    end = authenticatorParamsMap.end (); it != end; ++it) {
                size += it->second->GetSize ();
            }
            size += util::SizeT (authenticatorKeyMap.size ()).Size ();
            for (AsymmetricKeyMap::const_iterator
                    it = authenticatorKeyMap.begin (),
                    end = authenticatorKeyMap.end (); it != end; ++it) {
                size += it->second->GetSize ();
            }
            size += util::SizeT (cipherKeyMap.size ()).Size ();
            for (SymmetricKeyMap::const_iterator
                    it = cipherKeyMap.begin (),
                    end = cipherKeyMap.end (); it != end; ++it) {
                size += it->second->GetSize ();
            }
            size += util::SizeT (macKeyMap.size ()).Size ();
            for (SymmetricKeyMap::const_iterator
                    it = macKeyMap.begin (),
                    end = macKeyMap.end (); it != end; ++it) {
                size += it->second->GetSize ();
            }
            size += util::SizeT (userDataMap.size ()).Size ();
            for (SerializableMap::const_iterator
                    it = userDataMap.begin (),
                    end = userDataMap.end (); it != end; ++it) {
                size += it->second->GetSize ();
            }
            size += util::SizeT (subringMap.size ()).Size ();
            for (KeyRingMap::const_iterator
                    it = subringMap.begin (),
                    end = subringMap.end (); it != end; ++it) {
                size += it->second->GetSize ();
            }
            return size;
        }

        void KeyRing::Read (
                const Header &header,
                util::Serializer &serializer) {
            Serializable::Read (header, serializer);
            serializer >> cipherSuite;
            util::SizeT keyExchangeParamsCount;
            serializer >> keyExchangeParamsCount;
            keyExchangeParamsMap.clear ();
            while (keyExchangeParamsCount-- > 0) {
                Params::SharedPtr params;
                serializer >> params;
                std::pair<ParamsMap::iterator, bool> result =
                    keyExchangeParamsMap.insert (
                        ParamsMap::value_type (params->GetId (), params));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert KeyExchange params: %s",
                        params->GetName ().c_str ());
                }
            }
            util::SizeT keyExchangeKeyCount;
            serializer >> keyExchangeKeyCount;
            keyExchangeKeyMap.clear ();
            while (keyExchangeKeyCount-- > 0) {
                AsymmetricKey::SharedPtr key;
                serializer >> key;
                std::pair<AsymmetricKeyMap::iterator, bool> result =
                    keyExchangeKeyMap.insert (
                        AsymmetricKeyMap::value_type (key->GetId (), key));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert KeyExchange key: %s",
                        key->GetName ().c_str ());
                }
            }
            util::SizeT authenticatorParamsCount;
            serializer >> authenticatorParamsCount;
            authenticatorParamsMap.clear ();
            while (authenticatorParamsCount-- > 0) {
                Params::SharedPtr params;
                serializer >> params;
                std::pair<ParamsMap::iterator, bool> result =
                    authenticatorParamsMap.insert (
                        ParamsMap::value_type (params->GetId (), params));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert Authenticator params: %s",
                        params->GetName ().c_str ());
                }
            }
            util::SizeT authenticatorKeyCount;
            serializer >> authenticatorKeyCount;
            authenticatorKeyMap.clear ();
            while (authenticatorKeyCount-- > 0) {
                AsymmetricKey::SharedPtr key;
                serializer >> key;
                std::pair<AsymmetricKeyMap::iterator, bool> result =
                    authenticatorKeyMap.insert (
                        AsymmetricKeyMap::value_type (key->GetId (), key));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert Authenticator key: %s",
                        key->GetName ().c_str ());
                }
            }
            util::SizeT cipherKeyCount;
            serializer >> cipherKeyCount;
            cipherKeyMap.clear ();
            while (cipherKeyCount-- > 0) {
                SymmetricKey::SharedPtr key;
                serializer >> key;
                std::pair<SymmetricKeyMap::iterator, bool> result =
                    cipherKeyMap.insert (
                        SymmetricKeyMap::value_type (key->GetId (), key));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert Cipher key: %s",
                        key->GetName ().c_str ());
                }
            }
            util::SizeT macKeyCount;
            serializer >> macKeyCount;
            macKeyMap.clear ();
            while (macKeyCount-- > 0) {
                SymmetricKey::SharedPtr key;
                serializer >> key;
                std::pair<SymmetricKeyMap::iterator, bool> result =
                    macKeyMap.insert (
                        SymmetricKeyMap::value_type (key->GetId (), key));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert MAC key: %s",
                        key->GetName ().c_str ());
                }
            }
            util::SizeT userDataCount;
            serializer >> userDataCount;
            userDataMap.clear ();
            while (userDataCount-- > 0) {
                Serializable::SharedPtr userData;
                serializer >> userData;
                std::pair<SerializableMap::iterator, bool> result =
                    userDataMap.insert (
                        SerializableMap::value_type (userData->GetId (), userData));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert user data: %s",
                        userData->GetName ().c_str ());
                }
            }
            util::SizeT subringCount;
            serializer >> subringCount;
            subringMap.clear ();
            while (subringCount-- > 0) {
                SharedPtr subring;
                serializer >> subring;
                std::pair<KeyRingMap::iterator, bool> result =
                    subringMap.insert (
                        KeyRingMap::value_type (subring->GetId (), subring));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to instert subring: %s",
                        subring->GetName ().c_str ());
                }
            }
        }

        void KeyRing::Write (util::Serializer &serializer) const {
            Serializable::Write (serializer);
            serializer << cipherSuite;
            serializer << util::SizeT (keyExchangeParamsMap.size ());
            for (ParamsMap::const_iterator
                    it = keyExchangeParamsMap.begin (),
                    end = keyExchangeParamsMap.end (); it != end; ++it) {
                serializer << *it->second;
            }
            serializer << util::SizeT (keyExchangeKeyMap.size ());
            for (AsymmetricKeyMap::const_iterator
                    it = keyExchangeKeyMap.begin (),
                    end = keyExchangeKeyMap.end (); it != end; ++it) {
                serializer << *it->second;
            }
            serializer << util::SizeT (authenticatorParamsMap.size ());
            for (ParamsMap::const_iterator
                    it = authenticatorParamsMap.begin (),
                    end = authenticatorParamsMap.end (); it != end; ++it) {
                serializer << *it->second;
            }
            serializer << util::SizeT (authenticatorKeyMap.size ());
            for (AsymmetricKeyMap::const_iterator
                    it = authenticatorKeyMap.begin (),
                    end = authenticatorKeyMap.end (); it != end; ++it) {
                serializer << *it->second;
            }
            serializer << util::SizeT (cipherKeyMap.size ());
            for (SymmetricKeyMap::const_iterator
                    it = cipherKeyMap.begin (),
                    end = cipherKeyMap.end (); it != end; ++it) {
                serializer << *it->second;
            }
            serializer << util::SizeT (macKeyMap.size ());
            for (SymmetricKeyMap::const_iterator
                    it = macKeyMap.begin (),
                    end = macKeyMap.end (); it != end; ++it) {
                serializer << *it->second;
            }
            serializer << util::SizeT (userDataMap.size ());
            for (SerializableMap::const_iterator
                    it = userDataMap.begin (),
                    end = userDataMap.end (); it != end; ++it) {
                serializer << *it->second;
            }
            serializer << util::SizeT (subringMap.size ());
            for (KeyRingMap::const_iterator
                    it = subringMap.begin (),
                    end = subringMap.end (); it != end; ++it) {
                serializer << *it->second;
            }
        }

        const char * const KeyRing::TAG_KEY_RING = "KeyRing";
        const char * const KeyRing::ATTR_CIPHER_SUITE = "CipherSuite";
        const char * const KeyRing::TAG_KEY_EXCHANGE_PARAMS = "KeyExchangeParams";
        const char * const KeyRing::TAG_KEY_EXCHANGE_PARAM = "KeyExchangeParam";
        const char * const KeyRing::TAG_KEY_EXCHANGE_KEYS = "KeyExchangeKeys";
        const char * const KeyRing::TAG_KEY_EXCHANGE_KEY = "KeyExchangeKey";
        const char * const KeyRing::TAG_AUTHENTICATOR_PARAMS = "AuthenticatorParams";
        const char * const KeyRing::TAG_AUTHENTICATOR_PARAM = "AuthenticatorParam";
        const char * const KeyRing::TAG_AUTHENTICATOR_KEYS = "AuthenticatorKeys";
        const char * const KeyRing::TAG_AUTHENTICATOR_KEY = "AuthenticatorKey";
        const char * const KeyRing::TAG_CIPHER_KEYS = "CipherKeys";
        const char * const KeyRing::TAG_CIPHER_KEY = "CipherKey";
        const char * const KeyRing::TAG_MAC_KEYS = "MACKeys";
        const char * const KeyRing::TAG_MAC_KEY = "MACKey";
        const char * const KeyRing::TAG_USER_DATAS = "UserDatas";
        const char * const KeyRing::TAG_USER_DATA = "UserData";
        const char * const KeyRing::TAG_SUB_RINGS = "SubRings";
        const char * const KeyRing::TAG_SUB_RING = "SubRing";

        void KeyRing::ReadXML (
                const Header &header,
                const pugi::xml_node &node) {
            Serializable::ReadXML (header, node);
            cipherSuite = node.attribute (ATTR_CIPHER_SUITE).value ();
            keyExchangeParamsMap.clear ();
            pugi::xml_node keyExchangeParams = node.child (TAG_KEY_EXCHANGE_PARAMS);
            for (pugi::xml_node child = keyExchangeParams.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == TAG_KEY_EXCHANGE_PARAM) {
                        Params::SharedPtr params;
                        child >> params;
                        std::pair<ParamsMap::iterator, bool> result =
                            keyExchangeParamsMap.insert (
                                ParamsMap::value_type (params->GetId (), params));
                        if (!result.second) {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to instert KeyExchange params: %s",
                                params->GetName ().c_str ());
                        }
                    }
                }
            }
            keyExchangeKeyMap.clear ();
            pugi::xml_node keyExchangeKeys = node.child (TAG_KEY_EXCHANGE_KEYS);
            for (pugi::xml_node child = keyExchangeKeys.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == TAG_KEY_EXCHANGE_KEY) {
                        AsymmetricKey::SharedPtr key;
                        child >> key;
                        std::pair<AsymmetricKeyMap::iterator, bool> result =
                            keyExchangeKeyMap.insert (
                                AsymmetricKeyMap::value_type (key->GetId (), key));
                        if (!result.second) {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to instert KeyExchange key: %s",
                                key->GetName ().c_str ());
                        }
                    }
                }
            }
            authenticatorParamsMap.clear ();
            pugi::xml_node authenticatorParams = node.child (TAG_AUTHENTICATOR_PARAMS);
            for (pugi::xml_node child = authenticatorParams.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == TAG_AUTHENTICATOR_PARAM) {
                        Params::SharedPtr params;
                        child >> params;
                        std::pair<ParamsMap::iterator, bool> result =
                            authenticatorParamsMap.insert (
                                ParamsMap::value_type (params->GetId (), params));
                        if (!result.second) {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to instert Authenticator params: %s",
                                params->GetName ().c_str ());
                        }
                    }
                }
            }
            authenticatorKeyMap.clear ();
            pugi::xml_node authenticatorKeys = node.child (TAG_AUTHENTICATOR_KEYS);
            for (pugi::xml_node child = authenticatorKeys.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == TAG_AUTHENTICATOR_KEY) {
                        AsymmetricKey::SharedPtr key;
                        child >> key;
                        std::pair<AsymmetricKeyMap::iterator, bool> result =
                            authenticatorKeyMap.insert (
                                AsymmetricKeyMap::value_type (key->GetId (), key));
                        if (!result.second) {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to instert Authenticator key: %s",
                                key->GetName ().c_str ());
                        }
                    }
                }
            }
            cipherKeyMap.clear ();
            pugi::xml_node cipherKeys = node.child (TAG_CIPHER_KEYS);
            for (pugi::xml_node child = cipherKeys.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == TAG_CIPHER_KEY) {
                        SymmetricKey::SharedPtr key;
                        child >> key;
                        std::pair<SymmetricKeyMap::iterator, bool> result =
                            cipherKeyMap.insert (
                                SymmetricKeyMap::value_type (key->GetId (), key));
                        if (!result.second) {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to instert Cipher key: %s",
                                key->GetName ().c_str ());
                        }
                    }
                }
            }
            macKeyMap.clear ();
            pugi::xml_node macKeys = node.child (TAG_MAC_KEYS);
            for (pugi::xml_node child = macKeys.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == TAG_MAC_KEY) {
                        SymmetricKey::SharedPtr key;
                        child >> key;
                        std::pair<SymmetricKeyMap::iterator, bool> result =
                            macKeyMap.insert (
                                SymmetricKeyMap::value_type (key->GetId (), key));
                        if (!result.second) {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to instert MAC key: %s",
                                key->GetName ().c_str ());
                        }
                    }
                }
            }
            userDataMap.clear ();
            pugi::xml_node userDatas = node.child (TAG_USER_DATAS);
            for (pugi::xml_node child = userDatas.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == TAG_USER_DATA) {
                        Serializable::SharedPtr userData;
                        child >> userData;
                        std::pair<SerializableMap::iterator, bool> result =
                            userDataMap.insert (
                                SerializableMap::value_type (userData->GetId (), userData));
                        if (!result.second) {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to instert user data: %s",
                                userData->GetName ().c_str ());
                        }
                    }
                }
            }
            subringMap.clear ();
            pugi::xml_node subrings = node.child (TAG_SUB_RINGS);
            for (pugi::xml_node child = subrings.first_child ();
                    !child.empty (); child = child.next_sibling ()) {
                if (child.type () == pugi::node_element) {
                    std::string childName = child.name ();
                    if (childName == TAG_SUB_RING) {
                        SharedPtr subring;
                        child >> subring;
                        std::pair<KeyRingMap::iterator, bool> result =
                            subringMap.insert (
                                KeyRingMap::value_type (subring->GetId (), subring));
                        if (!result.second) {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to instert subring: %s",
                                subring->GetName ().c_str ());
                        }
                    }
                }
            }
        }

        void KeyRing::WriteXML (pugi::xml_node &node) const {
            Serializable::WriteXML (node);
            node.append_attribute (ATTR_CIPHER_SUITE).set_value (cipherSuite.ToString ().c_str ());
            {
                pugi::xml_node keyExchangeParams =
                    node.append_child (TAG_KEY_EXCHANGE_PARAMS);
                for (ParamsMap::const_iterator
                        it = keyExchangeParamsMap.begin (),
                        end = keyExchangeParamsMap.end (); it != end; ++it) {
                    pugi::xml_node keyExchangeParam =
                        keyExchangeParams.append_child (TAG_KEY_EXCHANGE_PARAM);
                    keyExchangeParam << *it->second;
                }
            }
            {
                pugi::xml_node keyExchangeKeys =
                    node.append_child (TAG_KEY_EXCHANGE_KEYS);
                for (AsymmetricKeyMap::const_iterator
                        it = keyExchangeKeyMap.begin (),
                        end = keyExchangeKeyMap.end (); it != end; ++it) {
                    pugi::xml_node keyExchangeKey =
                        keyExchangeKeys.append_child (TAG_KEY_EXCHANGE_KEY);
                    keyExchangeKey << *it->second;
                }
            }
            {
                pugi::xml_node authenticatorParams =
                    node.append_child (TAG_AUTHENTICATOR_PARAMS);
                for (ParamsMap::const_iterator
                        it = authenticatorParamsMap.begin (),
                        end = authenticatorParamsMap.end (); it != end; ++it) {
                    pugi::xml_node authenticatorParam =
                        authenticatorParams.append_child (TAG_AUTHENTICATOR_PARAM);
                    authenticatorParam << *it->second;
                }
            }
            {
                pugi::xml_node authenticatorKeys =
                    node.append_child (TAG_AUTHENTICATOR_KEYS);
                for (AsymmetricKeyMap::const_iterator
                        it = authenticatorKeyMap.begin (),
                        end = authenticatorKeyMap.end (); it != end; ++it) {
                    pugi::xml_node authenticatorKey =
                        authenticatorKeys.append_child (TAG_AUTHENTICATOR_KEY);
                    authenticatorKey << *it->second;
                }
            }
            {
                pugi::xml_node cipherKeys = node.append_child (TAG_CIPHER_KEYS);
                for (SymmetricKeyMap::const_iterator
                        it = cipherKeyMap.begin (),
                        end = cipherKeyMap.end (); it != end; ++it) {
                    pugi::xml_node cipherKey = cipherKeys.append_child (TAG_CIPHER_KEY);
                    cipherKey << *it->second;
                }
            }
            {
                pugi::xml_node macKeys = node.append_child (TAG_MAC_KEYS);
                for (SymmetricKeyMap::const_iterator
                        it = macKeyMap.begin (),
                        end = macKeyMap.end (); it != end; ++it) {
                    pugi::xml_node macKey = macKeys.append_child (TAG_CIPHER_KEY);
                    macKey << *it->second;
                }
            }
            {
                pugi::xml_node userDatas = node.append_child (TAG_USER_DATAS);
                for (SerializableMap::const_iterator
                        it = userDataMap.begin (),
                        end = userDataMap.end (); it != end; ++it) {
                    pugi::xml_node userData = userDatas.append_child (TAG_USER_DATA);
                    userData << *it->second;
                }
            }
            {
                pugi::xml_node subRings = node.append_child (TAG_SUB_RINGS);
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    pugi::xml_node subRing = subRings.append_child (TAG_SUB_RING);
                    subRing << *it->second;
                }
            }
        }

        void KeyRing::ReadJSON (
                const Header &header,
                const util::JSON::Object &object) {
            Serializable::ReadJSON (header, object);
            cipherSuite = object.Get<util::JSON::String> (ATTR_CIPHER_SUITE)->value;
            keyExchangeParamsMap.clear ();
            util::JSON::Array::SharedPtr keyExchangeParams =
                object.Get<util::JSON::Array> (TAG_KEY_EXCHANGE_PARAMS);
            if (keyExchangeParams != nullptr) {
                for (std::size_t i = 0, count = keyExchangeParams->GetValueCount (); i < count; ++i) {
                    util::JSON::Object::SharedPtr keyExchangeParam =
                        keyExchangeParams->Get<util::JSON::Object> (i);
                    Params::SharedPtr params;
                    *keyExchangeParam >> params;
                    std::pair<ParamsMap::iterator, bool> result =
                        keyExchangeParamsMap.insert (
                            ParamsMap::value_type (params->GetId (), params));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to instert KeyExchange params: %s",
                            params->GetName ().c_str ());
                    }
                }
            }
            keyExchangeKeyMap.clear ();
            util::JSON::Array::SharedPtr keyExchangeKeys =
                object.Get<util::JSON::Array> (TAG_KEY_EXCHANGE_KEYS);
            if (keyExchangeKeys != nullptr) {
                for (std::size_t i = 0, count = keyExchangeKeys->GetValueCount (); i < count; ++i) {
                    util::JSON::Object::SharedPtr keyExchangeKey =
                        keyExchangeKeys->Get<util::JSON::Object> (i);
                    AsymmetricKey::SharedPtr key;
                    *keyExchangeKey >> key;
                    std::pair<AsymmetricKeyMap::iterator, bool> result =
                        keyExchangeKeyMap.insert (
                            AsymmetricKeyMap::value_type (key->GetId (), key));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to instert KeyExchange key: %s",
                            key->GetName ().c_str ());
                    }
                }
            }
            authenticatorParamsMap.clear ();
            util::JSON::Array::SharedPtr authenticatorParams =
                object.Get<util::JSON::Array> (TAG_AUTHENTICATOR_PARAMS);
            if (authenticatorParams != nullptr) {
                for (std::size_t i = 0, count = authenticatorParams->GetValueCount (); i < count; ++i) {
                    util::JSON::Object::SharedPtr authenticatorParam =
                        authenticatorParams->Get<util::JSON::Object> (i);
                    Params::SharedPtr params;
                    *authenticatorParam >> params;
                    std::pair<ParamsMap::iterator, bool> result =
                        authenticatorParamsMap.insert (
                            ParamsMap::value_type (params->GetId (), params));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to instert Authenticator params: %s",
                            params->GetName ().c_str ());
                    }
                }
            }
            authenticatorKeyMap.clear ();
            util::JSON::Array::SharedPtr authenticatorKeys =
                object.Get<util::JSON::Array> (TAG_AUTHENTICATOR_KEYS);
            if (authenticatorKeys != nullptr) {
                for (std::size_t i = 0, count = authenticatorKeys->GetValueCount (); i < count; ++i) {
                    util::JSON::Object::SharedPtr authenticatorKey =
                        authenticatorKeys->Get<util::JSON::Object> (i);
                    AsymmetricKey::SharedPtr key;
                    *authenticatorKey >> key;
                    std::pair<AsymmetricKeyMap::iterator, bool> result =
                        authenticatorKeyMap.insert (
                            AsymmetricKeyMap::value_type (key->GetId (), key));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to instert Authenticator key: %s",
                            key->GetName ().c_str ());
                    }
                }
            }
            cipherKeyMap.clear ();
            util::JSON::Array::SharedPtr cipherKeys =
                object.Get<util::JSON::Array> (TAG_CIPHER_KEYS);
            if (cipherKeys != nullptr) {
                for (std::size_t i = 0, count = cipherKeys->GetValueCount (); i < count; ++i) {
                    util::JSON::Object::SharedPtr cipherKey =
                        cipherKeys->Get<util::JSON::Object> (i);
                    SymmetricKey::SharedPtr key;
                    *cipherKey >> key;
                    std::pair<SymmetricKeyMap::iterator, bool> result =
                        cipherKeyMap.insert (
                            SymmetricKeyMap::value_type (key->GetId (), key));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to instert Cipher key: %s",
                            key->GetName ().c_str ());
                    }
                }
            }
            macKeyMap.clear ();
            util::JSON::Array::SharedPtr macKeys = object.Get<util::JSON::Array> (TAG_MAC_KEYS);
            if (macKeys != nullptr) {
                for (std::size_t i = 0, count = macKeys->GetValueCount (); i < count; ++i) {
                    util::JSON::Object::SharedPtr macKey = macKeys->Get<util::JSON::Object> (i);
                    SymmetricKey::SharedPtr key;
                    *macKey >> key;
                    std::pair<SymmetricKeyMap::iterator, bool> result =
                        macKeyMap.insert (
                            SymmetricKeyMap::value_type (key->GetId (), key));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to instert MAC key: %s",
                            key->GetName ().c_str ());
                    }
                }
            }
            userDataMap.clear ();
            util::JSON::Array::SharedPtr userDatas = object.Get<util::JSON::Array> (TAG_USER_DATAS);
            if (userDatas != nullptr) {
                for (std::size_t i = 0, count = userDatas->GetValueCount (); i < count; ++i) {
                    util::JSON::Object::SharedPtr userData = userDatas->Get<util::JSON::Object> (i);
                    Serializable::SharedPtr data;
                    *userData >> data;
                    std::pair<SerializableMap::iterator, bool> result =
                        userDataMap.insert (
                            SerializableMap::value_type (data->GetId (), data));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to instert user data: %s",
                            data->GetName ().c_str ());
                    }
                }
            }
            subringMap.clear ();
            util::JSON::Array::SharedPtr subrings = object.Get<util::JSON::Array> (TAG_SUB_RINGS);
            if (subrings != nullptr) {
                for (std::size_t i = 0, count = subrings->GetValueCount (); i < count; ++i) {
                    util::JSON::Object::SharedPtr subring = subrings->Get<util::JSON::Object> (i);
                    SharedPtr keyRing;
                    *subring >> keyRing;
                    std::pair<KeyRingMap::iterator, bool> result =
                        subringMap.insert (
                            KeyRingMap::value_type (keyRing->GetId (), keyRing));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to instert subring: %s",
                            keyRing->GetName ().c_str ());
                    }
                }
            }
        }

        void KeyRing::WriteJSON (util::JSON::Object &object) const {
            Serializable::WriteJSON (object);
            object.Add<const std::string &> (ATTR_CIPHER_SUITE, cipherSuite.ToString ());
            {
                util::JSON::Array::SharedPtr keyExchangeParams (new util::JSON::Array);
                for (ParamsMap::const_iterator
                        it = keyExchangeParamsMap.begin (),
                        end = keyExchangeParamsMap.end (); it != end; ++it) {
                    util::JSON::Object::SharedPtr keyExchangeParam (new util::JSON::Object);
                    *keyExchangeParam << *it->second;
                    keyExchangeParams->Add (keyExchangeParam);
                }
                object.Add (TAG_KEY_EXCHANGE_PARAMS, keyExchangeParams);
            }
            {
                util::JSON::Array::SharedPtr keyExchangeKeys (new util::JSON::Array);
                for (AsymmetricKeyMap::const_iterator
                        it = keyExchangeKeyMap.begin (),
                        end = keyExchangeKeyMap.end (); it != end; ++it) {
                    util::JSON::Object::SharedPtr keyExchangeKey (new util::JSON::Object);
                    *keyExchangeKey << *it->second;
                    keyExchangeKeys->Add (keyExchangeKey);
                }
                object.Add (TAG_KEY_EXCHANGE_KEYS, keyExchangeKeys);
            }
            {
                util::JSON::Array::SharedPtr authenticatorParams (new util::JSON::Array);
                for (ParamsMap::const_iterator
                        it = authenticatorParamsMap.begin (),
                        end = authenticatorParamsMap.end (); it != end; ++it) {
                    util::JSON::Object::SharedPtr authenticatorParam (new util::JSON::Object);
                    *authenticatorParam << *it->second;
                    authenticatorParams->Add (authenticatorParam);
                }
                object.Add (TAG_AUTHENTICATOR_PARAMS, authenticatorParams);
            }
            {
                util::JSON::Array::SharedPtr authenticatorKeys (new util::JSON::Array);
                for (AsymmetricKeyMap::const_iterator
                        it = authenticatorKeyMap.begin (),
                        end = authenticatorKeyMap.end (); it != end; ++it) {
                    util::JSON::Object::SharedPtr authenticatorKey (new util::JSON::Object);
                    *authenticatorKey << *it->second;
                    authenticatorKeys->Add (authenticatorKey);
                }
                object.Add (TAG_AUTHENTICATOR_KEYS, authenticatorKeys);
            }
            {
                util::JSON::Array::SharedPtr cipherKeys (new util::JSON::Array);
                for (SymmetricKeyMap::const_iterator
                        it = cipherKeyMap.begin (),
                        end = cipherKeyMap.end (); it != end; ++it) {
                    util::JSON::Object::SharedPtr cipherKey (new util::JSON::Object);
                    *cipherKey << *it->second;
                    cipherKeys->Add (cipherKey);
                }
                object.Add (TAG_CIPHER_KEYS, cipherKeys);
            }
            {
                util::JSON::Array::SharedPtr macKeys (new util::JSON::Array);
                for (SymmetricKeyMap::const_iterator
                        it = macKeyMap.begin (),
                        end = macKeyMap.end (); it != end; ++it) {
                    util::JSON::Object::SharedPtr macKey (new util::JSON::Object);
                    *macKey << *it->second;
                    macKeys->Add (macKey);
                }
                object.Add (TAG_MAC_KEYS, macKeys);
            }
            {
                util::JSON::Array::SharedPtr userDatas (new util::JSON::Array);
                for (SerializableMap::const_iterator
                        it = userDataMap.begin (),
                        end = userDataMap.end (); it != end; ++it) {
                    util::JSON::Object::SharedPtr userData (new util::JSON::Object);
                    *userData << *it->second;
                    userDatas->Add (userData);
                }
                object.Add (TAG_USER_DATAS, userDatas);
            }
            {
                util::JSON::Array::SharedPtr subRings (new util::JSON::Array);
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    util::JSON::Object::SharedPtr subRing (new util::JSON::Object);
                    *subRing << *it->second;
                    subRings->Add (subRing);
                }
                object.Add (TAG_SUB_RINGS, subRings);
            }
        }

    } // namespace crypto
} // namespace thekogans
