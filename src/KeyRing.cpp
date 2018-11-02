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

#include <sstream>
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
            KeyRing,
            1,
            THEKOGANS_CRYPTO_MIN_KEY_RINGS_IN_PAGE)

        KeyRing::Ptr KeyRing::Load (
                const std::string &path,
                Cipher *cipher,
                const void *associatedData,
                std::size_t associatedDataLength) {
            util::ReadOnlyFile file (util::NetworkEndian, path);
            util::Buffer buffer (util::NetworkEndian, (std::size_t)file.GetSize ());
            buffer.AdvanceWriteOffset (
                file.Read (
                    buffer.GetWritePtr (),
                    buffer.GetDataAvailableForWriting ()));
            if (cipher != 0) {
                buffer = cipher->Decrypt (
                    buffer.GetReadPtr (),
                    buffer.GetDataAvailableForReading (),
                    associatedData,
                    associatedDataLength,
                    true);
            }
            Ptr keyRing;
            buffer >> keyRing;
            return keyRing;
        }

        void KeyRing::Save (
                const std::string &path,
                Cipher *cipher,
                const void *associatedData,
                std::size_t associatedDataLength) {
            util::Buffer buffer (
                util::NetworkEndian,
                util::Serializable::Size (*this));
            buffer << *this;
            if (cipher != 0) {
                buffer = cipher->Encrypt (
                    buffer.GetReadPtr (),
                    buffer.GetDataAvailableForReading (),
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
                buffer.GetReadPtr (),
                buffer.GetDataAvailableForReading ());
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
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    Params::Ptr params =
                        it->second->GetKeyExchangeParams (paramsId, recursive);
                    if (params.Get () != 0) {
                        return params;
                    }
                }
            }
            return Params::Ptr ();
        }

        Params::Ptr KeyRing::GetKeyExchangeParams (
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
                    Params::Ptr params =
                        it->second->GetKeyExchangeParams (equalityTest, recursive);
                    if (params.Get () != 0) {
                        return params;
                    }
                }
            }
            return Params::Ptr ();
        }

        Params::Ptr KeyRing::GetRandomKeyExchangeParams () const {
            Params::Ptr params;
            if (!keyExchangeParamsMap.empty ()) {
                ParamsMap::const_iterator it = keyExchangeParamsMap.begin ();
                if (keyExchangeParamsMap.size () > 1) {
                    std::advance (
                        it,
                        util::GlobalRandomSource::Instance ().Getui32 () % keyExchangeParamsMap.size ());
                }
                params = it->second;
            }
            return params;
        }

        bool KeyRing::AddKeyExchangeParams (Params::Ptr params) {
            if (params.Get () != 0 &&
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

        AsymmetricKey::Ptr KeyRing::GetKeyExchangeKey (
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
                    AsymmetricKey::Ptr key =
                        it->second->GetKeyExchangeKey (keyId, recursive);
                    if (key.Get () != 0) {
                        return key;
                    }
                }
            }
            return AsymmetricKey::Ptr ();
        }

        AsymmetricKey::Ptr KeyRing::GetKeyExchangeKey (
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
                    AsymmetricKey::Ptr key =
                        it->second->GetKeyExchangeKey (equalityTest, recursive);
                    if (key.Get () != 0) {
                        return key;
                    }
                }
            }
            return AsymmetricKey::Ptr ();
        }

        bool KeyRing::AddKeyExchangeKey (AsymmetricKey::Ptr key) {
            if (key.Get () != 0 && cipherSuite.VerifyKeyExchangeKey (*key)) {
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

        KeyExchange::Ptr KeyRing::AddKeyExchange (
                const ID &paramsOrKeyId,
                std::size_t secretLength,
                const void *salt,
                std::size_t saltLength,
                std::size_t count,
                const ID &keyId,
                const std::string &name,
                const std::string &description,
                bool recursive) {
            crypto::KeyExchange::Ptr keyExchange;
            if (cipherSuite.keyExchange == CipherSuite::KEY_EXCHANGE_ECDHE ||
                    cipherSuite.keyExchange == CipherSuite::KEY_EXCHANGE_DHE) {
                crypto::Params::Ptr params = paramsOrKeyId != ID::Empty ?
                    GetKeyExchangeParams (paramsOrKeyId) :
                    GetRandomKeyExchangeParams ();
                if (params.Get () != 0) {
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
                        paramsOrKeyId.ToString ().c_str ());
                }
            }
            else if (cipherSuite.keyExchange == CipherSuite::KEY_EXCHANGE_RSA) {
                crypto::AsymmetricKey::Ptr key = GetKeyExchangeKey (paramsOrKeyId);
                if (key.Get () != 0 && !key->IsPrivate ()) {
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
                        paramsOrKeyId.ToString ().c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unknown key exchange type: %s",
                    cipherSuite.keyExchange.c_str ());
            }
            if (keyExchange.Get () != 0) {
                std::pair<KeyExchangeMap::iterator, bool> result =
                    keyExchangeMap.insert (
                        KeyExchangeMap::value_type (keyExchange->GetId (), keyExchange));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to add a KeyExchange: %s.",
                        keyExchange->GetId ().ToString ().c_str ());
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
                    if (keyExchange.Get () != 0) {
                        break;
                    }
                }
            }
            return keyExchange;
        }

        KeyExchange::Ptr KeyRing::CreateKeyExchange (
                KeyExchange::Params::Ptr params,
                bool recursive) {
            if (params.Get () != 0) {
                // Validate the parameters signature (if one was provided).
                if (!params->signature.IsEmpty ()) {
                    AsymmetricKey::Ptr publicKey =
                        GetAuthenticatorKey (params->signatureKeyId, recursive);
                    if (publicKey.Get () != 0 && !publicKey->IsPrivate ()) {
                        MessageDigest::Ptr messageDigest (
                            new MessageDigest (
                                CipherSuite::GetOpenSSLMessageDigestByName (
                                    params->signatureMessageDigestName)));
                        if (messageDigest.Get () != 0) {
                            if (!params->ValidateSignature (publicKey, messageDigest)) {
                                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                    "Params failed signature validation: %s",
                                    params->id.ToString ().c_str ());
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
                            params->signatureKeyId.ToString ().c_str ());
                    }
                }
                if (cipherSuite.keyExchange == CipherSuite::KEY_EXCHANGE_ECDHE ||
                        cipherSuite.keyExchange == CipherSuite::KEY_EXCHANGE_DHE) {
                    return KeyExchange::Ptr (new DHEKeyExchange (params));
                }
                else if (cipherSuite.keyExchange == CipherSuite::KEY_EXCHANGE_RSA) {
                    RSAKeyExchange::RSAParams::Ptr rsaParams =
                        util::dynamic_refcounted_pointer_cast<RSAKeyExchange::RSAParams> (params);
                    if (rsaParams.Get () != 0) {
                        AsymmetricKey::Ptr key = GetKeyExchangeKey (rsaParams->keyId, recursive);
                        if (key.Get () != 0) {
                            return KeyExchange::Ptr (new RSAKeyExchange (key, params));
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to get key for id: %s",
                                rsaParams->keyId.ToString ().c_str ());
                        }
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Incorrect key exchange parameters type: %s, "
                            "expected RSAKeyExchange::RSAParams.",
                            params->GetType ().c_str ());
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

        KeyExchange::Ptr KeyRing::GetKeyExchange (
                const ID &keyExchangeId,
                bool recursive) {
            KeyExchange::Ptr keyExchange;
            KeyExchangeMap::iterator it = keyExchangeMap.find (keyExchangeId);
            if (it != keyExchangeMap.end ()) {
                keyExchange = it->second;
            }
            if (keyExchange.Get () != 0) {
                keyExchangeMap.erase (it);
            }
            else if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    keyExchange =
                        it->second->GetKeyExchange (keyExchangeId, recursive);
                    if (keyExchange.Get () != 0) {
                        break;
                    }
                }
            }
            return keyExchange;
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
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    Params::Ptr params =
                        it->second->GetAuthenticatorParams (paramsId, recursive);
                    if (params.Get () != 0) {
                        return params;
                    }
                }
            }
            return Params::Ptr ();
        }

        Params::Ptr KeyRing::GetAuthenticatorParams (
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
                    Params::Ptr params =
                        it->second->GetAuthenticatorParams (equalityTest, recursive);
                    if (params.Get () != 0) {
                        return params;
                    }
                }
            }
            return Params::Ptr ();
        }

        bool KeyRing::AddAuthenticatorParams (Params::Ptr params) {
            if (params.Get () != 0 && cipherSuite.VerifyAuthenticatorParams (*params)) {
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

        AsymmetricKey::Ptr KeyRing::GetAuthenticatorKey (
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
                    AsymmetricKey::Ptr key =
                        it->second->GetAuthenticatorKey (keyId, recursive);
                    if (key.Get () != 0) {
                        return key;
                    }
                }
            }
            return AsymmetricKey::Ptr ();
        }

        AsymmetricKey::Ptr KeyRing::GetAuthenticatorKey (
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
                    AsymmetricKey::Ptr key =
                        it->second->GetAuthenticatorKey (equalityTest, recursive);
                    if (key.Get () != 0) {
                        return key;
                    }
                }
            }
            return AsymmetricKey::Ptr ();
        }

        Authenticator::Ptr KeyRing::GetAuthenticator (
                const ID &keyId,
                bool recursive) {
            AuthenticatorMap::const_iterator it = authenticatorMap.find (keyId);
            if (it != authenticatorMap.end ()) {
                return it->second;
            }
            AsymmetricKey::Ptr key = GetAuthenticatorKey (keyId, false);
            if (key.Get () != 0) {
                Authenticator::Ptr authenticator =
                    cipherSuite.GetAuthenticator (key);
                std::pair<AuthenticatorMap::iterator, bool> result =
                    authenticatorMap.insert (
                        AuthenticatorMap::value_type (keyId, authenticator));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to add an Authenticator: %s.",
                        keyId.ToString ().c_str ());
                }
                return authenticator;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    Authenticator::Ptr authenticator =
                        it->second->GetAuthenticator (keyId, recursive);
                    if (authenticator.Get () != 0) {
                        return authenticator;
                    }
                }
            }
            return Authenticator::Ptr ();
        }

        bool KeyRing::AddAuthenticatorKey (
                AsymmetricKey::Ptr key,
                Authenticator::Ptr authenticator) {
            if (key.Get () != 0 && cipherSuite.VerifyAuthenticatorKey (*key)) {
                std::pair<AsymmetricKeyMap::iterator, bool> result =
                    authenticatorKeyMap.insert (
                        AsymmetricKeyMap::value_type (key->GetId (), key));
                if (result.second && authenticator.Get () != 0) {
                    std::pair<AuthenticatorMap::iterator, bool> result =
                        authenticatorMap.insert (
                            AuthenticatorMap::value_type (
                                key->GetId (),
                                authenticator));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to add an Authenticator: %s.",
                            key->GetId ().ToString ().c_str ());
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

        SymmetricKey::Ptr KeyRing::GetCipherKey (
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
                    SymmetricKey::Ptr key = it->second->GetCipherKey (keyId, recursive);
                    if (key.Get () != 0) {
                        return key;
                    }
                }
            }
            return SymmetricKey::Ptr ();
        }

        SymmetricKey::Ptr KeyRing::GetCipherKey (
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
                    SymmetricKey::Ptr key = it->second->GetCipherKey (equalityTest, recursive);
                    if (key.Get () != 0) {
                        return key;
                    }
                }
            }
            return SymmetricKey::Ptr ();
        }

        Cipher::Ptr KeyRing::GetCipher (
                const ID &keyId,
                bool recursive) {
            CipherMap::const_iterator it = cipherMap.find (keyId);
            if (it != cipherMap.end ()) {
                return it->second;
            }
            SymmetricKey::Ptr key = GetCipherKey (keyId, false);
            if (key.Get () != 0) {
                Cipher::Ptr cipher =
                    cipherSuite.GetCipher (key);
                std::pair<CipherMap::iterator, bool> result =
                    cipherMap.insert (
                        CipherMap::value_type (keyId, cipher));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to add a Cipher: %s.",
                        keyId.ToString ().c_str ());
                }
                return cipher;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    Cipher::Ptr cipher =
                        it->second->GetCipher (keyId, recursive);
                    if (cipher.Get () != 0) {
                        return cipher;
                    }
                }
            }
            return Cipher::Ptr ();
        }

        Cipher::Ptr KeyRing::GetRandomCipher () {
            Cipher::Ptr cipher;
            if (!cipherKeyMap.empty ()) {
                SymmetricKeyMap::const_iterator keyIt = cipherKeyMap.begin ();
                if (cipherKeyMap.size () > 1) {
                    std::advance (
                        keyIt,
                        util::GlobalRandomSource::Instance ().Getui32 () % cipherKeyMap.size ());
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
                            keyIt->second->GetId ().ToString ().c_str ());
                    }
                }
                else {
                    cipher = cipherIt->second;
                }
            }
            return cipher;
        }

        bool KeyRing::AddCipherKey (
                SymmetricKey::Ptr key,
                Cipher::Ptr cipher) {
            if (key.Get () != 0 && cipherSuite.VerifyCipherKey (*key)) {
                std::pair<SymmetricKeyMap::iterator, bool> result =
                    cipherKeyMap.insert (
                        SymmetricKeyMap::value_type (key->GetId (), key));
                if (result.second && cipher.Get () != 0) {
                    std::pair<CipherMap::iterator, bool> result =
                        cipherMap.insert (
                            CipherMap::value_type (key->GetId (), cipher));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to add a Cipher: %s.",
                            key->GetId ().ToString ().c_str ());
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

        SymmetricKey::Ptr KeyRing::GetMACKey (
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
                    SymmetricKey::Ptr key =
                        it->second->GetMACKey (keyId, recursive);
                    if (key.Get () != 0) {
                        return key;
                    }
                }
            }
            return SymmetricKey::Ptr ();
        }

        SymmetricKey::Ptr KeyRing::GetMACKey (
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
                    SymmetricKey::Ptr key =
                        it->second->GetMACKey (equalityTest, recursive);
                    if (key.Get () != 0) {
                        return key;
                    }
                }
            }
            return SymmetricKey::Ptr ();
        }

        MAC::Ptr KeyRing::GetMAC (
                const ID &keyId,
                bool recursive) {
            MACMap::const_iterator it = macMap.find (keyId);
            if (it != macMap.end ()) {
                return it->second;
            }
            SymmetricKey::Ptr key = GetMACKey (keyId, false);
            if (key.Get () != 0) {
                MAC::Ptr mac = cipherSuite.GetHMAC (key);
                std::pair<MACMap::iterator, bool> result =
                    macMap.insert (
                        MACMap::value_type (keyId, mac));
                if (!result.second) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to add a MAC: %s.",
                        keyId.ToString ().c_str ());
                }
                return mac;
            }
            if (recursive) {
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    MAC::Ptr mac =
                        it->second->GetMAC (keyId, recursive);
                    if (mac.Get () != 0) {
                        return mac;
                    }
                }
            }
            return MAC::Ptr ();
        }

        bool KeyRing::AddMACKey (
                SymmetricKey::Ptr key,
                MAC::Ptr mac) {
            if (key.Get () != 0 && cipherSuite.VerifyMACKey (*key, true)) {
                std::pair<SymmetricKeyMap::iterator, bool> result =
                    macKeyMap.insert (
                        SymmetricKeyMap::value_type (key->GetId (), key));
                if (result.second && mac.Get () != 0) {
                    std::pair<MACMap::iterator, bool> result =
                        macMap.insert (MACMap::value_type (key->GetId (), mac));
                    if (!result.second) {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Unable to add a MAC: %s.",
                            key->GetId ().ToString ().c_str ());
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

        Serializable::Ptr KeyRing::GetUserData (
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
                    Serializable::Ptr userData =
                        it->second->GetUserData (id, recursive);
                    if (userData.Get () != 0) {
                        return userData;
                    }
                }
            }
            return Serializable::Ptr ();
        }

        Serializable::Ptr KeyRing::GetUserData (
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
                    Serializable::Ptr userData =
                        it->second->GetUserData (equalityTest, recursive);
                    if (userData.Get () != 0) {
                        return userData;
                    }
                }
            }
            return Serializable::Ptr ();
        }

        bool KeyRing::AddUserData (Serializable::Ptr userData) {
            if (userData.Get () != 0) {
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

        KeyRing::Ptr KeyRing::GetSubring (
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
                    Ptr subring = it->second->GetSubring (subringId, recursive);
                    if (subring.Get () != 0) {
                        return subring;
                    }
                }
            }
            return Ptr ();
        }

        KeyRing::Ptr KeyRing::GetSubring (
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
                    Ptr subring = it->second->GetSubring (equalityTest, recursive);
                    if (subring.Get () != 0) {
                        return subring;
                    }
                }
            }
            return Ptr ();
        }

        bool KeyRing::AddSubring (Ptr subring) {
            if (subring.Get () != 0) {
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

        std::size_t KeyRing::Size () const {
            std::size_t size = Serializable::Size () + cipherSuite.Size ();
            size += util::UI32_SIZE;
            for (ParamsMap::const_iterator
                    it = keyExchangeParamsMap.begin (),
                    end = keyExchangeParamsMap.end (); it != end; ++it) {
                size += util::Serializable::Size (*it->second);
            }
            size += util::UI32_SIZE;
            for (AsymmetricKeyMap::const_iterator
                    it = keyExchangeKeyMap.begin (),
                    end = keyExchangeKeyMap.end (); it != end; ++it) {
                size += util::Serializable::Size (*it->second);
            }
            size += util::UI32_SIZE;
            for (ParamsMap::const_iterator
                    it = authenticatorParamsMap.begin (),
                    end = authenticatorParamsMap.end (); it != end; ++it) {
                size += util::Serializable::Size (*it->second);
            }
            size += util::UI32_SIZE;
            for (AsymmetricKeyMap::const_iterator
                    it = authenticatorKeyMap.begin (),
                    end = authenticatorKeyMap.end (); it != end; ++it) {
                size += util::Serializable::Size (*it->second);
            }
            size += util::UI32_SIZE;
            for (SymmetricKeyMap::const_iterator
                    it = cipherKeyMap.begin (),
                    end = cipherKeyMap.end (); it != end; ++it) {
                size += util::Serializable::Size (*it->second);
            }
            size += util::UI32_SIZE;
            for (SymmetricKeyMap::const_iterator
                    it = macKeyMap.begin (),
                    end = macKeyMap.end (); it != end; ++it) {
                size += util::Serializable::Size (*it->second);
            }
            size += util::UI32_SIZE;
            for (SerializableMap::const_iterator
                    it = userDataMap.begin (),
                    end = userDataMap.end (); it != end; ++it) {
                size += util::Serializable::Size (*it->second);
            }
            size += util::UI32_SIZE;
            for (KeyRingMap::const_iterator
                    it = subringMap.begin (),
                    end = subringMap.end (); it != end; ++it) {
                size += util::Serializable::Size (*it->second);
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
                Params::Ptr params;
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
                AsymmetricKey::Ptr key;
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
                Params::Ptr params;
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
                AsymmetricKey::Ptr key;
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
                SymmetricKey::Ptr key;
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
                SymmetricKey::Ptr key;
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
                Serializable::Ptr userData;
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
                Ptr subring;
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
        const char * const KeyRing::TAG_CIPHER_KEYS = "CipherKeys";
        const char * const KeyRing::TAG_CIPHER_KEY = "CipherKey";
        const char * const KeyRing::TAG_MAC_KEYS = "MACKeys";
        const char * const KeyRing::TAG_MAC_KEY = "MACKey";
        const char * const KeyRing::TAG_USER_DATAS = "UserDatas";
        const char * const KeyRing::TAG_USER_DATA = "UserData";
        const char * const KeyRing::TAG_SUB_RINGS = "SubRings";
        const char * const KeyRing::TAG_SUB_RING = "SubRing";

        std::string KeyRing::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            std::stringstream stream;
            util::Attributes attributes;
            attributes.push_back (util::Attribute (ATTR_ID, id.ToString ()));
            attributes.push_back (util::Attribute (ATTR_NAME, name));
            attributes.push_back (util::Attribute (ATTR_DESCRIPTION, description));
            attributes.push_back (util::Attribute (ATTR_CIPHER_SUITE, cipherSuite.ToString ()));
            stream << util::OpenTag (indentationLevel, tagName, attributes, false, true);
            {
                stream << util::OpenTag (
                    indentationLevel + 1,
                    TAG_KEY_EXCHANGE_PARAMS,
                    util::Attributes (),
                    false,
                    true);
                for (ParamsMap::const_iterator
                        it = keyExchangeParamsMap.begin (),
                        end = keyExchangeParamsMap.end (); it != end; ++it) {
                    stream << it->second->ToString (
                        indentationLevel + 2,
                        TAG_KEY_EXCHANGE_PARAM);
                }
                stream << util::CloseTag (
                    indentationLevel + 1,
                    TAG_KEY_EXCHANGE_PARAMS);
            }
            {
                stream << util::OpenTag (
                    indentationLevel + 1,
                    TAG_KEY_EXCHANGE_KEYS,
                    util::Attributes (),
                    false,
                    true);
                for (AsymmetricKeyMap::const_iterator
                        it = keyExchangeKeyMap.begin (),
                        end = keyExchangeKeyMap.end (); it != end; ++it) {
                    stream << it->second->ToString (
                        indentationLevel + 2,
                        TAG_KEY_EXCHANGE_KEY);
                }
                stream << util::CloseTag (
                    indentationLevel + 1,
                    TAG_KEY_EXCHANGE_KEYS);
            }
            {
                stream << util::OpenTag (
                    indentationLevel + 1,
                    TAG_AUTHENTICATOR_PARAMS,
                    util::Attributes (),
                    false,
                    true);
                for (ParamsMap::const_iterator
                        it = authenticatorParamsMap.begin (),
                        end = authenticatorParamsMap.end (); it != end; ++it) {
                    stream << it->second->ToString (
                        indentationLevel + 2,
                        TAG_AUTHENTICATOR_PARAM);
                }
                stream << util::CloseTag (
                    indentationLevel + 1,
                    TAG_AUTHENTICATOR_PARAMS);
            }
            {
                stream << util::OpenTag (
                    indentationLevel + 1,
                    TAG_AUTHENTICATOR_KEYS,
                    util::Attributes (),
                    false,
                    true);
                for (AsymmetricKeyMap::const_iterator
                        it = authenticatorKeyMap.begin (),
                        end = authenticatorKeyMap.end (); it != end; ++it) {
                    stream << it->second->ToString (
                        indentationLevel + 2,
                        TAG_AUTHENTICATOR_KEY);
                }
                stream << util::CloseTag (
                    indentationLevel + 1,
                    TAG_AUTHENTICATOR_KEYS);
            }
            {
                stream << util::OpenTag (
                    indentationLevel + 1,
                    TAG_CIPHER_KEYS,
                    util::Attributes (),
                    false,
                    true);
                for (SymmetricKeyMap::const_iterator
                        it = cipherKeyMap.begin (),
                        end = cipherKeyMap.end (); it != end; ++it) {
                    stream << it->second->ToString (
                        indentationLevel + 2,
                        TAG_CIPHER_KEY);
                }
                stream << util::CloseTag (
                    indentationLevel + 1,
                    TAG_CIPHER_KEYS);
            }
            {
                stream << util::OpenTag (
                    indentationLevel + 1,
                    TAG_MAC_KEYS,
                    util::Attributes (),
                    false,
                    true);
                for (SymmetricKeyMap::const_iterator
                        it = macKeyMap.begin (),
                        end = macKeyMap.end (); it != end; ++it) {
                    stream << it->second->ToString (
                        indentationLevel + 2,
                        TAG_MAC_KEY);
                }
                stream << util::CloseTag (
                    indentationLevel + 1,
                    TAG_MAC_KEYS);
            }
            {
                stream << util::OpenTag (
                    indentationLevel + 1,
                    TAG_USER_DATAS,
                    util::Attributes (),
                    false,
                    true);
                for (SerializableMap::const_iterator
                        it = userDataMap.begin (),
                        end = userDataMap.end (); it != end; ++it) {
                    stream << it->second->ToString (
                        indentationLevel + 2,
                        TAG_USER_DATA);
                }
                stream << util::CloseTag (
                    indentationLevel + 1,
                    TAG_USER_DATAS);
            }
            {
                stream << util::OpenTag (
                    indentationLevel + 1,
                    TAG_SUB_RINGS,
                    util::Attributes (),
                    false,
                    true);
                for (KeyRingMap::const_iterator
                        it = subringMap.begin (),
                        end = subringMap.end (); it != end; ++it) {
                    stream << it->second->ToString (
                        indentationLevel + 2,
                        TAG_SUB_RING);
                }
                stream << util::CloseTag (
                    indentationLevel + 1,
                    TAG_SUB_RINGS);
            }
            stream << util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }

    } // namespace crypto
} // namespace thekogans
