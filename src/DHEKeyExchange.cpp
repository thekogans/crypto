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

#include "thekogans/util/SecureAllocator.h"
#include "thekogans/util/DefaultAllocator.h"
#include "thekogans/util/Serializable.h"
#include "thekogans/crypto/CipherSuite.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLAsymmetricKey.h"
#include "thekogans/crypto/X25519AsymmetricKey.h"
#include "thekogans/crypto/OpenSSLUtils.h"
#include "thekogans/crypto/DHEKeyExchange.h"

namespace thekogans {
    namespace crypto {

        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (
            DHEKeyExchange::DHEParams,
            1,
            util::SpinLock,
            16,
            util::DefaultAllocator::Global)

        void DHEKeyExchange::DHEParams::CreateSignature (
                AsymmetricKey::Ptr privateKey,
                MessageDigest::Ptr messageDigest) {
            if (privateKey.Get () != 0 && messageDigest.Get () != 0) {
                util::Buffer paramsBuffer (
                    util::NetworkEndian,
                    util::Serializer::Size (id) +
                    util::Serializable::Size (*params) +
                    util::Serializer::Size (salt) +
                    util::Serializer::Size (keyLength) +
                    util::Serializer::Size (messageDigestName) +
                    util::Serializer::Size (count) +
                    util::Serializer::Size (keyId) +
                    util::Serializer::Size (keyName) +
                    util::Serializer::Size (keyDescription) +
                    util::Serializable::Size (*publicKey));
                paramsBuffer <<
                    id <<
                    *params <<
                    salt <<
                    keyLength <<
                    messageDigestName <<
                    count <<
                    keyId <<
                    keyName <<
                    keyDescription <<
                    *publicKey;
                Authenticator authenticator (privateKey, messageDigest);
                signature = authenticator.SignBuffer (
                    paramsBuffer.GetReadPtr (),
                    paramsBuffer.GetDataAvailableForReading ()).Tovector ();
                signatureKeyId = privateKey->GetId ();
                signatureMessageDigestName = messageDigest->GetName ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        bool DHEKeyExchange::DHEParams::ValidateSignature (
                AsymmetricKey::Ptr publicKey,
                MessageDigest::Ptr messageDigest) {
            if (publicKey.Get () != 0 && messageDigest.Get () != 0 &&
                    publicKey->GetId () == signatureKeyId &&
                    messageDigest->GetName () == signatureMessageDigestName) {
                if (!signature.empty ()) {
                    util::Buffer paramsBuffer (
                        util::NetworkEndian,
                        util::Serializer::Size (id) +
                        util::Serializable::Size (*params) +
                        util::Serializer::Size (salt) +
                        util::Serializer::Size (keyLength) +
                        util::Serializer::Size (messageDigestName) +
                        util::Serializer::Size (count) +
                        util::Serializer::Size (keyId) +
                        util::Serializer::Size (keyName) +
                        util::Serializer::Size (keyDescription) +
                        util::Serializable::Size (*this->publicKey));
                    paramsBuffer <<
                        id <<
                        *params <<
                        salt <<
                        keyLength <<
                        messageDigestName <<
                        count <<
                        keyId <<
                        keyName <<
                        keyDescription <<
                        *this->publicKey;
                    Authenticator authenticator (publicKey, messageDigest);
                    return authenticator.VerifyBufferSignature (
                        paramsBuffer.GetReadPtr (),
                        paramsBuffer.GetDataAvailableForReading (),
                        signature.data (),
                        signature.size ());
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Params (%s) are not signed.",
                        id.ToHexString ().c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        std::size_t DHEKeyExchange::DHEParams::Size () const {
            return
                Params::Size () +
                util::Serializable::Size (*params) +
                util::Serializer::Size (salt) +
                util::Serializer::Size (keyLength) +
                util::Serializer::Size (messageDigestName) +
                util::Serializer::Size (count) +
                util::Serializer::Size (keyId) +
                util::Serializer::Size (keyName) +
                util::Serializer::Size (keyDescription) +
                util::Serializable::Size (*publicKey);
        }

        void DHEKeyExchange::DHEParams::Read (
                const BinHeader &header,
                util::Serializer &serializer) {
            Params::Read (header, serializer);
            serializer >>
                params >>
                salt >>
                keyLength >>
                messageDigestName >>
                count >>
                keyId >>
                keyName >>
                keyDescription >>
                publicKey;
        }

        void DHEKeyExchange::DHEParams::Write (util::Serializer &serializer) const {
            Params::Write (serializer);
            serializer <<
                *params <<
                salt <<
                keyLength <<
                messageDigestName <<
                count <<
                keyId <<
                keyName <<
                keyDescription <<
                *publicKey;
        }

        const char * const DHEKeyExchange::DHEParams::TAG_PARAMS = "Params";
        const char * const DHEKeyExchange::DHEParams::ATTR_SALT = "Salt";
        const char * const DHEKeyExchange::DHEParams::ATTR_KEY_LENGTH = "KeyLength";
        const char * const DHEKeyExchange::DHEParams::ATTR_MESSAGE_DIGEST_NAME = "MessageDigestName";
        const char * const DHEKeyExchange::DHEParams::ATTR_COUNT = "Count";
        const char * const DHEKeyExchange::DHEParams::ATTR_KEY_ID = "KeyId";
        const char * const DHEKeyExchange::DHEParams::ATTR_KEY_NAME = "KeyName";
        const char * const DHEKeyExchange::DHEParams::ATTR_KEY_DESCRIPTION = "KeyDescription";
        const char * const DHEKeyExchange::DHEParams::TAG_PUBLIC_KEY = "PublicKey";

        void DHEKeyExchange::DHEParams::Read (
                const TextHeader &header,
                const pugi::xml_node &node) {
            Params::Read (header, node);
            salt = util::HexDecodestring (node.attribute (ATTR_SALT).value ());
            keyLength = util::stringToui64 (node.attribute (ATTR_KEY_LENGTH).value ());
            messageDigestName = node.attribute (ATTR_MESSAGE_DIGEST_NAME).value ();
            count = util::stringToui64 (node.attribute (ATTR_COUNT).value ());
            keyId = ID::FromHexString (node.attribute (ATTR_KEY_ID).value ());
            keyName = node.attribute (ATTR_KEY_NAME).value ();
            keyDescription = node.attribute (ATTR_KEY_DESCRIPTION).value ();
            pugi::xml_node paramsNode = node.child (TAG_PARAMS);
            paramsNode >> params;
            pugi::xml_node publicKeyNode = node.child (TAG_PUBLIC_KEY);
            publicKeyNode >> publicKey;
        }

        void DHEKeyExchange::DHEParams::Write (pugi::xml_node &node) const {
            Params::Write (node);
            node.append_attribute (ATTR_SALT).set_value (util::HexEncodeBuffer (salt.data (), salt.size ()).c_str ());
            node.append_attribute (ATTR_KEY_LENGTH).set_value (util::ui64Tostring (keyLength).c_str ());
            node.append_attribute (ATTR_MESSAGE_DIGEST_NAME).set_value (messageDigestName.c_str ());
            node.append_attribute (ATTR_COUNT).set_value (util::ui64Tostring (count).c_str ());
            node.append_attribute (ATTR_KEY_ID).set_value (keyId.ToHexString ().c_str ());
            node.append_attribute (ATTR_KEY_NAME).set_value (keyName.c_str ());
            node.append_attribute (ATTR_KEY_DESCRIPTION).set_value (keyDescription.c_str ());
            pugi::xml_node paramsNode = node.append_child (TAG_PARAMS);
            paramsNode << *params;
            pugi::xml_node publicKeyNode = node.append_child (TAG_PUBLIC_KEY);
            publicKeyNode << *publicKey;
        }

        void DHEKeyExchange::DHEParams::Read (
                const TextHeader &header,
                const util::JSON::Object &object) {
            Params::Read (header, object);
            salt = util::HexDecodestring (object.Get<util::JSON::String> (ATTR_SALT)->value);
            keyLength = object.Get<util::JSON::Number> (ATTR_KEY_LENGTH)->To<util::SizeT> ();
            messageDigestName = object.Get<util::JSON::String> (ATTR_MESSAGE_DIGEST_NAME)->value;
            count = object.Get<util::JSON::Number> (ATTR_COUNT)->To<util::SizeT> ();
            keyId = ID::FromHexString (object.Get<util::JSON::String> (ATTR_KEY_ID)->value);
            keyName = object.Get<util::JSON::String> (ATTR_KEY_NAME)->value;
            keyDescription = object.Get<util::JSON::String> (ATTR_KEY_DESCRIPTION)->value;
            util::JSON::Object::Ptr paramsObject = object.Get<util::JSON::Object> (TAG_PARAMS);
            *paramsObject >> params;
            util::JSON::Object::Ptr publicKeyObject = object.Get<util::JSON::Object> (TAG_PUBLIC_KEY);
            *publicKeyObject >> publicKey;
        }

        void DHEKeyExchange::DHEParams::Write (util::JSON::Object &object) const {
            Params::Write (object);
            object.Add (ATTR_SALT, util::HexEncodeBuffer (salt.data (), salt.size ()));
            object.Add (ATTR_KEY_LENGTH, keyLength);
            object.Add (ATTR_MESSAGE_DIGEST_NAME, messageDigestName);
            object.Add (ATTR_COUNT, count);
            object.Add (ATTR_KEY_ID, keyId.ToHexString ());
            object.Add (ATTR_KEY_NAME, keyName);
            object.Add (ATTR_KEY_DESCRIPTION, keyDescription);
            util::JSON::Object::Ptr paramsObject (new util::JSON::Object);
            *paramsObject << *params;
            object.Add (TAG_PARAMS, paramsObject);
            util::JSON::Object::Ptr publicKeyObject (new util::JSON::Object);
            *publicKeyObject << *publicKey;
            object.Add (TAG_PUBLIC_KEY, publicKeyObject);
        }

        namespace {
            inline bool ValidateParamsKeyType (const char *keyType) {
                return
                    keyType == OPENSSL_PKEY_DH ||
                    keyType == OPENSSL_PKEY_EC ||
                    keyType == X25519AsymmetricKey::KEY_TYPE;
            }
        }

        DHEKeyExchange::DHEKeyExchange (
                const ID &id,
                crypto::Params::Ptr params_,
                const void *salt_,
                std::size_t saltLength_,
                std::size_t keyLength_,
                const EVP_MD *md_,
                std::size_t count_,
                const ID &keyId_,
                const std::string &keyName_,
                const std::string &keyDescription_) :
                KeyExchange (id),
                initiator (true),
                params (params_),
                salt (
                    salt_ != 0 && saltLength_ > 0 ?
                        std::vector<util::ui8> (
                            (const util::ui8 *)salt_,
                            (const util::ui8 *)salt_ + saltLength_) :
                    std::vector<util::ui8> ()),
                keyLength (keyLength_),
                messageDigestName (CipherSuite::GetOpenSSLMessageDigestName (md_)),
                count (count_),
                keyId (keyId_),
                keyName (keyName_),
                keyDescription (keyDescription_) {
            if (params.Get () != 0 && ValidateParamsKeyType (params->GetKeyType ())) {
                privateKey = params->CreateKey ();
                publicKey = privateKey->GetPublicKey ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        DHEKeyExchange::DHEKeyExchange (Params::Ptr params) :
                KeyExchange (ID::Empty),
                initiator (false) {
            DHEParams::Ptr dheParams =
                util::dynamic_refcounted_pointer_cast<DHEParams> (params);
            if (dheParams.Get () != 0 &&
                    ValidateParamsKeyType (dheParams->params->GetKeyType ())) {
                id = dheParams->id;
                this->params = dheParams->params;
                salt = dheParams->salt;
                keyLength = dheParams->keyLength;
                messageDigestName = dheParams->messageDigestName;
                count = dheParams->count;
                keyId = dheParams->keyId;
                keyName = dheParams->keyName;
                keyDescription = dheParams->keyDescription;
                privateKey = this->params->CreateKey ();
                publicKey = privateKey->GetPublicKey ();
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        KeyExchange::Params::Ptr DHEKeyExchange::GetParams (
                AsymmetricKey::Ptr privateKey,
                MessageDigest::Ptr messageDigest) const {
            Params::Ptr dheParams (
                new DHEParams (
                    id,
                    params,
                    salt,
                    keyLength,
                    messageDigestName,
                    count,
                    keyId,
                    keyName,
                    keyDescription,
                    publicKey));
            if (privateKey.Get () != 0 && messageDigest.Get () != 0) {
                dheParams->CreateSignature (privateKey, messageDigest);
            }
            return dheParams;
        }

        namespace {
            util::Buffer GetSalt (
                    const std::vector<util::ui8> &salt,
                    const AsymmetricKey &publicKey1,
                    const AsymmetricKey &publicKey2) {
                util::Buffer buffer (
                    util::NetworkEndian,
                    util::Serializer::Size (salt) +
                    util::Serializable::Size (publicKey1) +
                    util::Serializable::Size (publicKey2));
                buffer << salt << publicKey1 << publicKey2;
                return buffer;
            }
        }

        SymmetricKey::Ptr DHEKeyExchange::DeriveSharedSymmetricKey (Params::Ptr params) const {
            DHEParams::Ptr dheParams =
                util::dynamic_refcounted_pointer_cast<DHEParams> (params);
            if (dheParams.Get () != 0) {
                util::SecureVector<util::ui8> secret;
                const char *keyType = privateKey->GetKeyType ();
                if (keyType == OPENSSL_PKEY_DH || keyType == OPENSSL_PKEY_EC) {
                    EVP_PKEY_CTXPtr ctx (
                        EVP_PKEY_CTX_new (
                            ((OpenSSLAsymmetricKey *)privateKey.Get ())->key.get (),
                            OpenSSLInit::engine));
                    if (ctx.get () != 0) {
                        std::size_t secretLength = 0;
                        if (EVP_PKEY_derive_init (ctx.get ()) == 1 &&
                                EVP_PKEY_derive_set_peer (
                                    ctx.get (),
                                    ((OpenSSLAsymmetricKey *)dheParams->publicKey.Get ())->key.get ()) == 1 &&
                                EVP_PKEY_derive (ctx.get (), 0, &secretLength) == 1) {
                            secret.resize (secretLength);
                            EVP_PKEY_derive (ctx.get (), secret.data (), &secretLength);
                        }
                        else {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (keyType == X25519AsymmetricKey::KEY_TYPE) {
                    secret.resize (X25519::SHARED_SECRET_LENGTH);
                    X25519::ComputeSharedSecret (
                        ((X25519AsymmetricKey *)privateKey.Get ())->key.GetReadPtr (),
                        ((X25519AsymmetricKey *)dheParams->publicKey.Get ())->key.GetReadPtr (),
                        secret.data ());
                }
                util::Buffer salt = initiator ?
                    GetSalt (dheParams->salt, *publicKey, *dheParams->publicKey) :
                    GetSalt (dheParams->salt, *dheParams->publicKey, *publicKey);
                return SymmetricKey::FromSecretAndSalt (
                    secret.data (),
                    secret.size (),
                    salt.GetReadPtr (),
                    salt.GetDataAvailableForReading (),
                    dheParams->keyLength,
                    CipherSuite::GetOpenSSLMessageDigestByName (dheParams->messageDigestName),
                    dheParams->count,
                    dheParams->keyId,
                    dheParams->keyName,
                    dheParams->keyDescription);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
