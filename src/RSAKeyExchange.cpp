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

#include "thekogans/util/RefCounted.h"
#include "thekogans/util/DefaultAllocator.h"
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/util/RandomSource.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/crypto/RSA.h"
#include "thekogans/crypto/Authenticator.h"
#include "thekogans/crypto/SymmetricKey.h"
#include "thekogans/crypto/RSAKeyExchange.h"

namespace thekogans {
    namespace crypto {

        std::size_t RSAKeyExchange::RSAParams::Size () const {
            return
                Params::Size () +
                util::Serializer::Size (keyId) +
                util::Serializer::Size (*buffer);
        }

        void RSAKeyExchange::RSAParams::Read (
                const Header &header,
                util::Serializer &serializer) {
            Params::Read (header, serializer);
            buffer.reset (new util::Buffer (util::NetworkEndian));
            serializer >> keyId >> *buffer;
        }

        void RSAKeyExchange::RSAParams::Write (util::Serializer &serializer) const {
            Params::Write (serializer);
            serializer << keyId << *buffer;
        }

        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (
            RSAKeyExchange::RSAParams,
            1,
            util::SpinLock,
            16,
            util::DefaultAllocator::Global)

        RSAKeyExchange::RSAKeyExchange (
                const ID &id,
                AsymmetricKey::Ptr key_,
                std::size_t secretLength,
                const void *salt,
                std::size_t saltLength,
                std::size_t keyLength,
                const EVP_MD *md,
                std::size_t count,
                const ID &keyId,
                const std::string &name,
                const std::string &description) :
                KeyExchange (id),
                key (key_) {
            if (key.Get () != 0 && key->GetType () == EVP_PKEY_RSA && !key->IsPrivate () &&
                    secretLength > 0 && md != 0 && count > 0) {
                util::SecureVector<util::ui8> secret (secretLength);
                if (util::GlobalRandomSource::Instance ().GetBytes (
                        &secret[0], secretLength) == secretLength) {
                    symmetricKey = SymmetricKey::FromSecretAndSalt (
                        &secret[0],
                        secretLength,
                        salt,
                        saltLength,
                        keyLength,
                        md,
                        count,
                        keyId,
                        name,
                        description);
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to get %u random bytes for key.",
                        secretLength);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        RSAKeyExchange::RSAKeyExchange (
                const ID &id,
                AsymmetricKey::Ptr key_,
                util::Buffer &buffer) :
                KeyExchange (id),
                key (key_) {
            if (key.Get () != 0 && key->GetType () == EVP_PKEY_RSA && key->IsPrivate ()) {
                util::Buffer::UniquePtr symmetricKeyBuffer =
                    RSA::DecryptBuffer (
                        buffer.GetReadPtr (),
                        buffer.GetDataAvailableForReading (),
                        key,
                        RSA_PKCS1_OAEP_PADDING,
                        true);
                SymmetricKey::Ptr symmetricKey;
                *symmetricKeyBuffer >> symmetricKey;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        KeyExchange::Params::Ptr RSAKeyExchange::GetParams () const {
            util::SecureBuffer symmetricKeyBuffer (
                util::NetworkEndian,
                (util::ui32)util::Serializable::Size (*symmetricKey));
            symmetricKeyBuffer << *symmetricKey;
            if (key->IsPrivate ()) {
                Authenticator authenticator (Authenticator::Sign, key);
                return Params::Ptr (
                    new RSAParams (
                        id,
                        key->GetId (),
                        authenticator.SignBuffer (
                            symmetricKeyBuffer.GetReadPtr (),
                            symmetricKeyBuffer.GetDataAvailableForReading ())));
            }
            return Params::Ptr (
                new RSAParams (
                    id,
                    key->GetId (),
                    RSA::EncryptBuffer (
                        symmetricKeyBuffer.GetReadPtr (),
                        symmetricKeyBuffer.GetDataAvailableForReading (),
                        key)));
        }

        SymmetricKey::Ptr RSAKeyExchange::DeriveSharedSymmetricKey (Params::Ptr params) const {
            if (key->IsPrivate ()) {
                return symmetricKey;
            }
            RSAParams::Ptr rsaParams =
                util::dynamic_refcounted_pointer_cast<RSAParams> (params);
            if (rsaParams.Get () != 0) {
                util::SecureBuffer symmetricKeyBuffer (
                    util::NetworkEndian,
                    (util::ui32)util::Serializable::Size (*symmetricKey));
                symmetricKeyBuffer << *symmetricKey;
                Authenticator authenticator (Authenticator::Verify, key);
                if (authenticator.VerifyBufferSignature (
                        symmetricKeyBuffer.GetReadPtr (),
                        symmetricKeyBuffer.GetDataAvailableForReading (),
                        rsaParams->buffer->GetReadPtr (),
                        rsaParams->buffer->GetDataAvailableForReading ())) {
                    return symmetricKey;
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Key (%s) failed signature verification.",
                        symmetricKey->GetId ().ToString ().c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
