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
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "thekogans/util/Types.h"
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/StringUtils.h"
#include "thekogans/util/XMLUtils.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLAsymmetricKey.h"
#include "thekogans/crypto/OpenSSLParams.h"

namespace thekogans {
    namespace crypto {

        #if !defined (THEKOGANS_CRYPTO_MIN_OPENSSL_PARAMS_IN_PAGE)
            #define THEKOGANS_CRYPTO_MIN_OPENSSL_PARAMS_IN_PAGE 16
        #endif // !defined (THEKOGANS_CRYPTO_MIN_OPENSSL_PARAMS_IN_PAGE)

        THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
            thekogans::crypto::OpenSSLParams,
            1,
            0,
            THEKOGANS_CRYPTO_MIN_OPENSSL_PARAMS_IN_PAGE,
            Params::TYPE)

        OpenSSLParams::OpenSSLParams (
                EVP_PKEYPtr params_,
                const ID &id,
                const std::string &name,
                const std::string &description) :
                Params (id, name, description),
                params (std::move (params_)) {
            if (params != nullptr) {
                std::string paramsType = GetKeyType ();
                if (paramsType != OPENSSL_PKEY_DH &&
                        paramsType != OPENSSL_PKEY_DSA &&
                        paramsType != OPENSSL_PKEY_EC) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Invalid parameters type %s.", paramsType.c_str ());
                }
            }
        }

        AsymmetricKey::SharedPtr OpenSSLParams::CreateKey (
                const ID &id,
                const std::string &name,
                const std::string &description) const {
            EVP_PKEY *key = 0;
            EVP_PKEY_CTXPtr ctx (
                EVP_PKEY_CTX_new (params.get (), OpenSSLInit::engine));
            if (ctx != nullptr &&
                    EVP_PKEY_keygen_init (ctx.get ()) == 1 &&
                    EVP_PKEY_keygen (ctx.get (), &key) == 1) {
                return AsymmetricKey::SharedPtr (
                    new OpenSSLAsymmetricKey (EVP_PKEYPtr (key), true, id, name, description));
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        OpenSSLParams::SharedPtr OpenSSLParams::LoadFromFile (
                const std::string &path,
                util::i32 paramsType,
                pem_password_cb *passwordCallback,
                void *userData,
                const ID &id,
                const std::string &name,
                const std::string &description) {
            if (paramsType == EVP_PKEY_DH) {
                BIOPtr bio (BIO_new_file (path.c_str (), "r"));
                if (bio != nullptr) {
                    DHPtr dhParams (
                        PEM_read_bio_DHparams (bio.get (), 0, passwordCallback, userData));
                    if (dhParams != nullptr) {
                        EVP_PKEYPtr params (EVP_PKEY_new ());
                        if (params != nullptr) {
                            if (EVP_PKEY_assign_DH (params.get (), dhParams.get ()) == 1) {
                                dhParams.release ();
                                return SharedPtr (
                                    new OpenSSLParams (std::move (params), id, name, description));
                            }
                            else {
                                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                            }
                        }
                        else {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else if (paramsType == EVP_PKEY_DSA) {
                BIOPtr bio (BIO_new_file (path.c_str (), "r"));
                if (bio != nullptr) {
                    DSAPtr dsaParams (
                        PEM_read_bio_DSAparams (bio.get (), 0, passwordCallback, userData));
                    if (dsaParams != nullptr) {
                        EVP_PKEYPtr params (EVP_PKEY_new ());
                        if (params != nullptr) {
                            if (EVP_PKEY_assign_DSA (params.get (), dsaParams.get ()) == 1) {
                                dsaParams.release ();
                                return SharedPtr (
                                    new OpenSSLParams (std::move (params), id, name, description));
                            }
                            else {
                                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                            }
                        }
                        else {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else if (paramsType == EVP_PKEY_EC) {
                BIOPtr bio (BIO_new_file (path.c_str (), "r"));
                if (bio != nullptr) {
                    EC_GROUPPtr curve (
                        PEM_read_bio_ECPKParameters (bio.get (), 0, passwordCallback, userData));
                    if (curve != nullptr) {
                        EC_KEYPtr ecParams (EC_KEY_new ());
                        if (ecParams != nullptr) {
                            EC_KEY_set_group (ecParams.get (), curve.get ());
                            EVP_PKEYPtr params (EVP_PKEY_new ());
                            if (params != nullptr) {
                                if (EVP_PKEY_assign_EC_KEY (params.get (), ecParams.get ()) == 1) {
                                    ecParams.release ();
                                    return SharedPtr (
                                        new OpenSSLParams (
                                            std::move (params), id, name, description));
                                }
                                else {
                                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                                }
                            }
                            else {
                                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                            }
                        }
                        else {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid parameters type %d.", paramsType);
            }
        }

        void OpenSSLParams::Save (const std::string &path) const {
            BIOPtr bio (BIO_new_file (path.c_str (), "w+"));
            if (bio != nullptr) {
                std::string paramsType = GetKeyType ();
                if (paramsType == OPENSSL_PKEY_DH) {
                    DHPtr dhParams (EVP_PKEY_get1_DH (params.get ()));
                    if (dhParams == nullptr ||
                            PEM_write_bio_DHparams (bio.get (), dhParams.get ()) == 0) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (paramsType == OPENSSL_PKEY_DSA) {
                    DSAPtr dsaParams (EVP_PKEY_get1_DSA (params.get ()));
                    if (dsaParams == nullptr ||
                            PEM_write_bio_DSAparams (bio.get (), dsaParams.get ()) == 0) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (paramsType == OPENSSL_PKEY_EC) {
                    EC_KEYPtr ecParams (EVP_PKEY_get1_EC_KEY (params.get ()));
                    if (ecParams == nullptr ||
                            PEM_write_bio_ECPKParameters (bio.get (),
                                EC_KEY_get0_group (ecParams.get ())) == 0) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        // NOTE: At some point I must have thought it was a good idea
        // to declare Serializable::Size noexcept. Unfortunatelly I
        // now face the delema of ignoring exceptional conditions.
        // This needs to be investigated more to see if its a problem.
        std::size_t OpenSSLParams::Size () const noexcept {
            std::string paramsType = GetKeyType ();
            util::i32 paramsLength = 0;
            if (paramsType == OPENSSL_PKEY_DH) {
                DHPtr dhParams (EVP_PKEY_get1_DH (params.get ()));
                if (dhParams != nullptr) {
                    paramsLength = i2d_DHparams (dhParams.get (), 0);
                    if (paramsLength <= 0) {
                        //THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        paramsLength = 0;
                    }
                }
                // else {
                //     THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                // }
            }
            else if (paramsType == OPENSSL_PKEY_DSA) {
                DSAPtr dsaParams (EVP_PKEY_get1_DSA (params.get ()));
                if (dsaParams != nullptr) {
                    paramsLength = i2d_DSAparams (dsaParams.get (), 0);
                    if (paramsLength <= 0) {
                        //THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        paramsLength = 0;
                    }
                }
                // else {
                //     THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                // }
            }
            else if (paramsType == OPENSSL_PKEY_EC) {
                EC_KEYPtr ecParams (EVP_PKEY_get1_EC_KEY (params.get ()));
                if (ecParams != nullptr) {
                    paramsLength = i2d_ECParameters (ecParams.get (), 0);
                    if (paramsLength <= 0) {
                        //THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        paramsLength = 0;
                    }
                }
                // else {
                //     THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                // }
            }
            return
                Params::Size () +
                util::Serializer::Size (paramsType) + // paramsType
                // * 2 is because they get hex encoded.
                util::SizeT (paramsLength * 2).Size () + // paramsLength
                paramsLength * 2;
        }

        namespace {
            EVP_PKEYPtr ReadParams (
                    const std::string &paramsType,
                    const util::SecureString &paramsBuffer) {
                EVP_PKEYPtr params (EVP_PKEY_new ());
                if (params != nullptr) {
                    if (paramsType == OPENSSL_PKEY_DH ||
                            paramsType == OPENSSL_PKEY_DSA ||
                            paramsType == OPENSSL_PKEY_EC) {
                        util::SecureVector<util::ui8> decodedParams (paramsBuffer.size () / 2);
                        util::HexDecodeBuffer (
                            paramsBuffer.data (),
                            paramsBuffer.size (),
                            decodedParams.data ());
                        const util::ui8 *paramsData = decodedParams.data ();
                        if (paramsType == OPENSSL_PKEY_DH) {
                            DHPtr dhParams (
                                d2i_DHparams (0, &paramsData, (long)decodedParams.size ()));
                            if (dhParams != nullptr) {
                                if (EVP_PKEY_assign_DH (params.get (), dhParams.get ()) == 1) {
                                    dhParams.release ();
                                }
                                else {
                                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                                }
                            }
                            else {
                                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                            }
                        }
                        else if (paramsType == OPENSSL_PKEY_DSA) {
                            DSAPtr dsaParams (
                                d2i_DSAparams (0, &paramsData, (long)decodedParams.size ()));
                            if (dsaParams != nullptr) {
                                if (EVP_PKEY_assign_DSA (params.get (), dsaParams.get ()) == 1) {
                                    dsaParams.release ();
                                }
                                else {
                                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                                }
                            }
                            else {
                                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                            }
                        }
                        else if (paramsType == OPENSSL_PKEY_EC) {
                            EC_KEYPtr ecParams (
                                d2i_ECParameters (0, &paramsData, (long)decodedParams.size ()));
                            if (ecParams != nullptr) {
                                if (EVP_PKEY_assign_EC_KEY (params.get (), ecParams.get ()) == 1) {
                                    ecParams.release ();
                                }
                                else {
                                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                                }
                            }
                            else {
                                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                            }
                        }
                        return params;
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Invalid parameters type %s.", paramsType.c_str ());
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
        }

        void OpenSSLParams::Read (
                const util::SerializableHeader &header,
                util::Serializer &serializer) {
            Params::Read (header, serializer);
            std::string paramsType;
            util::SecureString paramsBuffer;
            serializer >> paramsType >> paramsBuffer;
            params = ReadParams (paramsType, paramsBuffer);
        }

        namespace {
            util::SecureString WriteParams (EVP_PKEY &params) {
                util::SecureVector<util::ui8> paramsBuffer;
                util::i32 paramsType = EVP_PKEY_base_id (&params);
                if (paramsType == EVP_PKEY_DH) {
                    DHPtr dhParams (EVP_PKEY_get1_DH (&params));
                    if (dhParams != nullptr) {
                        util::i32 paramsLength = i2d_DHparams (dhParams.get (), 0);
                        if (paramsLength > 0) {
                            paramsBuffer.resize (paramsLength);
                            util::ui8 *paramsData = paramsBuffer.data ();
                            i2d_DHparams (dhParams.get (), &paramsData);
                        }
                        else {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (paramsType == EVP_PKEY_DSA) {
                    DSAPtr dsaParams (EVP_PKEY_get1_DSA (&params));
                    if (dsaParams != nullptr) {
                        util::i32 paramsLength = i2d_DSAparams (dsaParams.get (), 0);
                        if (paramsLength > 0) {
                            paramsBuffer.resize (paramsLength);
                            util::ui8 *paramsData = paramsBuffer.data ();
                            i2d_DSAparams (dsaParams.get (), &paramsData);
                        }
                        else {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (paramsType == EVP_PKEY_EC) {
                    EC_KEYPtr ecParams (EVP_PKEY_get1_EC_KEY (&params));
                    if (ecParams != nullptr) {
                        util::i32 paramsLength = i2d_ECParameters (ecParams.get (), 0);
                        if (paramsLength > 0) {
                            paramsBuffer.resize (paramsLength);
                            util::ui8 *paramsData = paramsBuffer.data ();
                            i2d_ECParameters (ecParams.get (), &paramsData);
                        }
                        else {
                            THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                        }
                    }
                    else {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Invalid parameters type %d.", paramsType);
                }
                util::SecureString encodedParams;
                encodedParams.resize (paramsBuffer.size () * 2);
                util::HexEncodeBuffer (paramsBuffer.data (), paramsBuffer.size (), &encodedParams[0]);
                return encodedParams;
            }
        }

        void OpenSSLParams::Write (util::Serializer &serializer) const {
            Params::Write (serializer);
            serializer << GetKeyType () << WriteParams (*params);
        }

        const char * const OpenSSLParams::ATTR_PARAMS_TYPE = "ParamsType";
        const char * const OpenSSLParams::ATTR_PARAMS = "Params";

        void OpenSSLParams::ReadXML (
                const util::SerializableHeader &header,
                const pugi::xml_node &node) {
            Params::ReadXML (header, node);
            params = ReadParams (
                node.attribute (ATTR_PARAMS_TYPE).value (),
                node.attribute (ATTR_PARAMS).value ());
        }

        void OpenSSLParams::WriteXML (pugi::xml_node &node) const {
            Params::WriteXML (node);
            node.append_attribute (ATTR_PARAMS_TYPE).set_value (GetKeyType ().c_str ());
            node.append_attribute (ATTR_PARAMS).set_value (WriteParams (*params).c_str ());
        }

        void OpenSSLParams::ReadJSON (
                const util::SerializableHeader &header,
                const util::JSON::Object &object) {
            Params::ReadJSON (header, object);
            params = ReadParams (
                object.Get<util::JSON::String> (ATTR_PARAMS_TYPE)->value,
                object.Get<util::JSON::String> (ATTR_PARAMS)->value.c_str ());
        }

        void OpenSSLParams::WriteJSON (util::JSON::Object &object) const {
            Params::WriteJSON (object);
            object.Add<const std::string &> (ATTR_PARAMS_TYPE, GetKeyType ());
            object.Add<const std::string &> (ATTR_PARAMS, WriteParams (*params).c_str ());
        }

    } // namespace crypto
} // namespace thekogans
