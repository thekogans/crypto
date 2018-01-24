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
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "thekogans/util/Types.h"
#include "thekogans/util/SecureAllocator.h"
#include "thekogans/util/Exception.h"
#if defined (THEKOGANS_CRYPTO_TESTING)
    #include "thekogans/util/StringUtils.h"
    #include "thekogans/util/XMLUtils.h"
#endif // defined (THEKOGANS_CRYPTO_TESTING)
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/Params.h"

namespace thekogans {
    namespace crypto {

        #if !defined (THEKOGANS_CRYPTO_MIN_PARAMS_IN_PAGE)
            #define THEKOGANS_CRYPTO_MIN_PARAMS_IN_PAGE 16
        #endif // !defined (THEKOGANS_CRYPTO_MIN_PARAMS_IN_PAGE)

        THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
            Params,
            THEKOGANS_CRYPTO_MIN_PARAMS_IN_PAGE)

        Params::Params (
                EVP_PKEYPtr params_,
                const std::string &name,
                const std::string &description) :
                Serializable (name, description),
                params (std::move (params_)) {
            if (params.get () != 0) {
                util::i32 type = EVP_PKEY_base_id (params.get ());
                if (type != EVP_PKEY_DH && type != EVP_PKEY_DSA && type != EVP_PKEY_EC) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Invalid parameters type %d.", type);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        Params::Params (util::Serializer &serializer) :
                Serializable (serializer),
                params (EVP_PKEY_new ()) {
            if (params.get () != 0) {
                util::i32 type;
                serializer >> type;
                if (type == EVP_PKEY_DH || type == EVP_PKEY_DSA || type == EVP_PKEY_EC) {
                    util::i32 paramsLength;
                    serializer >> paramsLength;
                    util::SecureVector<util::ui8> paramsBuffer (paramsLength);
                    serializer.Read (&paramsBuffer[0], paramsLength);
                    const util::ui8 *paramsData = &paramsBuffer[0];
                    if (type == EVP_PKEY_DH) {
                        DHPtr dhParams (d2i_DHparams (0, &paramsData, paramsLength));
                        if (dhParams.get () != 0) {
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
                    else if (type == EVP_PKEY_DSA) {
                        DSAPtr dsaParams (d2i_DSAparams (0, &paramsData, paramsLength));
                        if (dsaParams.get () != 0) {
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
                    else if (type == EVP_PKEY_EC) {
                        EC_KEYPtr ecParams (d2i_ECParameters (0, &paramsData, paramsLength));
                        if (ecParams.get () != 0) {
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
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Invalid parameters type %d.", type);
                }
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        AsymmetricKey::Ptr Params::CreateKey (
                const std::string &name,
                const std::string &description) const {
            EVP_PKEY *key = 0;
            EVP_PKEY_CTXPtr ctx (
                EVP_PKEY_CTX_new (params.get (), OpenSSLInit::engine));
            if (ctx.get () != 0 &&
                    EVP_PKEY_keygen_init (ctx.get ()) == 1 &&
                    EVP_PKEY_keygen (ctx.get (), &key) == 1) {
                return AsymmetricKey::Ptr (
                    new AsymmetricKey (EVP_PKEYPtr (key), true, name, description));
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        Params::Ptr Params::LoadFromFile (
                const std::string &path,
                util::i32 type,
                pem_password_cb *passwordCallback,
                void *userData,
                const std::string &name,
                const std::string &description) {
            if (type == EVP_PKEY_DH) {
                BIOPtr bio (BIO_new_file (path.c_str (), "r"));
                if (bio.get () != 0) {
                    DHPtr dhParams (PEM_read_bio_DHparams (bio.get (), 0, passwordCallback, userData));
                    if (dhParams.get () != 0) {
                        EVP_PKEYPtr params (EVP_PKEY_new ());
                        if (params.get () != 0) {
                            if (EVP_PKEY_assign_DH (params.get (), dhParams.get ()) == 1) {
                                dhParams.release ();
                                return Ptr (new Params (std::move (params), name, description));
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
            else if (type == EVP_PKEY_DSA) {
                BIOPtr bio (BIO_new_file (path.c_str (), "r"));
                if (bio.get () != 0) {
                    DSAPtr dsaParams (PEM_read_bio_DSAparams (bio.get (), 0, passwordCallback, userData));
                    if (dsaParams.get () != 0) {
                        EVP_PKEYPtr params (EVP_PKEY_new ());
                        if (params.get () != 0) {
                            if (EVP_PKEY_assign_DSA (params.get (), dsaParams.get ()) == 1) {
                                dsaParams.release ();
                                return Ptr (new Params (std::move (params), name, description));
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
            else if (type == EVP_PKEY_EC) {
                BIOPtr bio (BIO_new_file (path.c_str (), "r"));
                if (bio.get () != 0) {
                    EC_GROUPPtr curve (PEM_read_bio_ECPKParameters (bio.get (), 0, passwordCallback, userData));
                    if (curve.get () != 0) {
                        EC_KEYPtr ecParams (EC_KEY_new ());
                        if (ecParams.get () != 0) {
                            EC_KEY_set_group (ecParams.get (), curve.get ());
                            EVP_PKEYPtr params (EVP_PKEY_new ());
                            if (params.get () != 0) {
                                if (EVP_PKEY_assign_EC_KEY (params.get (), ecParams.get ()) == 1) {
                                    ecParams.release ();
                                    return Params::Ptr (new Params (std::move (params), name, description));
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
                    "Invalid parameters type %d.", type);
            }
        }

        std::size_t Params::Size (bool includeType) const {
            util::i32 type = EVP_PKEY_base_id (params.get ());
            util::i32 paramsLength = 0;
            if (type == EVP_PKEY_DH) {
                DHPtr dhParams (EVP_PKEY_get1_DH (params.get ()));
                if (dhParams.get () != 0) {
                    paramsLength = i2d_DHparams (dhParams.get (), 0);
                    if (paramsLength <= 0) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else if (type == EVP_PKEY_DSA) {
                DSAPtr dsaParams (EVP_PKEY_get1_DSA (params.get ()));
                if (dsaParams.get () != 0) {
                    paramsLength = i2d_DSAparams (dsaParams.get (), 0);
                    if (paramsLength <= 0) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            else if (type == EVP_PKEY_EC) {
                EC_KEYPtr ecParams (EVP_PKEY_get1_EC_KEY (params.get ()));
                if (ecParams.get () != 0) {
                    paramsLength = i2d_ECParameters (ecParams.get (), 0);
                    if (paramsLength <= 0) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else {
                    THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                }
            }
            return
                Serializable::Size (includeType) +
                util::I32_SIZE + // type
                util::I32_SIZE + // paramsLength
                paramsLength;
        }

        namespace {
            void SerializeParams (
                    EVP_PKEY &params,
                    util::SecureVector<util::ui8> &paramsBuffer) {
                util::i32 type = EVP_PKEY_base_id (&params);
                if (type == EVP_PKEY_DH) {
                    DHPtr dhParams (EVP_PKEY_get1_DH (&params));
                    if (dhParams.get () != 0) {
                        util::i32 paramsLength = i2d_DHparams (dhParams.get (), 0);
                        if (paramsLength > 0) {
                            paramsBuffer.resize (paramsLength);
                            util::ui8 *paramsData = &paramsBuffer[0];
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
                else if (type == EVP_PKEY_DSA) {
                    DSAPtr dsaParams (EVP_PKEY_get1_DSA (&params));
                    if (dsaParams.get () != 0) {
                        util::i32 paramsLength = i2d_DSAparams (dsaParams.get (), 0);
                        if (paramsLength > 0) {
                            paramsBuffer.resize (paramsLength);
                            util::ui8 *paramsData = &paramsBuffer[0];
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
                else if (type == EVP_PKEY_EC) {
                    EC_KEYPtr ecParams (EVP_PKEY_get1_EC_KEY (&params));
                    if (ecParams.get () != 0) {
                        util::i32 paramsLength = i2d_ECParameters (ecParams.get (), 0);
                        if (paramsLength > 0) {
                            paramsBuffer.resize (paramsLength);
                            util::ui8 *paramsData = &paramsBuffer[0];
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
            }
        }

        void Params::Serialize (
                util::Serializer &serializer,
                bool includeType) const {
            Serializable::Serialize (serializer, includeType);
            util::SecureVector<util::ui8> paramsBuffer;
            SerializeParams (*params, paramsBuffer);
            serializer <<
                (util::i32)EVP_PKEY_base_id (params.get ()) <<
                (util::i32)paramsBuffer.size ();
            serializer.Write (&paramsBuffer[0], (util::i32)paramsBuffer.size ());
        }

    #if defined (THEKOGANS_CRYPTO_TESTING)
        const char * const Params::ATTR_PARAMS_TYPE = "ParamsType";

        namespace {
            std::string typeTostring (util::i32 type) {
                switch (type) {
                    case EVP_PKEY_DH:
                        return "DH";
                    case EVP_PKEY_DSA:
                        return "DSA";
                    case EVP_PKEY_EC:
                        return "EC";
                }
                return "unknown";
            }
        }

        std::string Params::ToString (
                util::ui32 indentationLevel,
                const char *tagName) const {
            util::SecureVector<util::ui8> paramsBuffer;
            SerializeParams (*params, paramsBuffer);
            std::stringstream stream;
            util::Attributes attributes;
            attributes.push_back (util::Attribute (ATTR_ID, id.ToString ()));
            attributes.push_back (util::Attribute (ATTR_NAME, name));
            attributes.push_back (util::Attribute (ATTR_DESCRIPTION, description));
            attributes.push_back (util::Attribute (ATTR_PARAMS_TYPE, typeTostring (EVP_PKEY_base_id (key.get ()))));
            stream <<
                util::OpenTag (indentationLevel, tagName, attributes, false, true) <<
                std::string (paramsBuffer.begin (), paramsBuffer.end ()) << std::endl <<
                util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

    } // namespace crypto
} // namespace thekogans
