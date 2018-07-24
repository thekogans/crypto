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
#include "thekogans/crypto/OpenSSLException.h"
#include "thekogans/crypto/OpenSSLAsymmetricKey.h"
#include "thekogans/crypto/OpenSSLParams.h"

namespace thekogans {
    namespace crypto {

        #if !defined (THEKOGANS_CRYPTO_MIN_PARAMS_IN_PAGE)
            #define THEKOGANS_CRYPTO_MIN_PARAMS_IN_PAGE 16
        #endif // !defined (THEKOGANS_CRYPTO_MIN_PARAMS_IN_PAGE)

        THEKOGANS_CRYPTO_IMPLEMENT_SERIALIZABLE (
            OpenSSLParams,
            1,
            THEKOGANS_CRYPTO_MIN_PARAMS_IN_PAGE)

        OpenSSLParams::OpenSSLParams (
                EVP_PKEYPtr params_,
                const ID &id,
                const std::string &name,
                const std::string &description) :
                Params (id, name, description),
                params (std::move (params_)) {
            if (params.get () != 0) {
                const char *type = GetKeyType ();
                if (type != OPENSSL_PKEY_DH && type != OPENSSL_PKEY_DSA && type != OPENSSL_PKEY_EC) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Invalid parameters type %d.", type);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

        AsymmetricKey::Ptr OpenSSLParams::CreateKey (
                const ID &id,
                const std::string &name,
                const std::string &description) const {
            EVP_PKEY *key = 0;
            EVP_PKEY_CTXPtr ctx (
                EVP_PKEY_CTX_new (params.get (), OpenSSLInit::engine));
            if (ctx.get () != 0 &&
                    EVP_PKEY_keygen_init (ctx.get ()) == 1 &&
                    EVP_PKEY_keygen (ctx.get (), &key) == 1) {
                return AsymmetricKey::Ptr (
                    new OpenSSLAsymmetricKey (EVP_PKEYPtr (key), true, id, name, description));
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        OpenSSLParams::Ptr OpenSSLParams::LoadFromFile (
                const std::string &path,
                util::i32 type,
                pem_password_cb *passwordCallback,
                void *userData,
                const ID &id,
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
                                return Ptr (new OpenSSLParams (std::move (params), id, name, description));
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
                                return Ptr (new OpenSSLParams (std::move (params), id, name, description));
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
                                    return Ptr (new OpenSSLParams (std::move (params), id, name, description));
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

        void OpenSSLParams::Save (const std::string &path) const {
            BIOPtr bio (BIO_new_file (path.c_str (), "w+"));
            if (bio.get () != 0) {
                const char *type = GetKeyType ();
                if (type == OPENSSL_PKEY_DH) {
                    DHPtr dhParams (EVP_PKEY_get1_DH (params.get ()));
                    if (dhParams.get () == 0 ||
                            PEM_write_bio_DHparams (bio.get (), dhParams.get ()) == 0) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (type == OPENSSL_PKEY_DSA) {
                    DSAPtr dsaParams (EVP_PKEY_get1_DSA (params.get ()));
                    if (dsaParams.get () == 0 ||
                            PEM_write_bio_DSAparams (bio.get (), dsaParams.get ()) == 0) {
                        THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
                    }
                }
                else if (type == OPENSSL_PKEY_EC) {
                    EC_KEYPtr ecParams (EVP_PKEY_get1_EC_KEY (params.get ()));
                    if (ecParams.get () == 0 ||
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

        std::size_t OpenSSLParams::Size () const {
            const char *type = GetKeyType ();
            util::i32 paramsLength = 0;
            if (type == OPENSSL_PKEY_DH) {
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
            else if (type == OPENSSL_PKEY_DSA) {
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
            else if (type == OPENSSL_PKEY_EC) {
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
                Params::Size () +
                util::Serializer::Size (std::string (type)) + // type
                util::SizeT (paramsLength) + // paramsLength
                paramsLength;
        }

        void OpenSSLParams::Read (
                const Header &header,
                util::Serializer &serializer) {
            Params::Read (header, serializer);
            params.reset (EVP_PKEY_new ());
            if (params.get () != 0) {
                std::string type;
                serializer >> type;
                if (type == OPENSSL_PKEY_DH || type == OPENSSL_PKEY_DSA || type == OPENSSL_PKEY_EC) {
                    util::SizeT paramsLength;
                    serializer >> paramsLength;
                    util::SecureVector<util::ui8> paramsBuffer (paramsLength);
                    serializer.Read (&paramsBuffer[0], paramsLength);
                    const util::ui8 *paramsData = &paramsBuffer[0];
                    if (type == OPENSSL_PKEY_DH) {
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
                    else if (type == OPENSSL_PKEY_DSA) {
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
                    else if (type == OPENSSL_PKEY_EC) {
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
                        "Invalid parameters type %s.", type.c_str ());
                }
            }
            else {
                THEKOGANS_CRYPTO_THROW_OPENSSL_EXCEPTION;
            }
        }

        namespace {
            void WriteParams (
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

        void OpenSSLParams::Write (util::Serializer &serializer) const {
            Params::Write (serializer);
            util::SecureVector<util::ui8> paramsBuffer;
            WriteParams (*params, paramsBuffer);
            serializer <<
                std::string (GetKeyType ()) <<
                util::SizeT (paramsBuffer.size ());
            if (!paramsBuffer.empty ()) {
                serializer.Write (paramsBuffer.data (), paramsBuffer.size ());
            }
        }

    #if defined (THEKOGANS_CRYPTO_TESTING)
        std::string OpenSSLParams::ToString (
                std::size_t indentationLevel,
                const char *tagName) const {
            util::SecureVector<util::ui8> paramsBuffer;
            WriteParams (*params, paramsBuffer);
            std::stringstream stream;
            util::Attributes attributes;
            attributes.push_back (util::Attribute (ATTR_ID, id.ToString ()));
            attributes.push_back (util::Attribute (ATTR_NAME, name));
            attributes.push_back (util::Attribute (ATTR_DESCRIPTION, description));
            attributes.push_back (util::Attribute (ATTR_PARAMS_TYPE, GetKeyType ()));
            stream <<
                util::OpenTag (indentationLevel, tagName, attributes, false, true) <<
                std::string (paramsBuffer.begin (), paramsBuffer.end ()) << std::endl <<
                util::CloseTag (indentationLevel, tagName);
            return stream.str ();
        }
    #endif // defined (THEKOGANS_CRYPTO_TESTING)

    } // namespace crypto
} // namespace thekogans
