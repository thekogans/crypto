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

#if !defined (__thekogans_crypto_EC_h)
#define __thekogans_crypto_EC_h

#include <openssl/bn.h>
#include <openssl/evp.h>
#include "thekogans/util/Serializer.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct EC EC.h thekogans/crypto/EC.h
        ///
        /// \brief
        /// Generate Elliptic Curve (EC) parameters using various given techniques.
        /// Pass the resulting parameters to \see{AsymmetricKey::FromParams} to derive
        /// the key. Use the derived key with \see{KeyExchange} to perform key exchange
        /// (ECDH[E}) and to \see{Authenticatior} to sign/verify (ECDSA).

        struct _LIB_THEKOGANS_CRYPTO_DECL EC {
            /// \brief
            /// Generate parameters from the given GFp curve values.
            /// \param[in] p Prime.
            /// \param[in] a Elliptic curve a factor.
            /// \param[in] b Elliptic curve b factor.
            /// \param[in] gx Generator point x component.
            /// \param[in] gy Generator point y component.
            /// \param[in] n Group order.
            /// \param[in] c Curve co-factor.
            /// \return GFp elliptic curve parameters.
            static EVP_PKEYPtr ParamsFromGFpCurve (
                const BIGNUM &p,
                const BIGNUM &a,
                const BIGNUM &b,
                const BIGNUM &gx,
                const BIGNUM &gy,
                const BIGNUM &n,
                const BIGNUM &c);

            /// \brief
            /// Generate Elliptic Curve (EC) parameters given an OpenSSL curve id
            /// (ex: NID_X9_62_prime256v1).
            /// \param[in] nid OpenSSL curve id.
            /// \return OpenSSL named elliptic curve parameters.
            static EVP_PKEYPtr ParamsFromNamedCurve (util::i32 nid);

            enum RFC5114Curve {
                /// \brief
                /// 192 bit curve.
                RFC5114_CURVE_192,
                /// \brief
                /// 224 bit curve.
                RFC5114_CURVE_224,
                /// \brief
                /// 256 bit curve.
                RFC5114_CURVE_256,
                /// \brief
                /// 384 bit curve.
                RFC5114_CURVE_384,
                /// \brief
                /// 521 bit curve.
                RFC5114_CURVE_521
            };
            /// Generate GFp elliptic curve parameters from the values found in RFC5114.
            /// \param[in] curve One of the RFC5114_CURVE_* values from above.
            /// \return GFp elliptic curve parameters.
            static EVP_PKEYPtr ParamsFromRFC5114Curve (RFC5114Curve curve);

            enum RFC5639Curve {
                /// \brief
                /// 2D 160 bit curve.
                RFC5639_CURVE_160,
                /// \brief
                /// 3D 160 bit curve.
                RFC5639_CURVE_160_T,
                /// \brief
                /// 2D 192 bit curve.
                RFC5639_CURVE_192,
                /// \brief
                /// 3D 192 bit curve.
                RFC5639_CURVE_192_T,
                /// \brief
                /// 2D 224 bit curve.
                RFC5639_CURVE_224,
                /// \brief
                /// 3D 224 bit curve.
                RFC5639_CURVE_224_T,
                /// \brief
                /// 2D 256 bit curve.
                RFC5639_CURVE_256,
                /// \brief
                /// 3D 256 bit curve.
                RFC5639_CURVE_256_T,
                /// \brief
                /// 2D 320 bit curve.
                RFC5639_CURVE_320,
                /// \brief
                /// 3D 320 bit curve.
                RFC5639_CURVE_320_T,
                /// \brief
                /// 2D 384 bit curve.
                RFC5639_CURVE_384,
                /// \brief
                /// 3D 384 bit curve.
                RFC5639_CURVE_384_T,
                /// \brief
                /// 2D 512 bit curve.
                RFC5639_CURVE_512,
                /// \brief
                /// 3D 512 bit curve.
                RFC5639_CURVE_512_T
            };
            /// Generate GFp elliptic curve parameters from the values found in RFC5639.
            /// \param[in] curve One of the RFC5639_CURVE_* values from above.
            /// \return GFp elliptic curve parameters.
            static EVP_PKEYPtr ParamsFromRFC5639Curve (RFC5639Curve curve);

            /// \brief
            /// Save above generated parameters to a buffer.
            /// \param[in] params DSA parameters generated by ParamsFromKeyLength.
            /// \return Buffer containing the serialized parameters that can be put
            /// on the wire or written to disk.
            static util::Buffer::UniquePtr SaveParams (EVP_PKEY &params);
            /// \brief
            /// Load previously saved EC parameters.
            /// \param[in] serializer \see{util::Serializer} containing the saved EC parameters.
            /// \return Reconstituted EC parameters.
            static EVP_PKEYPtr LoadParams (util::Serializer &serializer);
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_EC_h)
