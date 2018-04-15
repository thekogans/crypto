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

#include <string>
#include <openssl/bn.h>
#include "thekogans/util/Types.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Params.h"

namespace thekogans {
    namespace crypto {

        /// \struct EC EC.h thekogans/crypto/EC.h
        ///
        /// \brief
        /// Generate Elliptic Curve (EC) parameters using various given techniques.
        /// Call \see{Params::CreateKey} to derive the key. Use the derived key with
        /// \see{KeyExchange} to perform key exchange (ECDH[E}) and to \see{Authenticatior}
        /// to sign/verify (ECDSA).

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
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            /// \return GFp elliptic curve parameters.
            static Params::Ptr ParamsFromGFpCurve (
                const BIGNUM &p,
                const BIGNUM &a,
                const BIGNUM &b,
                const BIGNUM &gx,
                const BIGNUM &gy,
                const BIGNUM &n,
                const BIGNUM &c,
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// Generate Elliptic Curve (EC) parameters given an OpenSSL curve id
            /// (ex: NID_X9_62_prime256v1).
            /// \param[in] nid OpenSSL curve id.
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            /// \return OpenSSL named elliptic curve parameters.
            static Params::Ptr ParamsFromNamedCurve (
                util::i32 nid,
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \enum
            /// Curves found in RFC 5114.
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
            /// \brief
            /// Generate GFp elliptic curve parameters from the values found in RFC5114.
            /// \param[in] curve One of the RFC5114_CURVE_* values from above.
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            /// \return GFp elliptic curve parameters.
            static Params::Ptr ParamsFromRFC5114Curve (
                RFC5114Curve curve,
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \enum
            /// Curves found in RFC 5639.
            enum RFC5639Curve {
                /// \brief
                /// 160 bit curve.
                RFC5639_CURVE_160,
                /// \brief
                /// Twisted 160 bit curve.
                RFC5639_CURVE_160_T,
                /// \brief
                /// 192 bit curve.
                RFC5639_CURVE_192,
                /// \brief
                /// Twisted 192 bit curve.
                RFC5639_CURVE_192_T,
                /// \brief
                /// 224 bit curve.
                RFC5639_CURVE_224,
                /// \brief
                /// Twisted 224 bit curve.
                RFC5639_CURVE_224_T,
                /// \brief
                /// 256 bit curve.
                RFC5639_CURVE_256,
                /// \brief
                /// Twisted 256 bit curve.
                RFC5639_CURVE_256_T,
                /// \brief
                /// 320 bit curve.
                RFC5639_CURVE_320,
                /// \brief
                /// Twisted 320 bit curve.
                RFC5639_CURVE_320_T,
                /// \brief
                /// 384 bit curve.
                RFC5639_CURVE_384,
                /// \brief
                /// Twisted 384 bit curve.
                RFC5639_CURVE_384_T,
                /// \brief
                /// 512 bit curve.
                RFC5639_CURVE_512,
                /// \brief
                /// Twisted 512 bit curve.
                RFC5639_CURVE_512_T
            };
            /// \brief
            /// Generate GFp elliptic curve parameters from the values found in RFC5639.
            /// \param[in] curve One of the RFC5639_CURVE_* values from above.
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            /// \return GFp elliptic curve parameters.
            static Params::Ptr ParamsFromRFC5639Curve (
                RFC5639Curve curve,
                const std::string &name = std::string (),
                const std::string &description = std::string ());
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_EC_h)
