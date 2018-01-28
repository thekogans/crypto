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

#if !defined (__thekogans_crypto_DH_h)
#define __thekogans_crypto_DH_h

#include <openssl/dh.h>
#include <openssl/bn.h>
#include "thekogans/util/Serializer.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/Params.h"

namespace thekogans {
    namespace crypto {

        /// \struct DH DH.h thekogans/crypto/DH.h
        ///
        /// \brief
        /// Generate Diffie-Hellman (DH) parameters (prime and generator) using various
        /// given techniques. Call \see{Params::CreateKey} to derive the key.
        /// Use the derived key to perform \see{KeyExchange}.

        struct _LIB_THEKOGANS_CRYPTO_DECL DH {
            /// \brief
            /// Generate a fresh prime given the prime length. This method is by far
            /// the slowest as finding suitable primes for DH is not easy.
            /// \param[in] primeLength Length of prime to generate.
            /// \param[in] generator DH generator.
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            /// \return DH parameters suitable for key and shared secret generation.
            static Params::Ptr ParamsFromPrimeLengthAndGenerator (
                std::size_t primeLength,
                std::size_t generator = DH_GENERATOR_2,
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \brief
            /// Generate DH parameters from a given prime and generator.
            /// WARNING: Not every prime is a DH prime. They are fairly difficult to
            /// generate and take a long time. You are strongly encouraged to use
            /// RFC3526Prime or RFC5114Prime (below) as these primes have been vetted
            /// by the community and are considered safe.
            /// \param[in] prime DH prime.
            /// \param[in] generator DH generator.
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            /// \return DH parameters suitable for key and shared secret generation.
            static Params::Ptr ParamsFromPrimeAndGenerator (
                BIGNUM &prime,
                BIGNUM &generator,
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \enum
            /// Primes found in RFC 3526.
            enum RFC3526Prime {
                /// \brief
                /// 1536 bit prime.
                RFC3526_PRIME_1536,
                /// \brief
                /// 2048 bit prime.
                RFC3526_PRIME_2048,
                /// \brief
                /// 3072 bit prime.
                RFC3526_PRIME_3072,
                /// \brief
                /// 4096 bit prime.
                RFC3526_PRIME_4096,
                /// \brief
                /// 6144 bit prime.
                RFC3526_PRIME_6144,
                /// \brief
                /// 8192 bit prime.
                RFC3526_PRIME_8192
            };
            /// \brief
            /// Generate DH parameters from primes found in RFC 3526.
            /// NOTE: No generator parameter is required as the RFC
            /// specifies that generator = 2.
            /// \param[in] prime One of RFC3526_PRIME_* values above.
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            /// \return DH parameters suitable for key and shared secret generation.
            static Params::Ptr ParamsFromRFC3526Prime (
                RFC3526Prime prime,
                const std::string &name = std::string (),
                const std::string &description = std::string ());

            /// \enum
            /// Primes found in RFC 5114.
            enum RFC5114Prime {
                /// \brief
                /// 1024 bit prime with 160-bit Prime Order Subgroup.
                RFC5114_PRIME_1024,
                /// \brief
                /// 2048 bit prime with 224-bit Prime Order Subgroup.
                RFC5114_PRIME_2048_224,
                /// \brief
                /// 2048 bit prime with 256-bit Prime Order Subgroup.
                RFC5114_PRIME_2048_256
            };
            /// \brief
            /// Generate DH parameters from primes found in RFC 5114.
            /// NOTE: No generator parameter is required as the RFC
            /// prescribes specific generators for each prime size.
            /// \param[in] prime One of RFC5114_PRIME_* values above.
            /// \param[in] name Optional parameters name.
            /// \param[in] description Optional parameters description.
            /// \return DH parameters suitable for key and shared secret generation.
            static Params::Ptr ParamsFromRFC5114Prime (
                RFC5114Prime prime,
                const std::string &name = std::string (),
                const std::string &description = std::string ());
        };

    } // namespace crypto
} // namespace thekogans

#endif // !defined (__thekogans_crypto_DH_h)
