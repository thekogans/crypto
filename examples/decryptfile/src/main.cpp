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

#include <iostream>
#include <CppUnitXLite/CppUnitXLite.cpp>
#include "thekogans/util/Exception.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/DH.h"
#include "thekogans/crypto/DSA.h"
#include "thekogans/crypto/EC.h"

using namespace thekogans;

namespace {
    bool operator == (
            const crypto::Params &params1,
            const crypto::Params &params2) {
        util::Buffer params1Buffer (util::HostEndian, util::Serializable::Size (params1));
        params1Buffer << params1;
        util::Buffer params2Buffer (util::HostEndian, util::Serializable::Size (params2));
        params2Buffer << params2;
        return params1Buffer.GetDataAvailableForReading () == params2Buffer.GetDataAvailableForReading () &&
            memcmp (
                params1Buffer.GetReadPtr (),
                params2Buffer.GetReadPtr (),
                params1Buffer.GetDataAvailableForReading ()) == 0;
    }

    bool TestParams (
            const char *paramsName,
            crypto::Params::SharedPtr params1) {
        THEKOGANS_UTIL_TRY {
            std::cout << paramsName << "...";
            util::Buffer buffer (
                util::NetworkEndian,
                util::Serializable::Size (*params1));
            buffer << *params1;
            crypto::Params::SharedPtr params2;
            buffer >> params2;
            bool result = *params1 == *params2;
            std::cout << (result ? "pass" : "fail") << std::endl;
            return result;
        }
        THEKOGANS_UTIL_CATCH (util::Exception) {
            std::cout << "fail " << exception.Report ();
            return false;
        }
    }
}

int main (int, const char *[]) {
    crypto::OpenSSLInit openSSLInit;
        TestParams (
            "crypto::DH::ParamsFromPrimeLengthAndGenerator (512)",
            crypto::DH::ParamsFromPrimeLengthAndGenerator (512));
        /*
        TestParams (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_1536)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_1536));
        TestParams (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_2048)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_2048));
        TestParams (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_3072)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_3072));
        TestParams (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_4096)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_4096));
        TestParams (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_6144)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_6144));
        TestParams (
            "crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_8192)",
            crypto::DH::ParamsFromRFC3526Prime (crypto::DH::RFC3526_PRIME_8192));
    // crypto::DH::RFC5114Prime
        TestParams (
            "crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_1024)",
            crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_1024));
        TestParams (
            "crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_224)",
            crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_224));
        TestParams (
            "crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_256)",
            crypto::DH::ParamsFromRFC5114Prime (crypto::DH::RFC5114_PRIME_2048_256));
}       TestParams (
            "crypto::DSA::ParamsFromKeyLength (512)",
            crypto::DSA::ParamsFromKeyLength (512));
        TestParams (
            "crypto::EC::ParamsFromNamedCurve (NID_X9_62_prime256v1)",
            crypto::EC::ParamsFromNamedCurve (NID_X9_62_prime256v1))
        TestParams (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_192)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_192));
        TestParams (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_224)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_224));
        TestParams (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_256)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_256));
        TestParams (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_384)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_384));
        TestParams (
            "crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_521)",
            crypto::EC::ParamsFromRFC5114Curve (crypto::EC::RFC5114_CURVE_521));
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160))
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_160_T))
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192))
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_192_T));
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224))
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_224_T))
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256))
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_256_T))
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320))
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_320_T))
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384))
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_384_T))
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512))
        TestParams (
            "crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512_T)",
            crypto::EC::ParamsFromRFC5639Curve (crypto::EC::RFC5639_CURVE_512_T));
        TestParams (
            "crypto::EC::ParamsFromEd25519Curve ()",
            crypto::EC::ParamsFromEd25519Curve ());
        TestParams (
            "crypto::EC::ParamsFromX25519Curve ()",
            crypto::EC::ParamsFromX25519Curve ());
            */
        return 0;
}
