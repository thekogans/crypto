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

#if defined (TOOLCHAIN_OS_Windows)
    #include <winsock2.h>
#endif // defined (TOOLCHAIN_OS_Windows)
#include "thekogans/util/CommandLineOptions.h"
#include "thekogans/util/LoggerMgr.h"
#include "thekogans/util/ConsoleLogger.h"
#include "thekogans/util/Exception.h"
#include "thekogans/util/File.h"
#include "thekogans/util/Base64.h"
#include "thekogans/crypto/OpenSSLInit.h"
#include "thekogans/crypto/AsymmetricKey.h"
#include "thekogans/crypto/Authenticator.h"

using namespace thekogans;

int main (
        int argc,
        const char *argv[]) {
    struct Options : public util::CommandLineOptions {
        bool help;
        std::string publicKey;
        std::string path;

        Options () :
            help (false) {}

        virtual void DoOption (
                char option,
                const std::string &value) {
            switch (option) {
                case 'h': {
                    help = true;
                    break;
                }
                case 'p': {
                    publicKey = value;
                    break;
                }
            }
        }
        virtual void DoPath (const std::string &value) {
            path = value;
        }
    } options;
    options.Parse (argc, argv, "hp");
    if (options.help || options.publicKey.empty () || options.path.empty ()) {
        std::cout << "usage: " << argv[0] << " [-h] -p:'public key path' path" << std::endl;
        return 1;
    }
    THEKOGANS_UTIL_LOG_INIT (
        util::LoggerMgr::Debug,
        util::LoggerMgr::All);
    THEKOGANS_UTIL_LOG_ADD_LOGGER (util::Logger::Ptr (new util::ConsoleLogger));
    THEKOGANS_UTIL_TRY {
        crypto::OpenSSLInit openSSLInit;
        std::cout << "Verifying '" << options.path << "'...";
        crypto::Authenticator authenticator (
            crypto::Authenticator::Verify,
            crypto::AsymmetricKey::LoadPublicKeyFromFile (options.publicKey));
        util::ReadOnlyFile signatureFile (util::HostEndian, options.path + ".sig");
        util::Buffer encodedSignature (util::NetworkEndian, signatureFile.GetSize ());
        encodedSignature.AdvanceWriteOffset (
            signatureFile.Read (
                encodedSignature.GetWritePtr (),
                encodedSignature.GetDataAvailableForWriting ()));
        util::Buffer::UniquePtr signature =
            util::Base64::Decode (
                encodedSignature.GetReadPtr (),
                encodedSignature.GetDataAvailableForReading ());
        bool result = authenticator.VerifyFileSignature (
            options.path,
            signature->GetReadPtr (),
            signature->GetDataAvailableForReading ());
        std::cout << (result ? "Passed" : "Failed") << std::endl;
    }
    THEKOGANS_UTIL_CATCH_AND_LOG
    THEKOGANS_UTIL_LOG_FLUSH
    return 0;
}
