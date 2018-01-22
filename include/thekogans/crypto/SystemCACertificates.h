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

#include <list>
#include <openssl/ssl.h>
#include "thekogans/util/Singleton.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/crypto/Config.h"
#include "thekogans/crypto/OpenSSLUtils.h"

namespace thekogans {
    namespace crypto {

        /// \struct SystemCACertificates SystemCACertificates.h thekogans/crypto/SystemCACertificates.h
        ///
        /// \brief
        /// Expose the system CA certificates provided by various OS. On Windows, use
        /// the HCERTSTORE api. On OS X use SecTrustSettingsCopyCertificates api. On
        /// Linux use the various system paths to load certificates and/or bundle files.

        struct _LIB_THEKOGANS_CRYPTO_DECL SystemCACertificates :
                public util::Singleton<SystemCACertificates, util::SpinLock> {
        private:
            /// \brief
            /// List of system CA certificates.
            std::list<X509Ptr> certificates;
            /// \brief
            /// Synchronization lock.
            util::SpinLock spinLock;

        public:
            /// \brief
            /// ctor
            SystemCACertificates () {}

            /// \brief
            /// Load system CA certificates.
            /// \param[in] loadSystemRootCACertificatesOnly Load only root CA (self signed) certificates.
            void Load (bool loadSystemRootCACertificatesOnly = true);

            /// \brief
            /// Load system CA certificates in to the X509_STORE of the given context.
            /// \param[in] ctx Context where to load the certificates.
            void Use (SSL_CTX *ctx);
            /// \brief
            /// Empty the certificates list.
            void Flush ();

            /// \brief
            /// SystemCACertificates is neither copy constructable, nor assignable.
            THEKOGANS_CRYPTO_DISALLOW_COPY_AND_ASSIGN (SystemCACertificates)
        };

    } // namespace crypto
} // namespace thekogans
