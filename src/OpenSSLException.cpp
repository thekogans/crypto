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

#include <openssl/err.h>
#include "thekogans/crypto/OpenSSLException.h"

namespace thekogans {
    namespace crypto {

        _LIB_THEKOGANS_CRYPTO_DECL util::Exception _LIB_THEKOGANS_CRYPTO_API
        CreateOpenSSLException (
                const char *file,
                const char *function,
                util::ui32 line,
                const char *buildTime,
                const char *message) {
            if (file != 0 && function != 0 && buildTime != 0 && message != 0) {
                THEKOGANS_UTIL_ERROR_CODE errorCode = ERR_get_error ();
                char buffer[256];
                ERR_error_string_n (errorCode, buffer, sizeof (buffer));
                util::Exception exception (file, function, line, buildTime,
                    errorCode, util::FormatString ("[0x%x:%d - %s]%s",
                        errorCode, errorCode, buffer, message));
                while ((errorCode = ERR_get_error_line (&file, (util::i32 *)&line)) != 0) {
                    exception.NoteLocation (file, "", line, "");
                }
                return exception;
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace crypto
} // namespace thekogans
