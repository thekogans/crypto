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

/*
 * Written by Solar Designer <solar at openwall.com> in 2000-2011.
 * No copyright is claimed, and the software is hereby placed in the public
 * domain.  In case this attempt to disclaim copyright and place the software
 * in the public domain is deemed null and void, then the software is
 * Copyright (c) 2000-2011 Solar Designer and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 *
 * See crypt_blowfish.c for more information.
 */

#ifndef _CRYPT_BLOWFISH_H
#define _CRYPT_BLOWFISH_H

#ifdef __cplusplus
extern "C" {
#endif

extern int _crypt_output_magic (
    const char *setting,
    char *output,
    int size);
extern char *_crypt_blowfish_rn (
    const char *key,
    const char *setting,
	char *output,
    int size);
extern char *_crypt_gensalt_blowfish_rn (
    const char *prefix,
	unsigned long count,
	const char *input,
    int size,
    char *output,
    int output_size);

#ifdef __cplusplus
}
#endif

#endif
