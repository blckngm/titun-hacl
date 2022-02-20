/* MIT License
 *
 * Copyright (c) 2016-2020 INRIA, CMU and Microsoft Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#ifndef __Hacl_Hash_Base_H
#define __Hacl_Hash_Base_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "evercrypt_targetconfig.h"
#include "libintvector.h"
#include "kremlin/internal/types.h"
#include "kremlin/lowstar_endianness.h"
#include <string.h>
#include "kremlin/internal/target.h"


#include "Hacl_Spec.h"

/* SNIPPET_START: Hacl_Hash_Definitions_word_len */

uint32_t Hacl_Hash_Definitions_word_len(Spec_Hash_Definitions_hash_alg a);

/* SNIPPET_END: Hacl_Hash_Definitions_word_len */

/* SNIPPET_START: Hacl_Hash_Definitions_block_len */

uint32_t Hacl_Hash_Definitions_block_len(Spec_Hash_Definitions_hash_alg a);

/* SNIPPET_END: Hacl_Hash_Definitions_block_len */

/* SNIPPET_START: Hacl_Hash_Definitions_hash_word_len */

uint32_t Hacl_Hash_Definitions_hash_word_len(Spec_Hash_Definitions_hash_alg a);

/* SNIPPET_END: Hacl_Hash_Definitions_hash_word_len */

/* SNIPPET_START: Hacl_Hash_Definitions_hash_len */

uint32_t Hacl_Hash_Definitions_hash_len(Spec_Hash_Definitions_hash_alg a);

/* SNIPPET_END: Hacl_Hash_Definitions_hash_len */

#if defined(__cplusplus)
}
#endif

#define __Hacl_Hash_Base_H_DEFINED
#endif