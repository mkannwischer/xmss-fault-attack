/*
 * Copyright (c) 2017, Matthias Julius Kannwischer
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef HELPER_H
#define HELPER_H
#include "xmss/wots_draft.h"

typedef struct {
  unsigned int num_values;
  unsigned char **values;
} intermediate_chain_values;

typedef struct {
  unsigned int i; // 0 if this is the secret key
  unsigned char *value;
} found_secret_value;


void helper_merge_found_key_parts(unsigned int n, unsigned int len,
                           unsigned int w, unsigned char *wots_signature,
                           intermediate_chain_values** values);

intermediate_chain_values** helper_init_chain_values(unsigned int w, unsigned int len);
void helper_free_chain_values(intermediate_chain_values **, unsigned int len);
void helper_print_progress(intermediate_chain_values ** , unsigned int len,
                           unsigned int w);
void helper_print_detailed_progress(intermediate_chain_values ** , unsigned int len,
                                                      unsigned int w);

#endif
