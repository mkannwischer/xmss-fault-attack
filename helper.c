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

#include "helper.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


/**
 * initializes partial W-OTS secret key
 */
intermediate_chain_values** helper_init_chain_values(unsigned int w, unsigned int len){
  intermediate_chain_values **chain_values;
  chain_values = (intermediate_chain_values **)
                      malloc(sizeof(void *)*len);
  for(unsigned int i=0;i<len;i++)
  {
    chain_values[i] = (intermediate_chain_values *)
                            malloc(sizeof(intermediate_chain_values));
    chain_values[i]->num_values = 0;
    chain_values[i]->values = (unsigned char **) malloc(sizeof(void *)*w);
  }
  return chain_values;
}

/**
 * frees memory of partial W-OTS+key
 */
void helper_free_chain_values(intermediate_chain_values **chain_values,
                       unsigned int len){
  for(unsigned int i=0;i<len;i++)
  {
    for(unsigned int j=0;j<chain_values[i]->num_values;j++){
      free(chain_values[i]->values[j]);
    }
    free(chain_values[i]->values);
    free(chain_values[i]);
  }
}
 /**
  * merges the recovered chain values into the intermediate_chain_values
  */

void helper_merge_found_key_parts(unsigned int n, unsigned int len,
                           unsigned int w, unsigned char *wots_signature,
                           intermediate_chain_values** values){
  for(unsigned int i=0;i<len;i++)
  {

    intermediate_chain_values *chain = values[i];
    unsigned char* sig_value = &wots_signature[n*i];

    unsigned int already_known = 0;

    for(unsigned int j=0;j<chain->num_values;j++)
    {
      if(memcmp(sig_value, chain->values[j], n) == 0){
        already_known = 1;
        break;
      }
    }

    if(!already_known){
      chain->values[chain->num_values]  = (unsigned char *) malloc(n);
      memcpy(chain->values[chain->num_values], sig_value, n);
      chain->num_values++;
    }
  }
}
/**
 * prints the progress for each chain
 */
void helper_print_progress(intermediate_chain_values **values, unsigned int len,
                           unsigned int w){
  unsigned int required_parts = len*w;
  unsigned int recovered_parts = 0;
  for(unsigned int i=0;i<len;i++){
    recovered_parts += values[i]->num_values;
  }
  printf("Recoverd %u of %u parts (%.2f%%)\n", recovered_parts, required_parts,
         (recovered_parts *100.0) / required_parts);

}

/**
 * prints the progress including all recovered chain values for each chain
 */
void helper_print_detailed_progress(intermediate_chain_values **values, unsigned int len,
                                                      unsigned int w){
  for(unsigned int i=0;i<len;i++){
    printf("Chain #%u, Progress %u/%u (%.2f%%)\n", i, values[i]->num_values,
                                                  w, (values[i]->num_values *100.0) / w);
  }
}
