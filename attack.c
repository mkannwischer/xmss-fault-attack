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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "xmss/xmssmt_draft.h"
#include "helper.h"
#include "xmss/hfas_draft.h"
#include "xmss/wots_draft.h"
#include "xmss/prf_draft.h"
#include "recover_wots_pk.h"
#include "forge_xmssmt_signature.h"


#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"




int generate_key(unsigned int n, unsigned int w, unsigned int h, unsigned int d);
void create_signature_and_merge(unsigned char *signature,
                           unsigned int n, unsigned int w,
                           unsigned int h, unsigned int d, int faulted);
void recover_keys(unsigned int h, unsigned int d, unsigned char *valid_signature);



// parameters
wots_param *para;
unsigned int silent = 0;

// variables of the attacked device
xmss_mt_sk *SKmt;
unsigned char *PKmt;

// variables of the adversary
intermediate_chain_values **chain_values; // containing all known chain values
found_secret_value **wots_secret_key;  // containing the lowest chain values



void printHex(const unsigned char* data, int length){
  printf("0x");
  for(int i=0;i<length;i++){
    printf("%02x", data[i]);
  }
  printf("\n");
}

/**
 * dumps a partial secret W-OTS+ key
 */
void dump_secret_key(){
  for(unsigned int i=0;i<para->len;i++){
    if(!silent) printf("c_k^%u(sk[%u])=0x", wots_secret_key[i]->i,i);
    hex_dump(wots_secret_key[i]->value, para->n);
    printf("\n");
  }
}

int main(int argc, char** argv){
  if(argc < 5){
    printf("Usage: attack n h d p [--silent]\n");
    printf("\tn : security parameter (32 for 256 bits, 64 for 512 bits)\n");
    printf("\th : total height of the hyper tree (e.g. 10)\n");
    printf("\td : number of tree layers (e.g. 5)\n");
    printf("\tp : number of forging attempts per iteration\n\n");
    printf("Not all combinations of h and d are possible \n\t(h must be divisible by d; see Internet Draft for full list)\n");
    printf("The implementation also supports other values for h than allowed in the Internet Draft\n");
    printf("The --silent option disables all console logs except the results\n");
    return 1;
  }

  // w is fixed according to rfc
  unsigned int n=strtol(argv[1], NULL, 10);
  unsigned int w=16;
  unsigned int h=strtol(argv[2], NULL, 10);
  unsigned int d=strtol(argv[3], NULL, 10);
  unsigned int p=strtol(argv[4], NULL, 10);

  if(argc >= 6 && strcmp(argv[5], "--silent") == 0){
    silent = 1;
    printf("%u;%u;%u;%u;%u;%lu;", n, w, h, d, p, (unsigned long)time(NULL));
  }


  // create XMSS^MT key pair
  if(generate_key(n, w, h, d) == 1){
    if(!silent) fputs("Error while key generation.\n", stderr);
    return 1;
  }

  // initialize the data structure used to store the intermediate results
  chain_values = helper_init_chain_values(w, para->len);

  // create one valid signature - used later
  // TODO: also use the key parts of the valid signature
  unsigned int signature_length = (int)ceil(h / 8.0) + n +
                                  d * (h/d + para->len) * n;
  unsigned char valid_signature[signature_length];

  if(!silent) printf("Creating a single valid signature...\n");
  create_signature_and_merge(valid_signature, n, w, h, d, 0);
  if(!silent) printf(GREEN "SUCCESS\n" RESET);

  if(!silent) printf("Extracting W-OTS+ public key from valid signature...\n");
  unsigned char wots_pk[para->len * para->n];
  memset(wots_pk, 0, sizeof(wots_pk));
  recover_wots_pk_from_sig(wots_pk, PKmt, valid_signature,para,h,d);
  if(!silent) printf(GREEN "SUCCESS\n" RESET);


  // alloc some space for recovery later
  wots_secret_key = (found_secret_value **) malloc(sizeof(void *)* para->len);

  // create faulted signatures until we recovered all key parts
  unsigned int num_signatures_generated = 0;

  // 0 --> attack succesful
  // 1 --> attack unsuccesful
  // 2 --> unknown error
  int attack_result = 2;

  unsigned int max_number_of_faulted_signatures = (1<<(h-(h/d)))-1;

  if(!silent) printf("Creating up to %u faulty signatures...\n", max_number_of_faulted_signatures);
  while(1){
    //helper_print_progress(chain_values, para->len, w);
    // check if we already exceeded the first subtree
    // if yes, the attack failed
    if(num_signatures_generated >= max_number_of_faulted_signatures){
        if(!silent) printf(RED "Exeeded the max number of faulty signatures.\n Unfortunately the attack failed" RESET);
        if(!silent) helper_print_detailed_progress(chain_values, para->len, w);
        attack_result = 1;
        break;
    }

    // create faulty signature
    if(!silent) printf("Creating faulty signature...\n");
    unsigned char tmp_signature[signature_length];
    create_signature_and_merge(tmp_signature, n, w, h, d, 1);

    // try to recover the private key
    recover_keys(h,d, valid_signature);



    unsigned char message[42];
    memset(message, 42, sizeof(message));
    unsigned char forged_signature[signature_length];

    // the forging may fail, because we do not have the entire private key
    for(unsigned int i=0;i<p;i++){
      if(!silent) printf("Forging signature...");
      unsigned int forgingResult = forge_xmssmt_signature(forged_signature, wots_secret_key, wots_pk, valid_signature, PKmt, message, sizeof(message),para, d, h);
      if(forgingResult == 0) {
        if(!silent) printf(GREEN "SUCCESS\n"RESET);
        if(!silent) printf("Validating forged signature...\n");


        unsigned int verificationResult = xmss_mt_verify(PKmt, forged_signature, message, sizeof(message), para, h, d);

        if(verificationResult == 0){
          attack_result = 0; // successful
          if(!silent) printf(GREEN "XMSS^MT Signature Verification for forged signature successful!\n"RESET );
        } else {
          attack_result = 2; // error, should not happen
          if(!silent) printf(RED "XMSS^MT Signature Verification for forged signature failed!\n THIS SHOULD NEVER HAPPEN!" RESET);
        }
        break;
      }
      if(!silent && forgingResult != 0) printf(RED " FAILED\n" RESET);
    }


    // free up some memory
    for(unsigned int c=0;c<para->len;c++){
      //printf("c=%u\n",c);
      free(wots_secret_key[c]->value);
      free(wots_secret_key[c]);
    }

    num_signatures_generated++;
    if(attack_result == 0) break;

  }

  if(silent) {
    printf("%u;%u;%lu;%u\n", num_signatures_generated, max_number_of_faulted_signatures, time(NULL), attack_result);
  } else {
    if(attack_result == 0){
      printf(GREEN"SUCCESS\n"RESET);
      printf(GREEN"We successfully attacked XMSS^MT.\n The attack required %u of max. %u faulty signatures\n"RESET, num_signatures_generated, max_number_of_faulted_signatures);
    } else {
      printf(RED"FAILED\n"RESET);
    }
  }

  // free memory
  helper_free_chain_values(chain_values, para->len);
  free(chain_values);
  free(para);
  free(SKmt);
  free(PKmt);
}


/**
 * generating a XMSS^MT key pair for certain parameters
 */

int generate_key(unsigned int n, unsigned int w, unsigned int h, unsigned int d){
  // W-OTS params
  para = (wots_param *) malloc(sizeof(wots_param));
  if (wots_param_init(para, n, w) == 1) {
    if(!silent) fputs("Error: wots_param_init: wrong parameters\n", stderr);
    return 1;
  }


  if(!silent) printf("Parameters: n = %u, w = %u, h = %u, d= %u, len= %u, len1= %u, len2=%u", para->n, para->w, h, d, para->len, para->len_1, para->len_2);
  if(!silent) printf("\nGenerating XMSS^MT key pair...\n");

  SKmt = (xmss_mt_sk *) malloc(sizeof(xmss_mt_sk));
  PKmt = (unsigned char *) malloc(sizeof(unsigned char)*2*para->n);
  xmss_mt_keyGen(SKmt, PKmt, para, h, d);
  if(!silent) printf(GREEN"SUCCESS\n"RESET);

  return 0;
}

/**
 * creating a XMSS^MT signature and merging th secret chain values to the known chain values
 * either faulty or not faulty
 *
 */

void create_signature_and_merge(unsigned char *signature,
                           unsigned int n, unsigned int w,
                           unsigned int h, unsigned int d, int faulty){

  // choose a message
  // actually we do not care what message is signed
  unsigned int msglen = 480;
  unsigned char message[msglen];
	memset(message, 0, sizeof(message));

  // init the signature
  unsigned int signature_length = (int)ceil(h / 8.0) + n +
                                  d * (h/d + para->len) * n;
  // idx_sig                           (int)ceil(h / 8.0)
  // randomness r                      n bytes
  // xmss signature (bottom layers)   ((h/d)-1) * (h/d + len) * n
  unsigned int start_of_top_signature = (int)ceil(h / 8.0) + n +
                                  (d-1) * (h/d + para->len) * n;

  memset(signature, 0, signature_length);


  xmss_mt_sign(SKmt, message, msglen, signature, faulty);


  helper_merge_found_key_parts(n, para->len, w, &signature[start_of_top_signature], chain_values);
}



/**
 * for each chain, try to recover the chain value with the lowest b_i.
 */
void recover_keys(unsigned int h, unsigned int d, unsigned char *valid_signature){
  if(!silent) printf("Trying to recover W-OTS private key...\n");
  // recover public key first
  unsigned char wots_pk[para->len * para->n];
  memset(wots_pk, 0, sizeof(wots_pk));
  recover_wots_pk_from_sig(wots_pk, PKmt, valid_signature,para,h,d);


  unsigned char* pk_seed = &PKmt[para->n];

  unsigned char adrs[32];
  memset(adrs, 0, sizeof(adrs));
  setLayerAddress(adrs, (uint32_t)(d - 1));
  setTreeAddress(adrs, 0);

  // recover chain value with the lowest b_i from each chain
  // ideally: b_i =0 -> secret key part
  for(unsigned int c=0;c<para->len;c++){
    unsigned char chained[para->n];
    setChainAddress(adrs, c);
    int found = 0;
    for(unsigned int i=0;i<para->w;i++){

        if(found) break;
        for(unsigned int x=0;x<chain_values[c]->num_values;x++){
          chain(chained, chain_values[c]->values[x], i, para->w-1-i, para, pk_seed, adrs);
          if(memcmp(chained, &wots_pk[para->n*c], para->n) == 0)
          {
            wots_secret_key[c] = (found_secret_value *) malloc(sizeof(found_secret_value));
            wots_secret_key[c]->i = i;
            wots_secret_key[c]->value = (unsigned char *) malloc(para->n);

            memcpy(wots_secret_key[c]->value, chain_values[c]->values[x], para->n);
            found=1;
            break;
          }
        }
    }
  }
}
