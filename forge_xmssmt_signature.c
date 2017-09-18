/*
 * Copyright (c) 2016, Denis Butin and Stefan-Lukas Gazdag
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
#include "forge_xmssmt_signature.h"

#include "xmss/xmssmt_draft.h"
#include "recover_wots_pk.h"


/**
 * trying to forge a W-OTS signature for a given message (public key)
 * adapted from xmss/wots_draft.c (genWotsSig(..))
 * i.e. corresponding to algorithm 5 in the XMSS Internet Draft
 */

int forge_wots_signature(found_secret_value **sk, const wots_param *para,
    const unsigned char *M, unsigned char *sig, const unsigned char *seed,
    unsigned char adrs[32]){

  //printf("m=");hex_dump((unsigned char*) M, para->n); printf("\n");
  // mostly copied from wots_draft
  unsigned int i = 0, w = para->w;
	int csum = 0;
	unsigned int len = para->len, len_1 = para->len_1, len_2 = para->len_2;
	int tmp_msg[len_1];
	memset(tmp_msg, 0, len_1 * sizeof(*tmp_msg));
	int msg[len];
	memset(msg, 0, len * sizeof(*msg));
	base_w(M, w, len_1, tmp_msg);
	unsigned int len_2_bytes = 0;
	for (i = 0; i < len_1; i++)
		csum = csum + (int)w - 1 - tmp_msg[i];
	csum = csum << (8 - (int)((int)(len_2 * log2(w)) % 8));
	len_2_bytes = ((len_2 * (int)log2(w)) + 7) / 8;
	unsigned char byte[len_2_bytes];
	memset(byte, 0, len_2_bytes * sizeof(*byte));
	toByte(byte, csum, len_2_bytes);
	int tmp[len_2];
	for (unsigned int q = 0 ; q < len_2; q++)
		tmp[q] = 0;
	base_w(byte, w, len_2, tmp);
	/* Pseudo: msg = msg || tmp; */
	concat_int(msg, tmp_msg, len_1, tmp, len_2);
	for (i = 0; i < len; i++) {
		setChainAddress(adrs, i);

    // if we try to sign a message block m that is smaller than the index z
    // the recovered chaining value  c^z(x,r), we can not forge this signature
    // we need to abort then
    if(msg[i] -  (int) sk[i]->i < 0) return -1;

		chain(&sig[i * para->n], sk[i]->value, sk[i]->i,
		    (unsigned int)msg[i] -  sk[i]->i, para, seed, adrs);
	}
  return 0;
}



/**
 * recovering the intermediate XMSS tree root from a given XMSS signature
 * modified version of XMSS_rootFromSig (xmss/xmss_draft.c)
 * i.e., corresponds to algorithm 13
 */
int xmss_rootFromSig_modified2(xmss_sig *Sig, unsigned char *msg,
    unsigned char *node, unsigned char *seed, const unsigned int n,
    const unsigned int h, unsigned char adrs[32]){
	/*
	 * returns 1 if the index idx_sig is too large for the tree
	 * Note: we actually want to get h (the height of the tree)
	 * from the OID. This is just a workaround.
	 * If actually getting it from Sig: bytes 4 to n + 3
	 */
	unsigned char r[n];
	memset(r, 0, n * sizeof(unsigned char));
	/* If actually getting it from Sig: the last (h - 1) * n bytes */
	unsigned char auth[h * n];
	memset(auth, 0, h * n * sizeof(unsigned char));
	memcpy(r, Sig->randomness, n * sizeof(unsigned char));
	memcpy(auth, Sig->auth, h * n * sizeof(unsigned char));
	/* If actually getting it from Sig: bytes 0 - 3 */
	uint32_t idx_sig = Sig->idx_sig;
	if (idx_sig >= (uint32_t)(1 << h))
		return 1;
	wots_param para;
	para.n = n;
	para.w = 16;
	para.len_1 = calcLen1(para.w, para.n);
	para.len_2 = calcLen2(para.w, para.len_1);
	para.len = calcLen(para.len_1, para.len_2);
	unsigned char sig_ots[para.len * n];
	memset(sig_ots, 0, para.len * n * sizeof(unsigned char));
	memcpy(sig_ots, Sig->sig_ots, para.len * n * sizeof(unsigned char));
	setType(adrs, 0);
	setOTSAddress(adrs, idx_sig);
	unsigned char pk_ots[para.len * n];
	memset(pk_ots, 0, para.len * n * sizeof(unsigned char));
	wotsPubKeyFromSig(&para, msg, sig_ots, pk_ots, seed, adrs);


	unsigned char node0[para.n], node1[para.n];
	memset(node0, 0, para.n * sizeof(unsigned char));
	memset(node1, 0, para.n * sizeof(unsigned char));
  setType(adrs, 1);

	ltree(pk_ots, node0, &para, seed, adrs);


	setType(adrs, 2);
  setLayerAddress(adrs, 4);
  setTreeAddress(adrs, 0);
  setTreeIndex(adrs, 0);
  setTreeHeight(adrs, 2);
  setKeyAndMask(adrs, 0);
	uint32_t  k = 0, index = 0;
	for (k = 0; k < h; k++) {
		setTreeHeight(adrs, k);
		if (((int)floor((double)((idx_sig/(1 << (uint32_t)k)) % 2)))
		     == 0) {
			getTreeIndex(adrs, &index);
			setTreeIndex(adrs, (index >> 1));
			rand_hash(node1, node0, &auth[k * n], seed, adrs, n);
		}
		else
		{
			getTreeIndex(adrs, &index);
			setTreeIndex(adrs, ((index - 1) >> 1));
			rand_hash(node1, &auth[k * n], node0, seed, adrs, n);
		}
		memcpy(node0, node1, para.n * sizeof(unsigned char));
	}
	memcpy(node, node0, para.n * sizeof(unsigned char));
	return 0;
}


/**
 * forging an XMSS^MT signature, given:
 *   - the XMSS^MT public key including parameters
 *   - a valid xmssmt signature
 *   - the W-OTS+ public key at the top layer (recoverd from the valid signature)
 *   - the recovered partial W-OTS+ secret key
 *   - the message for which an XMSS^MT signature should be forged
 * This may fail - if secret key is not containing enough secret values
 * returns -1 on failure and 0 on success
 */
int forge_xmssmt_signature(unsigned char *forged_signature,
                            found_secret_value **secret_values, unsigned char * wots_pk,
                            unsigned char *valid_xmssmt_signature, unsigned char *xmssmt_pk,
                            unsigned char *msg, unsigned int msglength, wots_param *para,
                            unsigned int d, unsigned h){
  xmss_mt_sk temp_sk;
  temp_sk.idx_MT = 0;
  temp_sk.SK_PRF = (unsigned char *) malloc(para->n);
  // a very random seed
  RAND_bytes(temp_sk.SK_PRF, para->n);



  temp_sk.root = xmssmt_pk;
  temp_sk.seed = &xmssmt_pk[para->n];
  temp_sk.d = d;
  temp_sk.hmt = h;
  unsigned int num = 0;
	for (unsigned int j = 1 ; j < d + 1; j++)
		num = num + (1 << (h - j * (h / d)));
  temp_sk.reduced_keys = (xmss_sk *) calloc(num, sizeof(*temp_sk.reduced_keys));

  unsigned int count = 0;
  unsigned char adrs[32];
	memset(adrs, 0, 32);
	memset(adrs, 0, sizeof(adrs));
	for (int32_t layer = (int32_t)(d - 1) ; layer > -1 ; layer--) {
		setLayerAddress(adrs, layer);
		for (unsigned long long int tree = 0 ; tree <
		    (unsigned long long int) (1 << (((int32_t)d - 1 - layer)
		     * (h / d))); tree++) {
			setTreeAddress(adrs, tree);
			xmss_sk_init(&(temp_sk.reduced_keys[count]), para,
			    h / d);
			memcpy(temp_sk.reduced_keys[count].SK_PRF, temp_sk.SK_PRF,
			    para->n);
			/* Will now call treeHash to compute nodes */
			unsigned char root[para->n];
			memset(root, 0, para->n);
			memcpy(temp_sk.reduced_keys[count].seed, temp_sk.seed,
			    para->n);
			treeHash(root, &(temp_sk.reduced_keys[count]), 0,
			    h / d, adrs);
			count++;
		}
	}


  xmss_mt_sign(&temp_sk, msg, msglength, forged_signature, 0);
  //printf("forged_xmssmt=0x"); hex_dump(xmssmt_signature, sizeof(xmssmt_signature)); printf("\n");


  unsigned char xmss_pk_tmp[para->n];
  recover_xmss_pk(xmss_pk_tmp, xmssmt_pk, forged_signature,para,h,d, msg, msglength);

  memset(adrs, 0, sizeof(adrs));
  setLayerAddress(adrs, (uint32_t)(d - 1));
  setTreeAddress(adrs, 0);
  setTreeIndex(adrs, 2);
  setTreeHeight(adrs, 2);
  setType(adrs, 0);
  setOTSAddress(adrs, 0);
  unsigned char wots_signature[para->n * para->len];
    //printf("adrs=0x"); hex_dump(adrs, 32); printf("\n");

  int forgingResult = forge_wots_signature(secret_values, para, xmss_pk_tmp, wots_signature, temp_sk.seed , adrs);
  // forging failed
  if(forgingResult == -1) return -1;


  // copy over the wots signature
  unsigned int start_of_top_signature = (int)ceil(h / 8.0) + para->n +
                                  (d-1) * (h/d + para->len) * para->n;
  memcpy(&forged_signature[start_of_top_signature], wots_signature, para->len * para->n);

  // copy over auth path
  memcpy(&forged_signature[start_of_top_signature+(para->len*para->n)],
         &valid_xmssmt_signature[start_of_top_signature+(para->len*para->n)], (h/d)*para->n );
  return 0;
}
