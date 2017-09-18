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

#include "recover_wots_pk.h"

#include "xmss/xmssmt_draft.h"



/**
 * modified version of xmss_rootFromSig (xmss/xmss_draft.c)
 * recoveres a XMSS pk from a XMSS signature
 */
int
xmss_rootFromSig_modified(xmss_sig *Sig, unsigned char *msg,
    unsigned char *node, unsigned char *seed, const unsigned int n,
    const unsigned int h, unsigned char adrs[32], unsigned char *outputpk){
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

  memcpy(outputpk, pk_ots, para.len*n);
	setType(adrs, 1);
	setLTreeAddress(adrs, idx_sig);
	unsigned char node0[para.n], node1[para.n];
	memset(node0, 0, para.n * sizeof(unsigned char));
	memset(node1, 0, para.n * sizeof(unsigned char));
	ltree(pk_ots, node0, &para, seed, adrs);
	setType(adrs, 2);
	setTreeIndex(adrs, idx_sig);
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
 * recovers the intermediate XMSS public key from a given XMSS^MT signature
 * adapted from xmss_mt_verify
 */
void recover_xmss_pk(unsigned char *xmss_root, unsigned char *xmss_mt_pk, unsigned char *sig,
                wots_param *para, unsigned int h, unsigned int d, unsigned char *msg, unsigned int msglen){

   // mostly copied from xmssmt_draft.c
   xmss_mt_sig Sig_MT;
   xmss_mt_sig_init(&Sig_MT, para, h, d);
   unsigned int w = para->w, n = para->n;
   xmss_mt_StringToSig(&Sig_MT, sig, n, h, w, d);
   uint64_t idx_sig = Sig_MT.idx_sig;

   xmss_pk PK_MT;
   xmss_pk_init(&PK_MT, n);
   xmssStringToPK(&PK_MT, xmss_mt_pk, n);
   unsigned char seed[n], adrs[32];
   memcpy(seed, PK_MT.seed, sizeof(seed));
   memset(adrs, 0, sizeof(adrs)); /* ADRS = toByte(0, 32) */
   unsigned char r[n];
   memset(r, 0, sizeof(r));
   memcpy(r, Sig_MT.randomness, n * sizeof(unsigned char));
   unsigned char msg_tmp[n];
   memset(msg_tmp, 0, sizeof(msg_tmp));
   unsigned char tobyte_tmp[n];
   memset(tobyte_tmp, 0, n * sizeof(unsigned char));
   unsigned char input_tmp[3 * n];
   memset(input_tmp, 0, 3 * n * sizeof(unsigned char));
   unsigned char rand_root_tmp[2 * n];
   memset(rand_root_tmp, 0, 2 * n * sizeof(unsigned char));
   toByte(tobyte_tmp, idx_sig, n);
   concat_bytes(rand_root_tmp, r, n, PK_MT.root, n);
   concat_bytes(input_tmp, rand_root_tmp, 2 * n, tobyte_tmp, n);
   H_msg(msg_tmp, msg, msglen, input_tmp, n); /* byte[n] */

   uint64_t idx_leaf = 0, idx_tree = 0;
   /* idx_leaf = (h / d) least significant bits of idx_sig */
   getLSB(idx_sig, &idx_leaf, h / d, h);
   /* idx_tree = (h - h / d) most significant bits of idx_sig */
   getMSB(idx_sig, &idx_tree, h - h / d, h);

   xmss_sig Sigp; /* Sig' */
   xmss_sig_init(&Sigp, para, h / d);

   /* Sig' = getXMSSSignature(Sig_MT, 0) */
   Sigp.idx_sig = idx_leaf;
   memcpy(Sigp.randomness, Sig_MT.randomness,
       n * sizeof(*Sigp.randomness));
   memcpy(Sigp.sig_ots, Sig_MT.reduced_sigs[0].sig_ots,
       para->len * n * sizeof(*Sigp.sig_ots));
   memcpy(Sigp.auth, Sig_MT.reduced_sigs[0].auth,
       (h / d) * n * sizeof(*Sigp.auth));
   setLayerAddress(adrs, 0); /* ADRS.setLayerAddress(0) */
   setTreeAddress(adrs, idx_tree); /* ADRS.setTreeAddress(idx_tree) */

   /* byte[n] node = XMSS_rootFromSig(idx_leaf, getSig_ots(Sig'),
         getAuth(Sig'), M', SEED, ADRS) */
   unsigned char node[n];
   memset(node, 0, sizeof(node));
   xmss_rootFromSig(&Sigp, msg_tmp, node, seed, n, h/d, adrs);
   if(d==2){
     memcpy(xmss_root, node, n);
   }
   for (unsigned int j = 1; j < d; j++) {
     /* idx_leaf = (h / d) least significant bits of idx_tree */
     getLSB(idx_tree, &idx_leaf, h / d, h);

     /*
      * idx_tree = (h - j * h / d)
      * most significant bits of idx_tree
      */
     getMSB(idx_tree, &idx_tree, h - h / d, h);

     /* Sig' = getXMSSSignature(Sig_MT, j) */
     Sigp.idx_sig = idx_leaf;
     memcpy(Sigp.sig_ots, Sig_MT.reduced_sigs[j].sig_ots,
         para->len * n * sizeof(*Sigp.sig_ots));
     memcpy(Sigp.auth, Sig_MT.reduced_sigs[j].auth,
         (h / d) * n * sizeof(*Sigp.auth));

     /* ADRS.setLayerAddress(j) */
     setLayerAddress(adrs, (uint32_t) j);
     /* ADRS.setTreeAddress(idx_tree) */
     setTreeAddress(adrs, idx_tree);



     unsigned char wots_pk[para->n * para->len];
     xmss_rootFromSig_modified(&Sigp, node, node, seed, n, h/d, adrs, wots_pk);
     /* node = XMSS_rootFromSig(idx_leaf, getSig_ots(Sig'),
         getAuth(Sig'), node, SEED, ADRS) */

    if(j == d-2){
      memcpy(xmss_root, node, n);
    }

   }
   xmss_sig_free(&Sigp);
   xmss_mt_sig_free(&Sig_MT, d);
}



/**
 * recovers the top W-OTS+ public key from a XMSS^MT signature
 * based on xmss_mt_verify in xmss/xmssmt_draft.c
 */
void recover_wots_pk_from_sig(unsigned char *wots_pk, unsigned char *xmss_mt_pk, unsigned char *sig,
                wots_param *para, unsigned int h, unsigned int d){
   unsigned int msglen = 480;
   unsigned char msg[msglen];
   memset(msg, 0, sizeof(msg));

    // mostly copied from xmssmt_draft.c



    xmss_mt_sig Sig_MT;
    xmss_mt_sig_init(&Sig_MT, para, h, d);
    unsigned int w = para->w, n = para->n;
    xmss_mt_StringToSig(&Sig_MT, sig, n, h, w, d);
    uint64_t idx_sig = Sig_MT.idx_sig;

    xmss_pk PK_MT;
    xmss_pk_init(&PK_MT, n);
    xmssStringToPK(&PK_MT, xmss_mt_pk, n);
    unsigned char seed[n], adrs[32];
    memcpy(seed, PK_MT.seed, sizeof(seed));
  	memset(adrs, 0, sizeof(adrs)); /* ADRS = toByte(0, 32) */
    unsigned char r[n];
  	memset(r, 0, sizeof(r));
  	memcpy(r, Sig_MT.randomness, n * sizeof(unsigned char));
    unsigned char msg_tmp[n];
  	memset(msg_tmp, 0, sizeof(msg_tmp));
  	unsigned char tobyte_tmp[n];
  	memset(tobyte_tmp, 0, n * sizeof(unsigned char));
  	unsigned char input_tmp[3 * n];
  	memset(input_tmp, 0, 3 * n * sizeof(unsigned char));
  	unsigned char rand_root_tmp[2 * n];
  	memset(rand_root_tmp, 0, 2 * n * sizeof(unsigned char));
  	toByte(tobyte_tmp, idx_sig, n);
  	concat_bytes(rand_root_tmp, r, n, PK_MT.root, n);
  	concat_bytes(input_tmp, rand_root_tmp, 2 * n, tobyte_tmp, n);
  	H_msg(msg_tmp, msg, msglen, input_tmp, n); /* byte[n] */

  	uint64_t idx_leaf = 0, idx_tree = 0;
  	/* idx_leaf = (h / d) least significant bits of idx_sig */
  	getLSB(idx_sig, &idx_leaf, h / d, h);
  	/* idx_tree = (h - h / d) most significant bits of idx_sig */
  	getMSB(idx_sig, &idx_tree, h - h / d, h);

  	xmss_sig Sigp; /* Sig' */
  	xmss_sig_init(&Sigp, para, h / d);

  	/* Sig' = getXMSSSignature(Sig_MT, 0) */
  	Sigp.idx_sig = idx_leaf;
  	memcpy(Sigp.randomness, Sig_MT.randomness,
  	    n * sizeof(*Sigp.randomness));
  	memcpy(Sigp.sig_ots, Sig_MT.reduced_sigs[0].sig_ots,
  	    para->len * n * sizeof(*Sigp.sig_ots));
  	memcpy(Sigp.auth, Sig_MT.reduced_sigs[0].auth,
  	    (h / d) * n * sizeof(*Sigp.auth));
  	setLayerAddress(adrs, 0); /* ADRS.setLayerAddress(0) */
  	setTreeAddress(adrs, idx_tree); /* ADRS.setTreeAddress(idx_tree) */

  	/* byte[n] node = XMSS_rootFromSig(idx_leaf, getSig_ots(Sig'),
  			  getAuth(Sig'), M', SEED, ADRS) */
  	unsigned char node[n];
  	memset(node, 0, sizeof(node));
    xmss_rootFromSig(&Sigp, msg_tmp, node, seed, n, h/d, adrs);

    for (unsigned int j = 1; j < d; j++) {
  		/* idx_leaf = (h / d) least significant bits of idx_tree */
  		getLSB(idx_tree, &idx_leaf, h / d, h);

  		/*
  		 * idx_tree = (h - j * h / d)
  		 * most significant bits of idx_tree
  		 */
  		getMSB(idx_tree, &idx_tree, h - h / d, h);

  		/* Sig' = getXMSSSignature(Sig_MT, j) */
  		Sigp.idx_sig = idx_leaf;
  		memcpy(Sigp.sig_ots, Sig_MT.reduced_sigs[j].sig_ots,
  		    para->len * n * sizeof(*Sigp.sig_ots));
  		memcpy(Sigp.auth, Sig_MT.reduced_sigs[j].auth,
  		    (h / d) * n * sizeof(*Sigp.auth));

  		/* ADRS.setLayerAddress(j) */
  		setLayerAddress(adrs, (uint32_t) j);
  		/* ADRS.setTreeAddress(idx_tree) */
  		setTreeAddress(adrs, idx_tree);

  		xmss_rootFromSig_modified(&Sigp, node, node, seed, n, h/d, adrs, wots_pk);
  		/* node = XMSS_rootFromSig(idx_leaf, getSig_ots(Sig'),
  			  getAuth(Sig'), node, SEED, ADRS) */
  	}
  	xmss_sig_free(&Sigp);
  	xmss_mt_sig_free(&Sig_MT, d);
}
