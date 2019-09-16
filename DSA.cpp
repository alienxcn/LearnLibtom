/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "DSA.h"

#define mp_init_multi                ltc_init_multi
#define mp_cmp_d(a, b)               ltc_mp.compare_d(a, b)
#define mp_cmp(a, b)                 ltc_mp.compare(a, b)
#define mp_invmod(a, b, c)           ltc_mp.invmod(a, b, c)
#define mp_read_unsigned_bin(a, b, c) ltc_mp.unsigned_read(a, b, c)
#define mp_mulmod(a, b, c, d)        ltc_mp.mulmod(a, b, c, d)
#define mp_exptmod(a,b,c,d)          ltc_mp.exptmod(a,b,c,d)
#define mp_mod(a, b, c)              ltc_mp.mpdiv(a, b, NULL, c)
#define mp_clear_multi               ltc_deinit_multi
#define mp_count_bits(a)             ltc_mp.count_bits(a)
#define mp_gcd(a, b, c)              ltc_mp.gcd(a, b, c)
#define mp_iszero(a)                 (mp_cmp_d(a, 0) == LTC_MP_EQ ? LTC_MP_YES : LTC_MP_NO)
#define mp_mul(a, b, c)              ltc_mp.mul(a, b, c)
#define mp_add(a, b, c)              ltc_mp.add(a, b, c)


int dsa_testp(void)
{
   unsigned char msg[16], out[1024], out2[1024], ch;
   unsigned long x, y;
   int stat1, stat2, err;
   dsa_key key, key2;
   prng_state prng;

   // ltc_mp = tfm_desc;

   if (ltc_mp.name == NULL) {
      printf("ERROR: ltc_mp.name == NULL!\n");
      return CRYPT_NOP;
   } else {
      printf("ltc_mp created Successed!\n");
   }

   /* register yarrow */
   if (register_prng(&yarrow_desc) == -1) {
      printf("Error registering Yarrow\n");
      return -1;
   }
   /* register hashes .... */
   if (register_hash(&sha1_desc) == -1) {
      printf("Error registering SHA1.\n");
      return -1;
   }
   /* setup the PRNG */
   if ((err = rng_make_prng(128, find_prng("yarrow"), &prng, NULL)) != CRYPT_OK) {
      printf("Error setting up PRNG, %s\n", error_to_string(err));
      return -1;
   }
   /* make a random key */
   dsa_generate_pqg(&prng, find_prng("yarrow"), 20, 128, &key);
   dsa_generate_key(&prng, find_prng("yarrow"), &key);
   /* verify it */
   dsa_verify_key(&key, &stat1);
   if (stat1 == 0) { 
      fprintf(stderr, "dsa_verify_key "); 
      return 1; 
   } else {
      fprintf(stderr, "dsa_verify_key Successed!\n");
   }

   /* encrypt a message */
   for (ch = 0; ch < 16; ch++) { msg[ch] = ch; }
   x = sizeof(out);
   dsa_encrypt_key(msg, 16, out, &x, &prng, find_prng("yarrow"), find_hash("sha1"), &key);

   /* decrypt */
   y = sizeof(out2);
   dsa_decrypt_key(out, x, out2, &y, &key);

   if (y != 16 || memcmp(out2, msg, 16)) {
      fprintf(stderr, "dsa_decrypt failed, y == %lu\n", y);
      return 1;
   } else {
      fprintf(stderr, "dsa_decrypt Successed!\n");
   }

   /* sign the message */
   x = sizeof(out);
   dsa_sign_hash(msg, sizeof(msg), out, &x, &prng, find_prng("yarrow"), &key);

   /* verify it once */
   dsa_verify_hash(out, x, msg, sizeof(msg), &stat1, &key);

   /* Modify and verify again */
   msg[0] ^= 1;
   dsa_verify_hash(out, x, msg, sizeof(msg), &stat2, &key);
   msg[0] ^= 1;
   if (!(stat1 == 1 && stat2 == 0)) { 
      fprintf(stderr, "dsa_verify %d %d", stat1, stat2); 
      return 1; 
   } else {
      fprintf(stderr, "dsa_verify sign Successed!\n");
   }

   /* test exporting it */
   y = sizeof(out2);
   dsa_export(out2, &y, PK_PRIVATE, &key);
   dsa_import(out2, y, &key2);

   /* verify a signature with it */
   dsa_verify_hash(out, x, msg, sizeof(msg), &stat1, &key2);
   if (stat1 == 0) { 
      fprintf(stderr, "dsa_verify (import private) %d ", stat1); 
      return 1; 
   } else {
      fprintf(stderr, "dsa_verify PRIVATE Successed!\n");
   }
   dsa_free(&key2);

   /* export as public now */
   y = sizeof(out2);
   dsa_export(out2, &y, PK_PUBLIC, &key);

   dsa_import(out2, y, &key2);
   /* verify a signature with it */
   dsa_verify_hash(out, x, msg, sizeof(msg), &stat1, &key2);
   if (stat1 == 0) { 
      fprintf(stderr, "dsa_verify (import public) %d ", stat1); 
      return 1; 
   } else {
      fprintf(stderr, "dsa_verify PUBLIC Successed!\n");
   }
   dsa_free(&key2);
   dsa_free(&key);
   printf("\n\n");

   return 0;
}

int DSA_generator_from_pqg(const char* g, const char* p, const char* q, const char* x, const char* y, dsa_key* prikey, dsa_key* pubkey){
   unsigned char key_parts[5][256];
   unsigned long key_lens[5];
   // unsigned long len;
   // unsigned char buf[1024];
   const char* paras[5] = {p, q, g, y, x};

   for (int i = 0; i < 5; i++){
      key_lens[i] = sizeof(key_parts[i]);
      radix_to_bin(paras[i], 16, key_parts[i], &key_lens[i]);
   }
   dsa_set_pqg(key_parts[0], key_lens[0],
               key_parts[1], key_lens[1],
               key_parts[2], key_lens[2],
               prikey);
   dsa_set_pqg(key_parts[0], key_lens[0],
               key_parts[1], key_lens[1],
               key_parts[2], key_lens[2],
               pubkey);
   dsa_set_key(key_parts[4], key_lens[4],
               PK_PRIVATE, 
               prikey);
   dsa_set_key(key_parts[3], key_lens[3],
               PK_PUBLIC, 
               pubkey);
   /*
   len = sizeof(buf);
   dsa_export(buf, &len, PK_PRIVATE | PK_STD, prikey);
   if(compare_testvector(buf, len, openssl_priv_dsa, sizeof(openssl_priv_dsa), "what", __LINE__) == 0){
      printf("Pri Com Successed!\n");
   } else {
      printf("Pri Com Failed!\n");
   }

   len = sizeof(buf);
   dsa_export(buf, &len, PK_PUBLIC | PK_STD, pubkey);
   if(compare_testvector(buf, len, openssl_pub_dsa, sizeof(openssl_pub_dsa), "what", __LINE__) == 0){
      printf("Pub Com Successed!\n");
   } else {
      printf("Pub Com Failed!\n");
   }
   */
   printf("DSA_generator_from_pqg:  OK!\n");
   return CRYPT_OK;
}

int DSA_generator_from_pqg_random(dsa_key* prikey){
   prng_state prng;
   int stat = 0, err = 0;

   /* register yarrow */
   if (register_prng(&yarrow_desc) == -1) {
      printf("Error registering Yarrow\n");
      return -1;
   }
   /* setup the PRNG */
   if ((err = rng_make_prng(128, find_prng("yarrow"), &prng, NULL)) != CRYPT_OK) {
      printf("Error setting up PRNG, %s\n", error_to_string(err));
      return -1;
   }

   dsa_generate_pqg(&prng, find_prng("yarrow"), 20, 128, prikey);
   dsa_generate_key(&prng, find_prng("yarrow"), prikey);

   dsa_verify_key(prikey, &stat);
   if (stat == 0) {
      printf("DSA_generator_from_pqg_random:  Failed!\n");
      return CRYPT_FAIL_TESTVECTOR;
   } else {
      printf("DSA_generator_from_pqg_random:  OK!\n");
      return CRYPT_OK;
   }
}

int DSA_encrypt_message(const unsigned char* msg, unsigned long msg_len, unsigned char* out, unsigned long* out_len, const dsa_key* prikey){
   prng_state prng;
   int err = 0;

   /* register hashes .... */
   if (register_hash(&sha1_desc) == -1) {
      printf("Error registering SHA1.\n");
      return -1;
   }
   /* register yarrow */
   if (register_prng(&yarrow_desc) == -1) {
      printf("Error registering Yarrow\n");
      return -1;
   }
   /* setup the PRNG */
   if ((err = rng_make_prng(128, find_prng("yarrow"), &prng, NULL)) != CRYPT_OK) {
      printf("Error setting up PRNG, %s\n", error_to_string(err));
      return -1;
   }

   dsa_encrypt_key(msg, msg_len, out, out_len, &prng, find_prng("yarrow"), find_hash("sha1"), prikey);
   return CRYPT_OK;
}

int DSA_decrypt_messgae(const unsigned char* in, unsigned long in_len, unsigned char* out, unsigned long* out_len, const dsa_key* prikey){
   return dsa_decrypt_key(in, in_len, out, out_len, prikey);
}

int DSA_sign_hash(const unsigned char* in, unsigned long in_len, unsigned char* out, unsigned long* out_len, const dsa_key* prikey){
   prng_state prng;
   int err = 0;

   /* register yarrow */
   if (register_prng(&yarrow_desc) == -1) {
      printf("Error registering Yarrow\n");
      return -1;
   }
   /* setup the PRNG */
   if ((err = rng_make_prng(128, find_prng("yarrow"), &prng, NULL)) != CRYPT_OK) {
      printf("Error setting up PRNG, %s\n", error_to_string(err));
      return -1;
   }

   dsa_sign_hash(in, in_len, out, out_len, &prng, find_prng("yarrow"), prikey);
   return CRYPT_OK;
}

int DSA_sign_verify(const unsigned char* sig, unsigned long sig_len, const unsigned char* hash, unsigned long hash_len, int* stat, const dsa_key* prikey){
   return dsa_verify_hash(sig, sig_len, hash, hash_len, stat, prikey);
}

int rand_bn_bits(void *N, int bits, prng_state *prng, int wprng)
{
   int res, bytes;
   unsigned char *buf, mask;

   LTC_ARGCHK(N != NULL);
   LTC_ARGCHK(bits > 1);

   /* check PRNG */
   if ((res = prng_is_valid(wprng)) != CRYPT_OK) return res;

   bytes = (bits+7) >> 3;
   mask = 0xff << (8 - bits % 8);

   /* allocate buffer */
   if ((buf = (unsigned char *)XCALLOC(1, bytes)) == NULL) return CRYPT_MEM;

   /* generate random bytes */
   if (prng_descriptor[wprng].read(buf, bytes, prng) != (unsigned long)bytes) {
      res = CRYPT_ERROR_READPRNG;
      goto cleanup;
   }
   /* mask bits */
   buf[0] &= ~mask;
   /* load value */
   if ((res = ltc_mp.unsigned_read(N, buf, bytes)) != CRYPT_OK) goto cleanup;

   res = CRYPT_OK;

cleanup:
#ifdef LTC_CLEAN_STACK
   zeromem(buf, bytes);
#endif
   XFREE(buf);
   return res;
}

int DSA_Batch_sign_hash_raw(const unsigned char* in, unsigned long inlen, void* r, void* s, prng_state* prng, int wprng, const dsa_key* prikey){
   void *k, *kinv, *tmp;
   unsigned char *buf;
   int err, qbits;

   LTC_ARGCHK(in != NULL);
   LTC_ARGCHK(r != NULL);
   LTC_ARGCHK(s != NULL);
   LTC_ARGCHK(prikey != NULL);

   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }
   if (prikey->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }
   if (prikey->qord >= LTC_MDSA_MAX_GROUP) {
      return CRYPT_INVALID_ARG;
   }
   buf = (unsigned char *)XMALLOC(LTC_MDSA_MAX_GROUP);
   if (buf == NULL) {
      return CRYPT_MEM;
   }

   if ((err = mp_init_multi(&k, &kinv, &tmp, NULL)) != CRYPT_OK) {
      goto ERRBUF;
   }
   qbits = mp_count_bits(prikey->q);

retry:
   do {
      // 生成随机数K
      if ((err = rand_bn_bits(k, qbits, prng, wprng)) != CRYPT_OK) {
         goto error;
      }
      if (mp_cmp_d(k, 0) != LTC_MP_GT || mp_cmp(k, prikey->q) != LTC_MP_LT) {
         goto retry;
      }
      if ((err = mp_gcd(k, prikey->q, tmp)) != CRYPT_OK) {
         goto error;
      }
   } while (mp_cmp_d(tmp, 1) != LTC_MP_EQ);

   // K的逆元
   if ((err = mp_invmod(k, prikey->q, kinv)) != CRYPT_OK) {
      goto error;
   }

   // 签名r = g^k mod p
   if ((err = mp_exptmod(prikey->g, k, prikey->p, r)) != CRYPT_OK) {
      goto error;
   }
   ////////////
   /*
   if((err = mp_mod(r, prikey->q, r)) != CRYPT_OK) {
      goto error;
   }
   */
   ////////////
   if (mp_iszero(r) == LTC_MP_YES) {
      goto retry;
   }

   // ?
   inlen = MIN(inlen, (unsigned long)(prikey->qord));

   // 签名s = (in + xr)/k mod q
   if ((err = mp_read_unsigned_bin(tmp, (unsigned char*)in, inlen)) != CRYPT_OK) {
      goto error;
   }
   if ((err = mp_mul(prikey->x, r, s)) != CRYPT_OK) {
      goto error;
   }
   if ((err = mp_add(s, tmp, s)) != CRYPT_OK) {
      goto error;
   }
   if ((err = mp_mulmod(s, kinv, prikey->q, s)) != CRYPT_OK) {
      goto error;
   }
   if (mp_iszero(s) == LTC_MP_YES) {
      goto retry;
   }
   err = CRYPT_OK;
error:
   mp_clear_multi(k, kinv, tmp, NULL);
ERRBUF:
#ifdef LTC_CLEAN_STACK
   zeromem(buf, LTC_MDSA_MAX_GROUP);
#endif
   XFREE(buf);
   return err;
}

int DSA_Batch_verify_hash_raw(void* r[], void* s[], const unsigned char* hash[], unsigned long hashlen[], int* stat, const dsa_key prikey[], int para_len){
   const int plen = para_len;
   void *w[plen], *v[plen], *u1[plen], *u2[plen];
   void *Left, *Right;
   int err;

   LTC_ARGCHK(r != NULL);
   LTC_ARGCHK(s != NULL);
   LTC_ARGCHK(stat != NULL);
   LTC_ARGCHK(prikey != NULL);

   *stat = 0;
   mp_init_multi(&Left, &Right, NULL);

   for (int i = 0; i < plen; i++) {
      if ((err = mp_init_multi(&(w[i]), &(v[i]), &(u1[i]), &(u2[i]), NULL)) != CRYPT_OK) {
         return err;
      }
      // r和s不能为空。(原始DSA不能大于q)
      /*
      if (mp_cmp_d(r, 0) != LTC_MP_GT || mp_cmp_d(s, 0) != LTC_MP_GT || mp_cmp(r, prikey->q) != LTC_MP_LT || mp_cmp(s, prikey->q) != LTC_MP_LT) {
         err = CRYPT_INVALID_PACKET;
         goto error;
      }
      */
      if (mp_cmp_d(r[i], 0) != LTC_MP_GT || mp_cmp_d(s[i], 0) != LTC_MP_GT) {
         err = CRYPT_INVALID_PACKET;
         goto error;
      }

      hashlen[i] = MIN(hashlen[i], (unsigned long)(prikey[i].qord));

      // w = s^-1 mod q
      if ((err = mp_invmod(s[i], prikey[i].q, w[i])) != CRYPT_OK) {
         goto error;
      }
      // u1 = m*w mod q
      if ((err = mp_read_unsigned_bin(u1[i], (unsigned char*)hash[i], hashlen[i])) != CRYPT_OK) {
         goto error;
      }
      if ((err = mp_mulmod(u1[i], w[i], prikey[i].q, u1[i])) != CRYPT_OK) {
         goto error;
      }

      // u2 = r*w mod q
      if ((err = mp_mulmod(r[i], w[i], prikey[i].q, u2)) != CRYPT_OK) {
         goto error;
      }

      // Left = g^u1 * y^u2 mod p
      if ((err = mp_exptmod(prikey[i].g, u1[i], prikey[i].p, u1[i])) != CRYPT_OK) {
         goto error;
      }
      if ((err = mp_exptmod(prikey[i].y, u2[i], prikey[i].p, u2[i])) != CRYPT_OK) {
         goto error;
      }
      if ((err = mp_mulmod(u1[i], u2[i], prikey[i].p, v[i])) != CRYPT_OK) {
         goto error;
      }

      ////////////
      /*
      if((err = mp_mod(v, prikey->q, v)) != CRYPT_OK) {
         goto error;
      }
      */
      ////////////

      mp_add(Left, v[i], Left);
      mp_mod(Left, prikey[i].p, Left);

      mp_add(Right, r[i], Right);
      mp_mod(Right, prikey[i].p, Right);
   }

   // Left ==? Right
   if (mp_cmp(Left, Right) == LTC_MP_EQ) {
      *stat = 1;
   }
   err = CRYPT_OK;

error:
   for (int i = 0; i < plen; i++) {
      mp_clear_multi(w[i], v[i], u1[i], u2[i], NULL);
   }
   return err;
}

int DSA_Batch_sign_hash(const unsigned char* in, unsigned long inlen, unsigned char* out, unsigned long* outlen, prng_state* prng, int wprng, const dsa_key* prikey){
   void *r, *s;
   int err;

   LTC_ARGCHK(in != NULL);
   LTC_ARGCHK(out != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(prikey != NULL);

   if (mp_init_multi(&r, &s, NULL) != CRYPT_OK) {
      return CRYPT_MEM;
   }
   if ((err = DSA_Batch_sign_hash_raw(in, inlen, r, s, prng, wprng, prikey)) != CRYPT_OK) {
      goto error;
   }
   err = der_encode_sequence_multi(out, outlen, LTC_ASN1_INTEGER, 1UL, r, LTC_ASN1_INTEGER, 1UL, s, LTC_ASN1_EOL, 0UL, NULL);

error:
   mp_clear_multi(r, s, NULL);
   return err;
}

int DSA_Batch_verify_hash(const unsigned char* sig[], unsigned long siglen[], const unsigned char* hash[], unsigned long hashlen[], int* stat, const dsa_key prikey[], int para_len){
   int err;
   const int plen = para_len;
   void *r[plen], *s[plen];

   LTC_ARGCHK(stat != NULL);
   *stat = 0;

   for( int i = 0; i < para_len; i++) {
      ltc_asn1_list sig_seq[2];
      unsigned long reallen = 0;

      if ((err = mp_init_multi(&(r[i]), &(s[i]), NULL)) != CRYPT_OK) {
         return err;
      }

      LTC_SET_ASN1(sig_seq, 0, LTC_ASN1_INTEGER, r[i], 1UL);
      LTC_SET_ASN1(sig_seq, 1, LTC_ASN1_INTEGER, s[i], 1UL);

      err = der_decode_sequence_strict(sig[i], siglen[i], sig_seq, 2);
      if (err != CRYPT_OK) {
         goto LBL_ERR;
      }

      err = der_length_sequence(sig_seq, 2, &reallen);
      if (err != CRYPT_OK || reallen != siglen[i]) {
         goto LBL_ERR;
      }
   }

   err = DSA_Batch_verify_hash_raw(r, s, hash, hashlen, stat, prikey, para_len);

LBL_ERR:
   ltc_deinit_multi(r, s, NULL);
   return err;
}

int DSA_sign_NEO(const unsigned char* in, unsigned long in_len, unsigned char* out, unsigned long* out_len, const dsa_key* prikey){
   prng_state prng;
   int err = 0;

   /* register yarrow */
   if (register_prng(&yarrow_desc) == -1) {
      printf("Error registering Yarrow\n");
      return -1;
   }
   /* setup the PRNG */
   if ((err = rng_make_prng(128, find_prng("yarrow"), &prng, NULL)) != CRYPT_OK) {
      printf("Error setting up PRNG, %s\n", error_to_string(err));
      return -1;
   }

   DSA_Batch_sign_hash(in, in_len, out, out_len, &prng, find_prng("yarrow"), prikey);
   return CRYPT_OK;
}

int DSA_verify_NEO(const unsigned char* sig[], unsigned long sig_len[], const unsigned char* hash[], unsigned long hash_len[], int* stat, const dsa_key prikey[], int para_len){
   return DSA_Batch_verify_hash(sig, sig_len, hash, hash_len, stat, prikey, para_len);
}