/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "DSA.h"

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