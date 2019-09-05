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

   ltc_mp = tfm_desc;

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

   return 0;
}
