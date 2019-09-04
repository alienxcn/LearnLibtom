/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "DSA.h"

#if defined(LTC_MDSA)

int dsa_testp(void)
{
   printf("hello\n");
   unsigned char msg[16], out[1024], out2[1024], ch;
   unsigned long x, y;
   int stat1, stat2;
   dsa_key key, key2;

   if (ltc_mp.name == NULL) return CRYPT_NOP;

   /* make a random key */
   DO(dsa_generate_pqg(&yarrow_prng, find_prng("yarrow"), 20, 128, &key));
   DO(dsa_generate_key(&yarrow_prng, find_prng("yarrow"), &key));

   /* verify it */
   DO(dsa_verify_key(&key, &stat1));
   if (stat1 == 0) { fprintf(stderr, "dsa_verify_key "); return 1; }

   /* encrypt a message */
   for (ch = 0; ch < 16; ch++) { msg[ch] = ch; }
   x = sizeof(out);
   DO(dsa_encrypt_key(msg, 16, out, &x, &yarrow_prng, find_prng("yarrow"), find_hash("sha1"), &key));

   /* decrypt */
   y = sizeof(out2);
   DO(dsa_decrypt_key(out, x, out2, &y, &key));

   if (y != 16 || memcmp(out2, msg, 16)) {
      fprintf(stderr, "dsa_decrypt failed, y == %lu\n", y);
      return 1;
   }

   /* sign the message */
   x = sizeof(out);
   DO(dsa_sign_hash(msg, sizeof(msg), out, &x, &yarrow_prng, find_prng("yarrow"), &key));

   /* verify it once */
   DO(dsa_verify_hash(out, x, msg, sizeof(msg), &stat1, &key));

   /* Modify and verify again */
   msg[0] ^= 1;
   DO(dsa_verify_hash(out, x, msg, sizeof(msg), &stat2, &key));
   msg[0] ^= 1;
   if (!(stat1 == 1 && stat2 == 0)) { fprintf(stderr, "dsa_verify %d %d", stat1, stat2); return 1; }

   /* test exporting it */
   y = sizeof(out2);
   DO(dsa_export(out2, &y, PK_PRIVATE, &key));
   DO(dsa_import(out2, y, &key2));

   /* verify a signature with it */
   DO(dsa_verify_hash(out, x, msg, sizeof(msg), &stat1, &key2));
   if (stat1 == 0) { fprintf(stderr, "dsa_verify (import private) %d ", stat1); return 1; }
   dsa_free(&key2);

   /* export as public now */
   y = sizeof(out2);
   DO(dsa_export(out2, &y, PK_PUBLIC, &key));

   DO(dsa_import(out2, y, &key2));
   /* verify a signature with it */
   DO(dsa_verify_hash(out, x, msg, sizeof(msg), &stat1, &key2));
   if (stat1 == 0) { fprintf(stderr, "dsa_verify (import public) %d ", stat1); return 1; }
   dsa_free(&key2);
   dsa_free(&key);

   return 0;
}

#else

int dsa_testp(void)
{
  return CRYPT_NOP;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  a1f6312416ef6cd183ee62db58b640dc2d7ec1f4 */
/* commit time: 2019-09-04 13:44:47 +0200 */
