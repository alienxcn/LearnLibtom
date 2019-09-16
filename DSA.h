//
// Created by alienx on 2019/9/4.
//

#ifndef LIBTOM_DEMO_DSA_H
#define LIBTOM_DEMO_DSA_H

#include <tomcrypt.h>

static const unsigned char openssl_priv_dsa[] = {
  0x30, 0x82, 0x01, 0xbb, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xc5,
  0x0a, 0x37, 0x51, 0x5c, 0xab, 0xd6, 0x18, 0xd5, 0xa2, 0x70, 0xbd, 0x4a,
  0x6f, 0x6b, 0x4a, 0xf9, 0xe1, 0x39, 0x95, 0x0f, 0x2b, 0x99, 0x38, 0x7d,
  0x9a, 0x64, 0xd6, 0x4c, 0xb5, 0x96, 0x7a, 0xdc, 0xed, 0xac, 0xa8, 0xac,
  0xc6, 0x1b, 0x65, 0x5a, 0xde, 0xdb, 0x00, 0x61, 0x25, 0x1a, 0x18, 0x2c,
  0xee, 0xa1, 0x07, 0x90, 0x62, 0x5e, 0x4d, 0x12, 0x31, 0x90, 0xc7, 0x03,
  0x21, 0xfa, 0x09, 0xe7, 0xb1, 0x73, 0xd7, 0x8e, 0xaf, 0xdb, 0xfd, 0xbf,
  0xb3, 0xef, 0xad, 0xd1, 0xa1, 0x2a, 0x03, 0x6d, 0xe7, 0x06, 0x92, 0x4a,
  0x85, 0x2a, 0xff, 0x7a, 0x01, 0x66, 0x53, 0x1f, 0xea, 0xc6, 0x67, 0x41,
  0x84, 0x5a, 0xc0, 0x6c, 0xed, 0x62, 0xf9, 0xc2, 0x62, 0x62, 0x05, 0xa4,
  0xfa, 0x48, 0xa0, 0x66, 0xec, 0x35, 0xc9, 0xa8, 0x11, 0xfe, 0xb9, 0x81,
  0xab, 0xee, 0xbe, 0x31, 0xb6, 0xbf, 0xcf, 0x02, 0x15, 0x00, 0xaa, 0x5b,
  0xd7, 0xf4, 0xe5, 0x06, 0x24, 0x13, 0xe5, 0x88, 0x35, 0xca, 0x00, 0xc7,
  0xa6, 0x35, 0x71, 0x61, 0x94, 0xc5, 0x02, 0x81, 0x80, 0x3b, 0x92, 0xe4,
  0xff, 0x59, 0x29, 0x15, 0x0b, 0x08, 0x99, 0x5a, 0x7b, 0xf2, 0xad, 0x14,
  0x40, 0x55, 0x6f, 0xa0, 0x47, 0xff, 0x90, 0x99, 0xb3, 0x44, 0xb3, 0xd4,
  0xfc, 0x45, 0x15, 0x05, 0xae, 0x67, 0x22, 0x43, 0x9c, 0xba, 0x37, 0x10,
  0xa5, 0x89, 0x47, 0x37, 0xec, 0xcc, 0xf5, 0xae, 0xad, 0xa8, 0xb4, 0x7a,
  0x35, 0xcb, 0x9d, 0x93, 0x5c, 0xed, 0xe6, 0xb0, 0x7e, 0x96, 0x94, 0xc4,
  0xa6, 0x0c, 0x7d, 0xd6, 0x70, 0x8a, 0x09, 0x4f, 0x81, 0x4a, 0x0e, 0xc2,
  0x13, 0xfb, 0xeb, 0x16, 0xbf, 0xea, 0xa4, 0xf4, 0x56, 0xff, 0x72, 0x30,
  0x05, 0xde, 0x8a, 0x44, 0x3f, 0xbe, 0xc6, 0x85, 0x26, 0x55, 0xd6, 0x2d,
  0x1d, 0x1e, 0xdb, 0x15, 0xda, 0xa4, 0x45, 0x83, 0x3c, 0x17, 0x97, 0x98,
  0x0b, 0x8d, 0x87, 0xf3, 0x49, 0x0d, 0x90, 0xbd, 0xa9, 0xab, 0x67, 0x6e,
  0x87, 0x68, 0x72, 0x23, 0xdc, 0x02, 0x81, 0x80, 0x53, 0x16, 0xb0, 0xfb,
  0xbf, 0x59, 0x8a, 0x5e, 0x55, 0x95, 0xc1, 0x4f, 0xac, 0x43, 0xb8, 0x08,
  0x53, 0xe6, 0xcf, 0x0d, 0x92, 0x23, 0xfa, 0xb1, 0x84, 0x59, 0x52, 0x39,
  0xbf, 0xcb, 0xf2, 0x2d, 0x38, 0x3a, 0xdd, 0x93, 0x52, 0x05, 0x49, 0x7e,
  0x2b, 0x12, 0xc4, 0x61, 0x73, 0xe3, 0x6f, 0x54, 0xbd, 0x96, 0xe5, 0xa7,
  0xaa, 0xa9, 0x5a, 0x58, 0xa4, 0xb7, 0x67, 0xd2, 0xc0, 0xbd, 0xc8, 0x1e,
  0xb1, 0x3a, 0x12, 0x4f, 0x98, 0xc0, 0x05, 0xef, 0x39, 0x5d, 0x6a, 0xba,
  0xb7, 0x0b, 0x3b, 0xd8, 0xb7, 0x95, 0xdd, 0x79, 0x6e, 0xa2, 0xd2, 0x84,
  0x73, 0x47, 0x03, 0x88, 0xb4, 0x64, 0xd9, 0xb9, 0xb8, 0x4f, 0xf1, 0xc9,
  0x34, 0xbb, 0xf9, 0x73, 0x66, 0xf5, 0x7c, 0x2e, 0x11, 0xfe, 0xc3, 0x31,
  0xe6, 0x08, 0x38, 0x59, 0x67, 0x81, 0xeb, 0x6d, 0x41, 0x27, 0xd7, 0x0d,
  0x74, 0xaf, 0xa0, 0x35, 0x02, 0x15, 0x00, 0x99, 0x36, 0xe5, 0xe4, 0xe9,
  0xfb, 0x28, 0xbe, 0x91, 0xf5, 0x06, 0x5f, 0xe8, 0xc9, 0x35, 0xb3, 0xf5,
  0xd8, 0x1f, 0xc5
};

static const unsigned char openssl_pub_dsa[] = {
  0x30, 0x82, 0x01, 0xb6, 0x30, 0x82, 0x01, 0x2b, 0x06, 0x07, 0x2a, 0x86,
  0x48, 0xce, 0x38, 0x04, 0x01, 0x30, 0x82, 0x01, 0x1e, 0x02, 0x81, 0x81,
  0x00, 0xc5, 0x0a, 0x37, 0x51, 0x5c, 0xab, 0xd6, 0x18, 0xd5, 0xa2, 0x70,
  0xbd, 0x4a, 0x6f, 0x6b, 0x4a, 0xf9, 0xe1, 0x39, 0x95, 0x0f, 0x2b, 0x99,
  0x38, 0x7d, 0x9a, 0x64, 0xd6, 0x4c, 0xb5, 0x96, 0x7a, 0xdc, 0xed, 0xac,
  0xa8, 0xac, 0xc6, 0x1b, 0x65, 0x5a, 0xde, 0xdb, 0x00, 0x61, 0x25, 0x1a,
  0x18, 0x2c, 0xee, 0xa1, 0x07, 0x90, 0x62, 0x5e, 0x4d, 0x12, 0x31, 0x90,
  0xc7, 0x03, 0x21, 0xfa, 0x09, 0xe7, 0xb1, 0x73, 0xd7, 0x8e, 0xaf, 0xdb,
  0xfd, 0xbf, 0xb3, 0xef, 0xad, 0xd1, 0xa1, 0x2a, 0x03, 0x6d, 0xe7, 0x06,
  0x92, 0x4a, 0x85, 0x2a, 0xff, 0x7a, 0x01, 0x66, 0x53, 0x1f, 0xea, 0xc6,
  0x67, 0x41, 0x84, 0x5a, 0xc0, 0x6c, 0xed, 0x62, 0xf9, 0xc2, 0x62, 0x62,
  0x05, 0xa4, 0xfa, 0x48, 0xa0, 0x66, 0xec, 0x35, 0xc9, 0xa8, 0x11, 0xfe,
  0xb9, 0x81, 0xab, 0xee, 0xbe, 0x31, 0xb6, 0xbf, 0xcf, 0x02, 0x15, 0x00,
  0xaa, 0x5b, 0xd7, 0xf4, 0xe5, 0x06, 0x24, 0x13, 0xe5, 0x88, 0x35, 0xca,
  0x00, 0xc7, 0xa6, 0x35, 0x71, 0x61, 0x94, 0xc5, 0x02, 0x81, 0x80, 0x3b,
  0x92, 0xe4, 0xff, 0x59, 0x29, 0x15, 0x0b, 0x08, 0x99, 0x5a, 0x7b, 0xf2,
  0xad, 0x14, 0x40, 0x55, 0x6f, 0xa0, 0x47, 0xff, 0x90, 0x99, 0xb3, 0x44,
  0xb3, 0xd4, 0xfc, 0x45, 0x15, 0x05, 0xae, 0x67, 0x22, 0x43, 0x9c, 0xba,
  0x37, 0x10, 0xa5, 0x89, 0x47, 0x37, 0xec, 0xcc, 0xf5, 0xae, 0xad, 0xa8,
  0xb4, 0x7a, 0x35, 0xcb, 0x9d, 0x93, 0x5c, 0xed, 0xe6, 0xb0, 0x7e, 0x96,
  0x94, 0xc4, 0xa6, 0x0c, 0x7d, 0xd6, 0x70, 0x8a, 0x09, 0x4f, 0x81, 0x4a,
  0x0e, 0xc2, 0x13, 0xfb, 0xeb, 0x16, 0xbf, 0xea, 0xa4, 0xf4, 0x56, 0xff,
  0x72, 0x30, 0x05, 0xde, 0x8a, 0x44, 0x3f, 0xbe, 0xc6, 0x85, 0x26, 0x55,
  0xd6, 0x2d, 0x1d, 0x1e, 0xdb, 0x15, 0xda, 0xa4, 0x45, 0x83, 0x3c, 0x17,
  0x97, 0x98, 0x0b, 0x8d, 0x87, 0xf3, 0x49, 0x0d, 0x90, 0xbd, 0xa9, 0xab,
  0x67, 0x6e, 0x87, 0x68, 0x72, 0x23, 0xdc, 0x03, 0x81, 0x84, 0x00, 0x02,
  0x81, 0x80, 0x53, 0x16, 0xb0, 0xfb, 0xbf, 0x59, 0x8a, 0x5e, 0x55, 0x95,
  0xc1, 0x4f, 0xac, 0x43, 0xb8, 0x08, 0x53, 0xe6, 0xcf, 0x0d, 0x92, 0x23,
  0xfa, 0xb1, 0x84, 0x59, 0x52, 0x39, 0xbf, 0xcb, 0xf2, 0x2d, 0x38, 0x3a,
  0xdd, 0x93, 0x52, 0x05, 0x49, 0x7e, 0x2b, 0x12, 0xc4, 0x61, 0x73, 0xe3,
  0x6f, 0x54, 0xbd, 0x96, 0xe5, 0xa7, 0xaa, 0xa9, 0x5a, 0x58, 0xa4, 0xb7,
  0x67, 0xd2, 0xc0, 0xbd, 0xc8, 0x1e, 0xb1, 0x3a, 0x12, 0x4f, 0x98, 0xc0,
  0x05, 0xef, 0x39, 0x5d, 0x6a, 0xba, 0xb7, 0x0b, 0x3b, 0xd8, 0xb7, 0x95,
  0xdd, 0x79, 0x6e, 0xa2, 0xd2, 0x84, 0x73, 0x47, 0x03, 0x88, 0xb4, 0x64,
  0xd9, 0xb9, 0xb8, 0x4f, 0xf1, 0xc9, 0x34, 0xbb, 0xf9, 0x73, 0x66, 0xf5,
  0x7c, 0x2e, 0x11, 0xfe, 0xc3, 0x31, 0xe6, 0x08, 0x38, 0x59, 0x67, 0x81,
  0xeb, 0x6d, 0x41, 0x27, 0xd7, 0x0d, 0x74, 0xaf, 0xa0, 0x35
};

static unsigned char dsaparam_der[] = {
   0x30, 0x82, 0x01, 0x1e, 0x02, 0x81, 0x81, 0x00, 0xc5, 0x0a, 0x37, 0x51,
   0x5c, 0xab, 0xd6, 0x18, 0xd5, 0xa2, 0x70, 0xbd, 0x4a, 0x6f, 0x6b, 0x4a,
   0xf9, 0xe1, 0x39, 0x95, 0x0f, 0x2b, 0x99, 0x38, 0x7d, 0x9a, 0x64, 0xd6,
   0x4c, 0xb5, 0x96, 0x7a, 0xdc, 0xed, 0xac, 0xa8, 0xac, 0xc6, 0x1b, 0x65,
   0x5a, 0xde, 0xdb, 0x00, 0x61, 0x25, 0x1a, 0x18, 0x2c, 0xee, 0xa1, 0x07,
   0x90, 0x62, 0x5e, 0x4d, 0x12, 0x31, 0x90, 0xc7, 0x03, 0x21, 0xfa, 0x09,
   0xe7, 0xb1, 0x73, 0xd7, 0x8e, 0xaf, 0xdb, 0xfd, 0xbf, 0xb3, 0xef, 0xad,
   0xd1, 0xa1, 0x2a, 0x03, 0x6d, 0xe7, 0x06, 0x92, 0x4a, 0x85, 0x2a, 0xff,
   0x7a, 0x01, 0x66, 0x53, 0x1f, 0xea, 0xc6, 0x67, 0x41, 0x84, 0x5a, 0xc0,
   0x6c, 0xed, 0x62, 0xf9, 0xc2, 0x62, 0x62, 0x05, 0xa4, 0xfa, 0x48, 0xa0,
   0x66, 0xec, 0x35, 0xc9, 0xa8, 0x11, 0xfe, 0xb9, 0x81, 0xab, 0xee, 0xbe,
   0x31, 0xb6, 0xbf, 0xcf, 0x02, 0x15, 0x00, 0xaa, 0x5b, 0xd7, 0xf4, 0xe5,
   0x06, 0x24, 0x13, 0xe5, 0x88, 0x35, 0xca, 0x00, 0xc7, 0xa6, 0x35, 0x71,
   0x61, 0x94, 0xc5, 0x02, 0x81, 0x80, 0x3b, 0x92, 0xe4, 0xff, 0x59, 0x29,
   0x15, 0x0b, 0x08, 0x99, 0x5a, 0x7b, 0xf2, 0xad, 0x14, 0x40, 0x55, 0x6f,
   0xa0, 0x47, 0xff, 0x90, 0x99, 0xb3, 0x44, 0xb3, 0xd4, 0xfc, 0x45, 0x15,
   0x05, 0xae, 0x67, 0x22, 0x43, 0x9c, 0xba, 0x37, 0x10, 0xa5, 0x89, 0x47,
   0x37, 0xec, 0xcc, 0xf5, 0xae, 0xad, 0xa8, 0xb4, 0x7a, 0x35, 0xcb, 0x9d,
   0x93, 0x5c, 0xed, 0xe6, 0xb0, 0x7e, 0x96, 0x94, 0xc4, 0xa6, 0x0c, 0x7d,
   0xd6, 0x70, 0x8a, 0x09, 0x4f, 0x81, 0x4a, 0x0e, 0xc2, 0x13, 0xfb, 0xeb,
   0x16, 0xbf, 0xea, 0xa4, 0xf4, 0x56, 0xff, 0x72, 0x30, 0x05, 0xde, 0x8a,
   0x44, 0x3f, 0xbe, 0xc6, 0x85, 0x26, 0x55, 0xd6, 0x2d, 0x1d, 0x1e, 0xdb,
   0x15, 0xda, 0xa4, 0x45, 0x83, 0x3c, 0x17, 0x97, 0x98, 0x0b, 0x8d, 0x87,
   0xf3, 0x49, 0x0d, 0x90, 0xbd, 0xa9, 0xab, 0x67, 0x6e, 0x87, 0x68, 0x72,
   0x23, 0xdc
 };

int dsa_testp(void);
int DSA_generator_from_pqg(const char* g, const char* p, const char* q, const char* x, const char* y, dsa_key* prikey, dsa_key* pubkey);
int DSA_generator_from_pqg_random(dsa_key* prikey);
int DSA_encrypt_message(const unsigned char* msg, unsigned long msg_len, unsigned char* buff, unsigned long* buff_len, const dsa_key* prikey);
int DSA_decrypt_messgae(const unsigned char* buff, unsigned long buff_len, unsigned char* orimsg, unsigned long* orimsg_len, const dsa_key* prikey);
int DSA_sign_hash(const unsigned char* in, unsigned long in_len, unsigned char* out, unsigned long* out_len, const dsa_key* prikey);
int DSA_sign_verify(const unsigned char* sig, unsigned long sig_len, const unsigned char* hash, unsigned long hash_len, int* stat, const dsa_key* prikey);

int DSA_Batch_sign_hash_raw(const unsigned char* in, unsigned long inlen, void* r, void* s, prng_state* prng, int wprng, const dsa_key* prikey);
int DSA_Batch_verify_hash_raw(void* r[], void* s[], const unsigned char* hash[], unsigned long hashlen[], int* stat, const dsa_key prikey[], int para_len);
int DSA_Batch_sign_hash(const unsigned char* in, unsigned long inlen, unsigned char* out, unsigned long* outlen, prng_state* prng, int wprng, const dsa_key* prikey);
int DSA_Batch_verify_hash(const unsigned char* sig[], unsigned long siglen[], const unsigned char* hash[], unsigned long hashlen[], int* stat, const dsa_key prikey[], int para_len);

int DSA_sign_NEO(const unsigned char* in, unsigned long in_len, unsigned char* out, unsigned long* out_len, const dsa_key* prikey);
int DSA_verify_NEO(const unsigned char* sig[], unsigned long sig_len[], const unsigned char* hash[], unsigned long hash_len[], int* stat, const dsa_key prikey[], int para_len);
#endif //LIBTOM_DEMO_DSA_H