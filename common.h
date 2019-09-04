/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#ifndef DEMOS_COMMON_H_
#define DEMOS_COMMON_H_

#include <tomcrypt.h>

extern prng_state yarrow_prng;

#ifdef LTC_VERBOSE
#define DO(x) do { fprintf(stderr, "%s:\n", #x); run_cmd((x), __LINE__, __FILE__, #x, NULL); } while (0)
#define DOX(x, str) do { fprintf(stderr, "%s - %s:\n", #x, (str)); run_cmd((x), __LINE__, __FILE__, #x, (str)); } while (0)
#define SHOULD_FAIL(x) do { fprintf(stderr, "%s:\n", #x); run_cmd((x) != CRYPT_OK ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR, __LINE__, __FILE__, #x, NULL); } while (0)
#else
#define DO(x) do { run_cmd((x), __LINE__, __FILE__, #x, NULL); } while (0)
#define DOX(x, str) do { run_cmd((x), __LINE__, __FILE__, #x, (str)); } while (0)
#define SHOULD_FAIL(x) do { run_cmd((x) != CRYPT_OK ? CRYPT_OK : CRYPT_FAIL_TESTVECTOR, __LINE__, __FILE__, #x, NULL); } while (0)
#endif

#define COMPARE_TESTVECTOR(i, il, s, sl, wa, wi) do { DO(do_compare_testvector((i), (il), (s), (sl), (wa), (wi))); } while(0)

#if !((defined(_WIN32) || defined(_WIN32_WCE)) && !defined(__GNUC__))
#define LTC_TEST_READDIR

typedef int (*dir_iter_cb)(const void *d, unsigned long l, void* ctx);
typedef void (*dir_cleanup_cb)(void* ctx);

int test_process_dir(const char *path, void *ctx, dir_iter_cb iter, dir_cleanup_cb cleanup, const char *test);
#endif

void run_cmd(int res, int line, const char *file, const char *cmd, const char *algorithm);

void print_hex(const char* what, const void* v, const unsigned long l);

int do_compare_testvector(const void* is, const unsigned long is_len, const void* should, const unsigned long should_len, const char* what, int which);

#endif /* DEMOS_COMMON_H_ */

/* ref:         HEAD -> develop */
/* git commit:  a1f6312416ef6cd183ee62db58b640dc2d7ec1f4 */
/* commit time: 2019-09-04 13:44:47 +0200 */
