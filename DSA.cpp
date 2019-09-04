//
// Created by alienx on 2019/9/4.
//

#include "DSA.h"
#include <stdio.h>
#include <tomcrypt.h>

#if defined(LTC_MDSA)
prng_state* yarrow_prng;

int DSA_test(void){
    unsigned char msg[16], out[1024], out2[1024], ch;
    unsigned long x, y;
    int stat1, stat2;
    dsa_key key, key2;

    // make a random key
    dsa_generate_pqg(yarrow_prng, find_prng("yarrow"), 20, 128, &key);
    dsa_generate_key(yarrow_prng, find_prng("yarrow"), &key);

    dsa_verify_key(&key, &stat1);
    if(stat1 == 0){
        printf("dsa_verify_key\n");
        return 1;
    } else {
        printf("Successed!\n");
    }
}

#else
#endif