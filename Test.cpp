//
// Created by Liming Shao on 2018/4/17.
// Modified by alienx on 2019/9/9.
//

#include "Test.h"
#include <stdio.h>
#include <string.h>
#include "AES.h"
#include "DSA.h"

int AES_Test() {
    AES_ECB_Test();
    AES_CBC_Test();
    AES_CTR_Test();
    return 0;
}

int DSA_Test(){
    printf("DSA Test:\n");
    ltc_mp = tfm_desc;
    // dsa_testp();
    // Test: 通过p、q、g参数来生成DSA密钥。
    dsa_key prikey, pubkey;
    const char *hex_g = "3B92E4FF5929150B08995A7BF2AD1440556FA047FF9099B344B3D4FC451505AE6722439CBA3710A5894737ECCCF5AEADA8B47A35CB9D935CEDE6B07E9694C4A60C7DD6708A094F814A0EC213FBEB16BFEAA4F456FF723005DE8A443FBEC6852655D62D1D1EDB15DAA445833C1797980B8D87F3490D90BDA9AB676E87687223DC";
    const char *hex_p = "C50A37515CABD618D5A270BD4A6F6B4AF9E139950F2B99387D9A64D64CB5967ADCEDACA8ACC61B655ADEDB0061251A182CEEA10790625E4D123190C70321FA09E7B173D78EAFDBFDBFB3EFADD1A12A036DE706924A852AFF7A0166531FEAC66741845AC06CED62F9C2626205A4FA48A066EC35C9A811FEB981ABEEBE31B6BFCF";
    const char *hex_q = "AA5BD7F4E5062413E58835CA00C7A635716194C5";
    const char *hex_x = "9936E5E4E9FB28BE91F5065FE8C935B3F5D81FC5";
    const char *hex_y = "5316B0FBBF598A5E5595C14FAC43B80853E6CF0D9223FAB184595239BFCBF22D383ADD935205497E2B12C46173E36F54BD96E5A7AAA95A58A4B767D2C0BDC81EB13A124F98C005EF395D6ABAB70B3BD8B795DD796EA2D28473470388B464D9B9B84FF1C934BBF97366F57C2E11FEC331E60838596781EB6D4127D70D74AFA035";
    DSA_generator_from_pqg(hex_g, hex_p, hex_q, hex_x, hex_y, &prikey, &pubkey);
    
    // Test: 随机生成p、q、g参数来生成DSA密钥。
    dsa_key prikey2;
    DSA_generator_from_pqg_random(&prikey2);

    // Test: DSA加解密。
    unsigned char msg[16], out[1024], out2[1024];
    unsigned long msg_len = sizeof(msg), x = sizeof(out), y = sizeof(out2);
    int enc_code = DSA_encrypt_message(msg, msg_len, out, &x, &prikey2);
    int dec_code = DSA_decrypt_messgae(out, x, out2, &y, &prikey2);
    if(enc_code != 0 || dec_code != 0 || y != msg_len || memcmp(out2, msg, msg_len)){
        printf("DSA Decrypt Failed!\n");
    } else {
        printf("DSA Decrypt Successed!\n");
    }

    // Test: DSA签名。
    int stat1 = 0, stat2 = 0;
    DSA_sign_hash(msg, msg_len, out, &x, &prikey2);
    dsa_verify_hash(out, x, msg, msg_len, &stat1, &prikey2);
    msg[0] ^= 1;
    dsa_verify_hash(out, x, msg, msg_len, &stat2, &prikey2);
    msg[0] ^= 1;
    if (stat1 == 1 && stat2 == 0) {
        printf("DSA Sign Successed!\n");
    } else {
        printf("DSA Sign Failed!\n");
    }
    return 0;
}

int AES_ECB_Test() {
    printf("\nAES_ECB_Test\n");
    unsigned char key[]="1234567890123456";

    const char *pt = "Advanced Encryption Standard, ECB.";
    uint8_t *ct = NULL, *ot = NULL;
    uint32_t cl = 0, ol = 0;

    PaddingType type = PKCS7;
//    PaddingType type = ZEROPADDING;

    AES_ECB(key, sizeof(key)-1, (uint8_t*)pt, (uint32_t)strlen(pt), &ct, &cl, ENCRYPTION, type);
    AES_ECB(key, sizeof(key)-1, ct, cl, &ot, &ol, DECRYPTION, type);

    printf("AES EBC plain before enc:\t%s\n", (char*)pt);
    printf("AES ECB cipher data HEX:\t%s\n", toHex(ct, cl));
    printf("AES ECB cipher data Base64:\t%s\n", toBase64(ct, cl));
    printf("AES EBC plain after dec:\t%s\n", (char*)ot);

    return 0;
}

int AES_CBC_Test() {
    printf("\nAES_CBC_Test\n");
    unsigned char key[]="1234567890123456";
    unsigned char iv[]="abcdefghijklmnop";

    const char *pt = "Advanced Encryption Standard, CBC.";
    uint8_t *ct = NULL, *ot = NULL;
    uint32_t cl = 0, ol = 0;

    PaddingType type = PKCS7;
//    PaddingType type = ZEROPADDING;

    AES_CBC(key, sizeof(key)-1, iv, sizeof(iv)-1,(uint8_t*)pt,(uint32_t)strlen(pt), &ct, &cl, ENCRYPTION, type);
    AES_CBC(key, sizeof(key)-1, iv, sizeof(iv)-1, ct, cl, &ot, &ol, DECRYPTION, type);

    printf("AES CBC plain before enc:\t%s\n", (char*)pt);
    printf("AES CBC cipher data HEX:\t%s\n", toHex(ct, cl));
    printf("AES CBC cipher data Base64:\t%s\n", toBase64(ct, cl));
    printf("AES CBC plain after dec:\t%s\n", (char*)ot);

    return 0;
}

int AES_CTR_Test() {

    printf("\nAES_CTR_Test\n");
    unsigned char key[]="1234567890123456";
    unsigned char iv[]="abcdefghijklmnop";

    const char *pt = "Hello";
    uint8_t *ct = NULL, *ot = NULL;
    uint32_t cl = 0, ol = 0;

    AES_CTR(key, sizeof(key)-1, iv, sizeof(iv)-1,(uint8_t*)pt,(uint32_t)strlen(pt), &ct, &cl, ENCRYPTION);
    AES_CTR(key, sizeof(key)-1, iv, sizeof(iv)-1, ct, cl, &ot, &ol, DECRYPTION);

    printf("AES CTR plain before enc:\t%s\n", (char*)pt);
    printf("AES CTR cipher data HEX:\t%s\n", toHex(ct, cl));
    printf("AES CTR cipher data Base64:\t%s\n", toBase64(ct, cl));
    printf("AES CTR plain after dec:\t%s\n", (char*)ot);

    return 0;
}
