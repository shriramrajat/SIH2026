#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/dh.h>
#include <stdio.h>

void test_asymmetric() {
    RSA *rsa = RSA_generate_key_ex(rsa, 2048, NULL, NULL);
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    DH *dh = DH_new();
}

void test_symmetric() {
    const EVP_CIPHER *c1 = EVP_aes_128_cbc();
    const EVP_CIPHER *c2 = EVP_aes_256_gcm();
}

void test_hashing() {
    const EVP_MD *m1 = EVP_sha1();
    const EVP_MD *m2 = EVP_sha256();
    const EVP_MD *m3 = EVP_md5();
}

void hardcoded_secrets() {
    char *aws_key = "AKIAIOSFODNN7EXAMPLE";
    char *pwd = "secret12345";
}

// Commented out code
// EVP_aes_256_gcm();
// RSA_generate_key_ex();

void crypto_strings() {
    printf("Calling EVP_aes_128_cbc() is fast.\n");
    char *doc = "RSA_generate_key_ex is used for RSA.";
}
