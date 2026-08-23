#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

void setup_crypto() {
    // OpenSSL RSA generation
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    RSA_generate_key_ex(rsa, 2048, bne, NULL);

    // OpenSSL EVP Ciphers
    const EVP_CIPHER *cipher_cbc = EVP_aes_128_cbc();
    const EVP_CIPHER *cipher_gcm = EVP_aes_256_gcm();

    // OpenSSL EVP Hashes
    const EVP_MD *md_sha256 = EVP_sha256();
    const EVP_MD *md_sha1 = EVP_sha1();
    const EVP_MD *md_md5 = EVP_md5();
}

int calculate_total(int count, int price) {
    // Non-crypto code
    return count * price;
}
