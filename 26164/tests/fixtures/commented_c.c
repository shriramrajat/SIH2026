#include <openssl/evp.h>

void crypto_func() {
    // Real active call
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();

    // Line comment false positive
    // const EVP_CIPHER *legacy = EVP_aes_128_cbc();

    /*
     * Multi-line block comment false positive
     * const EVP_MD *md = EVP_md5();
     */

    /* Single-line block comment EVP_sha1() */
}
