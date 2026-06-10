#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

int crypto_encrypt(const uint8_t *plaintext, size_t pt_len,
                   const uint8_t *key, const uint8_t *iv,
                   uint8_t *ciphertext, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len, ct_len;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL)) goto err;
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto err;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len)) goto err;
    ct_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) goto err;
    ct_len += len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)) goto err;
    EVP_CIPHER_CTX_free(ctx);
    return ct_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int crypto_decrypt(const uint8_t *ciphertext, size_t ct_len,
                   const uint8_t *key, const uint8_t *iv,
                   const uint8_t *tag, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len, pt_len;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL)) goto err;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto err;
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len)) goto err;
    pt_len = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag)) goto err;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) goto err;
    pt_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return pt_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

void crypto_random_bytes(uint8_t *buf, size_t len) {
    RAND_bytes(buf, len);
}
