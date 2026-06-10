#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define KEY_LEN 32
#define IV_LEN  12
#define TAG_LEN 16

int crypto_encrypt(const uint8_t *plaintext, size_t pt_len,
                   const uint8_t *key, const uint8_t *iv,
                   uint8_t *ciphertext, uint8_t *tag);

int crypto_decrypt(const uint8_t *ciphertext, size_t ct_len,
                   const uint8_t *key, const uint8_t *iv,
                   const uint8_t *tag, uint8_t *plaintext);

void crypto_random_bytes(uint8_t *buf, size_t len);

#endif
