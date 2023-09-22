#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
#error "You must compile SEAL with -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=off"
#endif

#ifdef __cplusplus
extern "C" {
#endif

// TODO: Make all of these real structs to
// avoid copies when passing by reference in C++
// code.
typedef struct context_s context_t;
typedef struct ciphertext_s ciphertext_t;
typedef struct plaintext_s plaintext_t;
typedef struct skey_s skey_t;

// Initialization
context_t* context_new();
void context_free(context_t *ctx);

// Debug
void context_print(context_t *ctx_in);

// Getters
size_t context_n(context_t *ctx_in);
size_t context_p(context_t *ctx_in);
size_t context_logq(context_t *ctx_in);

// Plaintext ops
plaintext_t *plaintext_new(void);
void plaintext_free(plaintext_t *pt);
void plaintext_set(plaintext_t *pt, context_t *ctx, const uint64_t *vals, size_t slots);
void plaintext_dump(plaintext_t *pt, uint64_t *vals_out, size_t slots);

void plaintext_to_NTT(plaintext_t *pt, context_t *c);


// Ciphertext ops
ciphertext_t *ciphertext_new(void);
void ciphertext_free(ciphertext_t *ct);
void ciphertext_copy(ciphertext_t *src, ciphertext_t *dst);

size_t ciphertext_size(ciphertext_t *ct_in);
void ciphertext_store(ciphertext_t *ct_in, uint8_t *dst, size_t sz);
void ciphertext_load(context_t *ctx, ciphertext_t *ct_out, uint8_t *src, size_t sz);

void ciphertext_to_NTT(context_t *c, ciphertext_t *ct);
void ciphertext_from_NTT(context_t *c, ciphertext_t *ct);

void ciphertext_multiply_plain(context_t *ctx, ciphertext_t *ct, plaintext_t *pt);
void ciphertext_add(context_t *ctx, ciphertext_t *ct, ciphertext_t *other);
void ciphertext_set_inner_product(context_t *ctx, ciphertext_t *out, ciphertext_t **cts, plaintext_t **pts, size_t len);

// Key generation
skey_t *key_new(context_t *ctx_in);
void key_free(skey_t *key_in);

void key_encrypt(skey_t *key, plaintext_t *pt, ciphertext_t *ct);
void key_decrypt(skey_t *key, ciphertext_t *ct, plaintext_t *pt);
void key_encrypt_squished(skey_t *key, plaintext_t *pt, uint8_t *dst, size_t sz);
size_t key_encrypt_squished_size(skey_t *key, plaintext_t *msg);

size_t key_size(skey_t *key);
void key_store(skey_t *key, uint8_t *dst, size_t sz);
void key_load(context_t *ctx, skey_t *key_out, uint8_t *src, size_t sz);

#ifdef __cplusplus
}
#endif
