#include "rlwe.h"
#include "rlwe.hpp"
#include <seal/seal.h>
#include <cassert>
#include <cmath>

using namespace std;
using namespace seal;
using namespace std::chrono;

struct context_s {
  CryptoContext *ctx; 
}; 

struct ciphertext_s {
  Ciphertext ct;
  ciphertext_s() : ct(Ciphertext(MemoryPoolHandle::Global())) {};
}; 

struct plaintext_s {
  Plaintext pt;  
  plaintext_s() : pt(Plaintext(MemoryPoolHandle::Global())) {};
};

struct skey_s {
  CryptoKey key;
  skey_s(SEALContext &ctx) : key(ctx) {};
};

context_t *context_new() {
  EncryptionParameters parms(scheme_type::bfv);

  size_t poly_modulus_degree = 2048;  
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_plain_modulus(Modulus(65537));
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, 65537, {38})); 

  SEALContext test_ctx(parms);
  if (!test_ctx.parameters_set()) {
    fprintf(stdout, "ERROR %s: %s\n", 
        test_ctx.parameter_error_name(),
        test_ctx.parameter_error_message());
    assert(false);
  }

  context_t *ctx = (context_t*)malloc(sizeof *ctx);
  assert(ctx);
  ctx->ctx = new CryptoContext(parms);

  return ctx;
}

void context_free(context_t *ctx_in) {
  delete ctx_in->ctx;
  free(ctx_in);
}

void context_print(context_t *ctx) {
  const shared_ptr<const SEALContext::ContextData> ctx_data = ctx->ctx->context.key_context_data();
  assert(ctx_data->parms().scheme() == seal::scheme_type::bfv);

  cout << "BFV Encryption: " << endl;
  cout << "  Polynomial modulus degree: n = " << ctx_data->parms().poly_modulus_degree() << endl;
  cout << "  Coefficient modulus: q = " << ctx_data->total_coeff_modulus_bit_count() << "-bits" << endl;
  cout << "  Plaintext modulus: p = " << ctx_data->parms().plain_modulus().value() << endl;
  cout << "  Parameter validation (success): " << ctx->ctx->context.parameter_error_message() << endl << endl;
}

size_t context_n(context_t *ctx_in) {
  return ctx_in->ctx->n;
}

size_t context_p(context_t *ctx_in) {
  return ctx_in->ctx->p;
}

size_t context_logq(context_t *ctx_in) {
  return ctx_in->ctx->logq;
}

plaintext_t *plaintext_new(void) {
  return new plaintext_s();
}

void plaintext_free(plaintext_t *pt) {
  delete pt;
}

void plaintext_set(plaintext_t *pt, context_t *ctx_in, const uint64_t *vals, size_t slots) {
  assert(slots == ctx_in->ctx->n);

  pt->pt.resize(slots);
  for (size_t i=0; i<slots; i++) {
    assert (vals[i] < ctx_in->ctx->p);
    pt->pt[i] = vals[i];
  }
}

void plaintext_dump(plaintext_t *pt, uint64_t *vals, size_t slots) {
  assert(pt->pt.coeff_count() <= slots);
  for (size_t i=0; i<pt->pt.coeff_count(); i++) {
    vals[i] = pt->pt[i];
  }

  for (size_t i=pt->pt.coeff_count(); i<slots; i++) {
    vals[i] = 0;
  }
}

void plaintext_to_NTT(plaintext_t *pt, context_t *ctx) {
  ctx->ctx->evaluator.transform_to_ntt_inplace(pt->pt, ctx->ctx->parms_id, MemoryPoolHandle::Global());
}

ciphertext_t *ciphertext_new(void) {
  return new ciphertext_s();
}

void ciphertext_free(ciphertext_t *ct) {
  delete ct;
}

void ciphertext_copy(ciphertext_t *src, ciphertext_t *dst) {
  dst->ct = src->ct;
}

size_t ciphertext_size(ciphertext_t *ct) {
  return static_cast<size_t>(ct->ct.save_size(compr_mode_type::none));
}

void ciphertext_store(ciphertext_t *ct, uint8_t *dst, size_t sz) {
  ct->ct.save((seal_byte*) dst, sz, compr_mode_type::none);
}

void ciphertext_load(context_t *ctx, ciphertext_t *ct_out, uint8_t *src, size_t sz) {
  ct_out->ct.load(ctx->ctx->context, (const seal_byte*) src, sz);
}

void ciphertext_to_NTT(context_t *ctx, ciphertext_t *ct) {
  ctx->ctx->evaluator.transform_to_ntt_inplace(ct->ct);
}

void ciphertext_from_NTT(context_t *ctx, ciphertext_t *ct) {
  ctx->ctx->evaluator.transform_from_ntt_inplace(ct->ct);
}

// Note: need to disable SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT
void ciphertext_multiply_plain(context_t *ctx, ciphertext_t *ct, plaintext_t *pt) {
  ctx->ctx->evaluator.multiply_plain_inplace(ct->ct, pt->pt, MemoryPoolHandle::Global());
}

void ciphertext_add(context_t *ctx, ciphertext_t *ct, ciphertext_t *other) {
  ctx->ctx->evaluator.add_inplace(ct->ct, other->ct);
}

void ciphertext_set_inner_product(context_t *ctx, ciphertext_t *out, ciphertext_t **cts, plaintext_t **pts, size_t len) {
  for (size_t i=0; i<len; i++) {
    Ciphertext tmp = cts[i]->ct;
    ctx->ctx->evaluator.multiply_plain_inplace(tmp, pts[i]->pt);

    if (!i) {
      out->ct = tmp; 
    } else {
      ctx->ctx->evaluator.add_inplace(out->ct, tmp);
    }
  }
}

skey_t *key_new(context_t *ctx_in) {
  return new skey_s(ctx_in->ctx->context);
}

void key_free(skey_t *sk) {
  delete sk;
}

void key_encrypt(skey_t *key, plaintext_t *pt, ciphertext_t *ct) {
  key->key.encryptor.encrypt_symmetric(pt->pt, ct->ct, MemoryPoolHandle::Global());
}

void key_encrypt_squished(skey_t *key, plaintext_t *pt, uint8_t *dst, size_t sz) {
  Serializable<Ciphertext> ct = key->key.encryptor.encrypt_symmetric(pt->pt, MemoryPoolHandle::Global());
  ct.save((seal_byte*) dst, sz, compr_mode_type::none);
}

size_t key_encrypt_squished_size(skey_t *key, plaintext_t *pt) {
  Serializable<Ciphertext> cs = key->key.encryptor.encrypt_symmetric(pt->pt, MemoryPoolHandle::Global());
  return static_cast<size_t>(cs.save_size(compr_mode_type::none));
}

void key_decrypt(skey_t *key, ciphertext_t *ct, plaintext_t *pt) {
  if (key->key.decryptor.invariant_noise_budget(ct->ct) == 0) {
    cout << "Noise budget exceeded" << endl;
    assert(false);
  }
  
  //cout << "Noise budget: " << key->key.decryptor.invariant_noise_budget(ct->ct) << endl;
  key->key.decryptor.decrypt(ct->ct, pt->pt);
}

size_t key_size(skey_t *key) {
  return static_cast<size_t>(key->key.sk.save_size(compr_mode_type::none));
}

void key_store(skey_t *key, uint8_t *dst, size_t sz) {
  key->key.sk.save((seal_byte*) dst, sz, compr_mode_type::none);
}

void key_load(context_t *ctx, skey_t *key, uint8_t *src, size_t sz) {
  key->key.set_key(ctx->ctx->context, src, sz);
}
