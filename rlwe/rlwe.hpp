
#ifndef _CONTEXT_HPP
#define _CONTEXT_HPP

#include <seal/seal.h>
#include <assert.h>
#include <cmath>

using namespace std;
using namespace seal;

class CryptoContext {
  public: 
    CryptoContext(EncryptionParameters parms_in)
    : context(parms_in),
      evaluator(context),
      parms_id(parms_in.parms_id()), 
      n(parms_in.poly_modulus_degree()),
      p(parms_in.plain_modulus().value()),
      logq(context.key_context_data()->total_coeff_modulus_bit_count()) {};

    virtual ~CryptoContext() {}

    seal::SEALContext context;
    Evaluator evaluator;
    parms_id_type parms_id;

    size_t n;
    size_t p;
    size_t logq;
};

class CryptoKey {
  public:
    CryptoKey(SEALContext &context) :
      sk(KeyGenerator(context).secret_key()),
      encryptor(context, sk),
      decryptor(context, sk) {};

    inline void set_key(SEALContext &context, uint8_t *src, size_t sz) {
      this->sk.load(context, (const seal_byte*) src, sz);
      new (&encryptor) Encryptor(context, this->sk);
      new (&decryptor) Decryptor(context, this->sk);
    };

    virtual ~CryptoKey() {};

    SecretKey sk;
    Encryptor encryptor;
    Decryptor decryptor;
};

#endif
