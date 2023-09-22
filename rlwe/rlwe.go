package rlwe

// #cgo CXXFLAGS: -std=c++20 -I/usr/local/include/SEAL-4.1 -pedantic -Wall -Werror -O3 -isystem /usr/local/include -march=native -g
// #cgo LDFLAGS: -lstdc++ -lseal-4.1
// #include "rlwe.h"
import "C"

type Context struct {
  ctx *C.context_t
}

type Ciphertext C.ciphertext_t


type Plaintext C.plaintext_t


type Key struct {
  key *C.skey_t
}

func NewContext() *Context {
  return &Context{
    ctx: C.context_new(),
  }
}

func (ctx *Context) Free() {
  C.context_free(ctx.ctx)
}

func (ctx *Context) N() uint64 {
  return uint64(C.context_n(ctx.ctx))
}

func (ctx *Context) P() uint64 {
  return uint64(C.context_p(ctx.ctx))
}

func (ctx *Context) Print() {
  C.context_print(ctx.ctx)
}

func NewPlaintext() *Plaintext {
  return (*Plaintext)(C.plaintext_new())
}

func (pt *Plaintext) Free() {
  C.plaintext_free((*C.plaintext_t)(pt))
}

func (pt *Plaintext) Set(ctx *Context, vals []uint64) {
  C.plaintext_set((*C.plaintext_t)(pt), ctx.ctx, (*C.uint64_t)(&vals[0]), C.size_t(len(vals)))
}

func (pt *Plaintext) Dump(vals []uint64) { 
  C.plaintext_dump((*C.plaintext_t)(pt), (*C.uint64_t)(&vals[0]), C.size_t(len(vals)))
}

func (pt *Plaintext) ToNTT(ctx *Context) {
  C.plaintext_to_NTT((*C.plaintext_t)(pt), ctx.ctx)
}

func NewCiphertext() *Ciphertext {
  return (*Ciphertext)(C.ciphertext_new())
}

func (ct *Ciphertext) Free() {
  C.ciphertext_free((*C.ciphertext_t)(ct))
}

func (dst *Ciphertext) CopyFrom(src *Ciphertext) {
  C.ciphertext_copy((*C.ciphertext_t)(src), (*C.ciphertext_t)(dst))
}

func (ct *Ciphertext) Size() int {
  return int(C.ciphertext_size((*C.ciphertext_t)(ct)))
}

func (ct *Ciphertext) Store() []byte {
  out := make([]byte, ct.Size())
  C.ciphertext_store((*C.ciphertext_t)(ct), (*C.uint8_t)(&out[0]), C.size_t(len(out)))
  return out
}

func (ct *Ciphertext) Load(ctx *Context, in []byte) {
  C.ciphertext_load(ctx.ctx, (*C.ciphertext_t)(ct), (*C.uint8_t)(&in[0]), C.size_t(len(in)))
}

func (ct *Ciphertext) ToNTT(ctx *Context) {
  C.ciphertext_to_NTT(ctx.ctx, (*C.ciphertext_t)(ct))
}

func (ct *Ciphertext) FromNTT(ctx *Context) {
  C.ciphertext_from_NTT(ctx.ctx, (*C.ciphertext_t)(ct))
}

func (ct *Ciphertext) MulPlain(ctx *Context, pt *Plaintext) {
  C.ciphertext_multiply_plain(ctx.ctx, (*C.ciphertext_t)(ct), (*C.plaintext_t)(pt))
}

func (ct *Ciphertext) Add(ctx *Context, other *Ciphertext) {
  C.ciphertext_add(ctx.ctx, (*C.ciphertext_t)(ct), (*C.ciphertext_t)(other))
}

func (ct *Ciphertext) SetInnerProduct(ctx *Context, cts []*Ciphertext, pts []*Plaintext) {
  if len(cts) != len(pts) {
    panic("Invalid arguments")
  }

  n := len(cts)
  ctsC := make([]*C.ciphertext_t, n)
  ptsC := make([]*C.plaintext_t, n)

  for i := range ctsC {
    ctsC[i] = (*C.ciphertext_t)(cts[i])
    ptsC[i] = (*C.plaintext_t)(pts[i])
  }

  C.ciphertext_set_inner_product(ctx.ctx, 
                                 (*C.ciphertext_t)(ct),
                                 (**C.ciphertext_t)(&ctsC[0]), 
				 (**C.plaintext_t)(&ptsC[0]), 
				 C.size_t(n))
}

func (ctx *Context) NewKey() *Key {
  return &Key{
    key: C.key_new(ctx.ctx),
  }
}

func (key *Key) Free() {
  C.key_free(key.key)
}

func (key *Key) Encrypt(pt *Plaintext, ct *Ciphertext) {
  C.key_encrypt(key.key, (*C.plaintext_t)(pt), (*C.ciphertext_t)(ct))
}

func (key *Key) EncryptSquishedSize(pt *Plaintext) uint64 {
  return uint64(C.key_encrypt_squished_size(key.key, (*C.plaintext_t)(pt)))
}

func (key *Key) EncryptSquished(pt *Plaintext) []byte {
  buf := make([]byte, key.EncryptSquishedSize(pt))
  C.key_encrypt_squished(key.key, (*C.plaintext_t)(pt), (*C.uint8_t)(&buf[0]), C.size_t(len(buf)))
  return buf
}

func (key *Key) EncryptSlice(ctx *Context, in []uint64, ct *Ciphertext) {
  pt := NewPlaintext()
  pt.Set(ctx, in)
  defer pt.Free()
  key.Encrypt(pt, ct)
}

func (key *Key) EncryptSquishedSlice(ctx *Context, in []uint64) []byte {
  pt := NewPlaintext()
  pt.Set(ctx, in)
  defer pt.Free()
  return key.EncryptSquished(pt)
}

func (key *Key) EncryptZero(ctx *Context, ct *Ciphertext) {
  pt := NewPlaintext()
  pt.Set(ctx, make([]uint64, ctx.N()))
  defer pt.Free()
  key.Encrypt(pt, ct)
}

func (key *Key) Decrypt(ct *Ciphertext, pt *Plaintext) {
  C.key_decrypt(key.key, (*C.ciphertext_t)(ct), (*C.plaintext_t)(pt))
}

func (key *Key) Size() int {
  return int(C.key_size(key.key))
}

func (key *Key) Store() []byte {
  out := make([]byte, key.Size())
  C.key_store(key.key, (*C.uint8_t)(&out[0]), C.size_t(len(out)))
  return out
}

func (key *Key) Load(ctx *Context, in []byte) {
  C.key_load(ctx.ctx, key.key, (*C.uint8_t)(&in[0]), C.size_t(len(in)))
}
