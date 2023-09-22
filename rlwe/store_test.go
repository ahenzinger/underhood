package rlwe

import (
  "testing"
)

func TestCiphertextStore(t *testing.T) {
  ctx := NewContext()
  defer ctx.Free()

  ct := NewCiphertext()
  defer ct.Free()

  pt := NewPlaintext()
  defer pt.Free()

  vals := make([]uint64, ctx.N())
  for i := uint64(0); i < ctx.N(); i++ {
    vals[i] = i
  }
  pt.Set(ctx, vals)

  key := ctx.NewKey()
  defer key.Free()

  key.Encrypt(pt, ct)

  byteArr := ct.Store()
  ct2 := NewCiphertext()
  defer ct2.Free()
  ct2.Load(ctx, byteArr)

  pt2 := NewPlaintext()
  defer pt2.Free()
  key.Decrypt(ct2, pt2)
  
  vals2 := make([]uint64, ctx.N())
  pt2.Dump(vals2)

  for i := uint64(0); i < ctx.N(); i++ {
    if vals2[i] != i {
      t.Fail()
    }
  }
}

func TestKeyStore(t *testing.T) {
  ctx := NewContext()
  defer ctx.Free()

  ct := NewCiphertext()
  defer ct.Free()

  pt := NewPlaintext()
  defer pt.Free()

  vals := make([]uint64, ctx.N())
  for i := uint64(0); i < ctx.N(); i++ {
    vals[i] = i
  }
  pt.Set(ctx, vals)

  key := ctx.NewKey()
  defer key.Free()
  key.Encrypt(pt, ct)

  keyStr := key.Store()

  key2 := ctx.NewKey()
  defer key2.Free()

  key2.Load(ctx, keyStr)

  pt2 := NewPlaintext()
  defer pt2.Free()
  key2.Decrypt(ct, pt2)
  
  vals2 := make([]uint64, ctx.N())
  pt2.Dump(vals2)

  for i := uint64(0); i < ctx.N(); i++ {
    if vals2[i] != i {
      t.Fail()
    }
  }
}
