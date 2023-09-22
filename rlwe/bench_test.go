package rlwe

import "testing"

func BenchmarkEncrypt(b *testing.B) {
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

  pt2 := NewPlaintext()
  defer pt2.Free()

  b.ResetTimer()
  for i := 0; i < b.N; i++ {
    key.Encrypt(pt, ct)
  }
}

func benchmarkPlainMulNTT(b *testing.B, useNTT bool) {
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

  if useNTT {
    pt.ToNTT(ctx)
    ct.ToNTT(ctx)
  }
  b.ResetTimer()
  for i := 0; i < b.N; i++ {
    ct.MulPlain(ctx, pt)
  }
}

func BenchmarkPlainMul(b *testing.B) {
  benchmarkPlainMulNTT(b, false)
}

func BenchmarkPlainMulNTT(b *testing.B) {
  benchmarkPlainMulNTT(b, true)
}

type IPFunc = func(*Ciphertext, *Context, []*Ciphertext, []*Plaintext)

func benchmarkIP(b *testing.B, f IPFunc) {
  ctx := NewContext()
  defer ctx.Free()

  cts := make([]*Ciphertext, b.N)
  for i := range cts {
    cts[i] = NewCiphertext()
    defer cts[i].Free()
  }

  pts := make([]*Plaintext, b.N)
  for i := range pts {
    pts[i] = NewPlaintext()
    defer pts[i].Free()
  }

  vals := make([]uint64, ctx.N())
  for i := uint64(0); i < ctx.N(); i++ {
    vals[i] = i
  }

  key := ctx.NewKey()
  defer key.Free()

  for i := range pts {
    pts[i].Set(ctx, vals)
    key.Encrypt(pts[i], cts[i])
    pts[i].ToNTT(ctx)
    cts[i].ToNTT(ctx)
  }

  b.ResetTimer()
  out := NewCiphertext()
  defer out.Free()

  f(out, ctx, cts, pts)
}

func BenchmarkInnerProduct(b *testing.B) {
  benchmarkIP(b, (*Ciphertext).SetInnerProduct)
}
