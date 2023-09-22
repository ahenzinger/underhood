package rlwe

import (
  "log"
  "testing"
  "math/rand"
)

func TestContext(t *testing.T) {
  ctx := NewContext()
  defer ctx.Free()
  if ctx.N() <= 100 {
    t.FailNow()
  }
}

func TestPlaintext(t *testing.T) {
  ctx := NewContext()
  defer ctx.Free()
  pt := NewPlaintext()
  defer pt.Free()
}

func TestCiphertext(t *testing.T) {
  ct := NewCiphertext()
  defer ct.Free()
}

func TestEncryptDecrypt(t *testing.T) {
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

  pt2 := NewPlaintext()
  defer pt2.Free()
  key.Decrypt(ct, pt2)
  
  vals2 := make([]uint64, ctx.N())
  pt2.Dump(vals2)

  for i := uint64(0); i < ctx.N(); i++ {
    if vals[i] != i {
      t.Fail()
    }
  }
}

func TestEncryptDecryptNTT(t *testing.T) {
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

  ct.ToNTT(ctx)
  ct.FromNTT(ctx)

  pt2 := NewPlaintext()
  defer pt2.Free()
  key.Decrypt(ct, pt2)
  
  vals2 := make([]uint64, ctx.N())
  pt2.Dump(vals2)

  for i := uint64(0); i < ctx.N(); i++ {
    if vals[i] != i {
      t.Fail()
    }
  }
}

func TestEncryptMul(t *testing.T) {
  ctx := NewContext()
  defer ctx.Free()

  ct := NewCiphertext()
  defer ct.Free()

  key := ctx.NewKey()
  defer key.Free()

  // ct encrypts the constant 7
  vals := make([]uint64, ctx.N())
  vals[0] = 7
  key.EncryptSlice(ctx, vals, ct)

  for i := uint64(0); i < ctx.N(); i++ {
    vals[i] = i
  }

  pt2 := NewPlaintext()
  defer pt2.Free()
  pt2.Set(ctx, vals)

  ct.MulPlain(ctx, pt2)

  pt3 := NewPlaintext()
  defer pt3.Free()
  key.Decrypt(ct, pt3)
  
  vals3 := make([]uint64, ctx.N())
  pt3.Dump(vals3)

  for i := uint64(0); i < ctx.N(); i++ {
    if vals3[i] != (i*7) % ctx.P() {
      log.Printf("%v %v", vals3[i], (i*7) % ctx.P())
      t.Fail()
    }
  }
}

func TestEncryptMulNTT(t *testing.T) {
  ctx := NewContext()
  defer ctx.Free()

  ct := NewCiphertext()
  defer ct.Free()

  pt := NewPlaintext()
  defer pt.Free()

  vals := make([]uint64, ctx.N())
  vals[0] = 2
  pt.Set(ctx, vals)

  key := ctx.NewKey()
  defer key.Free()

  // ct encrypts the constant 2
  key.Encrypt(pt, ct)
  ct.ToNTT(ctx)

  for i := uint64(0); i < ctx.N(); i++ {
    vals[i] = i % 3
  }

  pt2 := NewPlaintext()
  defer pt2.Free()
  pt2.Set(ctx, vals)
  pt2.ToNTT(ctx)

  ct.MulPlain(ctx, pt2)
  ct.FromNTT(ctx)

  pt3 := NewPlaintext()
  defer pt3.Free()
  key.Decrypt(ct, pt3)
  
  vals3 := make([]uint64, ctx.N())
  pt3.Dump(vals3)

  for i := uint64(0); i < ctx.N(); i++ {
    if vals3[i] != ((i%3)*2)%ctx.P() {
      log.Printf("%v %v", vals3[i], i*i)
      t.Fail()
    }
  }
}

func randSlice(L int, P uint64) []uint64 {
  r := rand.New(rand.NewSource(99))
  out := make([]uint64, L)
  for i, _ := range out {
    out[i] = r.Uint64() % P
  }
  return out
}

func TestInnerProduct(t *testing.T) {
  ctx := NewContext()
  defer ctx.Free()

  key := ctx.NewKey()
  defer key.Free()

  out := NewCiphertext()
  defer out.Free()

  key.EncryptZero(ctx, out)
  trueOut := make([]uint64, ctx.N())

  L := 1527
  for i := 0; i < L; i++ {
    ct := NewCiphertext()
    pt := NewPlaintext()
    defer ct.Free()
    defer pt.Free()

    c := make([]uint64, ctx.N())
    c[0] = 10
    key.EncryptSlice(ctx, c, ct)

    p := randSlice(int(ctx.N()), 2)
    pt.Set(ctx, p)

    ct.MulPlain(ctx, pt)

    for j := 0; j < int(ctx.N()); j++ {
      trueOut[j] += ((c[0] * p[j]) % uint64(ctx.P()))
      trueOut[j] %= uint64(ctx.P())
    }

    out.Add(ctx, ct)
  }

  pout := NewPlaintext()
  defer pout.Free()
  key.Decrypt(out, pout)

  expOut := make([]uint64, ctx.N())
  pout.Dump(expOut)

  for j := 0; j < L; j++ {
    if trueOut[j] != expOut[j] {
      log.Printf("%v %v", trueOut[j], expOut[j])
      t.Fail()
    }
  }
}

func TestInnerProduct2(t *testing.T) {
  ctx := NewContext()
  defer ctx.Free()

  key := ctx.NewKey()
  defer key.Free()

  out := NewCiphertext()
  defer out.Free()

  key.EncryptZero(ctx, out)
  trueOut := make([]uint64, ctx.N())

  L := 1527
  cts := make([]*Ciphertext, L)
  pts := make([]*Plaintext, L)
  for i := 0; i < L; i++ {
    cts[i] = NewCiphertext()
    pts[i] = NewPlaintext()
    defer cts[i].Free()
    defer pts[i].Free()

    c := make([]uint64, ctx.N())
    c[0] = 10
    key.EncryptSlice(ctx, c, cts[i])

    p := randSlice(int(ctx.N()), 2)
    pts[i].Set(ctx, p)

    for j := 0; j < int(ctx.N()); j++ {
      trueOut[j] += ((c[0] * p[j]) % uint64(ctx.P()))
      trueOut[j] %= uint64(ctx.P())
    }

  }

  out.SetInnerProduct(ctx, cts, pts)

  pout := NewPlaintext()
  defer pout.Free()
  key.Decrypt(out, pout)

  expOut := make([]uint64, ctx.N())
  pout.Dump(expOut)

  for j := 0; j < L; j++ {
    if trueOut[j] != expOut[j] {
      log.Printf("%v %v", trueOut[j], expOut[j])
      t.Fail()
    }
  }
}

func TestCopy(t *testing.T) {
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
  
  ct2 := NewCiphertext()
  defer ct2.Free()
  ct2.CopyFrom(ct)

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
