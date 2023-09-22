package underhood

import (
  "log"
  "github.com/henrycg/simplepir/matrix"
  "github.com/ahenzinger/underhood/rlwe"
)

// We break each 64-bit (or 32-bit) element of the SimplePIR hint into limbs.
const BitsPerLimb = 4

// The hint is a matrix of 64-bit (or 32-bit) values. The decomposition splits
// the hint in two ways:
// 1) We decompose each 64-bit (or 32-bit) value into 16x (or 8x) 4-bit values
// 2) We split the hint into chunks (of n rows) that we can embed into RLWE ciphertexts.
//
type hintDecomp struct {
  hintRows uint64
  rows     uint64
  cols     uint64
  pts      [][]*rlwe.Plaintext
}

// When using 64-bit values, the SimplePIR p is 2^17, so we need to recover
// the top 17 bits of the resulting ciphertext (to perform decryption). 
// The maximum value of each limb is 2^16 (because the secret dimension
// is 2^11, the max secret value is 2, and the max limb value is 2^4-1).
// So, to accurately get the value of the top 17 bits, we need to compute 
// over only the top 8 (of 16) limbs.
const NumLimbs64 = 8

// When using 32-bit values, the SimplePIR p is 2^8, so we need to recover
// the top 8 bits of the resulting ciphertext (to perform decryption).
// The max. value of each limb is again 2^16 (in practice, it's actually 
// smaller because we use secret dimension 1408). 
// So, to accurately get the value of the top 8 bits, we need to compute
// over only the top 5 (of 8) limbs.
const NumLimbs32 = 5

// Get the 'chunk'-th chunk of 'BitsPerLimb' bits from 'v'
func getChunk(v uint64, chunk int) uint64 {
  mask := uint64((1 << BitsPerLimb) - 1)
  v &= (mask << (chunk*BitsPerLimb))
  // Shift these bits into low-order positions
  v >>= chunk*BitsPerLimb
  if v >= (1 << BitsPerLimb) {
    panic("Value is too big")
  }
  return v
}

func makePlaintext[T matrix.Elem](p *params, hint *matrix.Matrix[T], index int) []*rlwe.Plaintext {
  n := uint64(p.ctx.N())
  rows := (hint.Rows() + n - 1)/n    // Compute Hint.Rows()/n rounded up
  cols := hint.Cols()
  out := make([]*rlwe.Plaintext, int(rows*cols))
  for i := range out {
    out[i] = rlwe.NewPlaintext()    // Must be free'd later on
  }

  for c := uint64(0); c < cols; c++ {
    for r := uint64(0); r < rows; r++ {
      vals := make([]uint64, n)
      for i := uint64(0); i < n && (r*n + i) < hint.Rows(); i++ {
        v := uint64(hint.Get(r*n + i, c))

        // Get the index-th chunk of 16 bits
        vals[i] = getChunk(v, index)
      }
      out[int(r*cols + c)].Set(p.ctx, vals)
      out[int(r*cols + c)].ToNTT(p.ctx)
    }
  }

  return out
}

func decomposeHint[T matrix.Elem](p *params, hint *matrix.Matrix[T]) *hintDecomp {
  d := new(hintDecomp)
  n := p.ctx.N()
  d.rows = (hint.Rows() + n - 1)/n    // Compute Hint.Rows()/n rounded up
  d.cols = hint.Cols()
  d.hintRows = hint.Rows()

  maxLimbs := int(T(0).Bitlen()/BitsPerLimb)
  limbs := 0
  switch T(0).Bitlen() {
  case 32:
    limbs = NumLimbs32
  case 64:
    limbs = NumLimbs64
  default:
    panic("Should not reach")
  }

  d.pts = make([][]*rlwe.Plaintext, limbs)
  for b := 0; b < limbs; b++ {
    d.pts[b] = makePlaintext(p, hint, maxLimbs - b - 1)
  }

  return d
}

func (h *hintDecomp) Free() {
  for _, lst := range h.pts {
    for _, pt := range lst {
      pt.Free()
    }
  }
}

func (p *params) applyHint(hint *hintDecomp, encSkIn []CipherBlob) [][]CipherBlob {
  encSk := make([]*rlwe.Ciphertext, len(encSkIn))

  for i, v := range encSkIn {
    encSk[i] = rlwe.NewCiphertext()
    defer encSk[i].Free()

    encSk[i].Load(p.ctx, v)
  }

  limbs := len(hint.pts)
  out := make([][]CipherBlob, limbs)

  for b := 0; b < limbs; b++ {
    out[b] = p.applyHintOnce(hint, encSk, b)
  }

  return out
}

func (p *params) applyHintOnce(hint *hintDecomp, encSk []*rlwe.Ciphertext, chunk int) []CipherBlob {
  const PARALLELISM = 64

  out := make([]CipherBlob, hint.rows)
  if uint64(len(encSk)) != hint.cols {
    log.Printf("%d != %d\n", len(encSk), hint.cols)
    panic("Wrong number of encrypted SK values")
  }

  cols := int(hint.cols)
  rows := int(hint.rows)
  rowsPerChunk := (rows+PARALLELISM-1) / PARALLELISM
  ch := make(chan int, rows)

  start := 0
  for l := 0; l < PARALLELISM; l++ {
    stop := start + rowsPerChunk
    if stop > rows {
      stop = rows
    }

    go func(ch chan int, startAt, stopAt int) {
      for i := startAt; i < stopAt; i++ {
        ct := rlwe.NewCiphertext()
        defer ct.Free()
        ct.SetInnerProduct(p.ctx, encSk, hint.pts[chunk][i*cols:(i+1)*cols])
        out[i] = ct.Store()
      }
      ch <- 0
    }(ch, start, stop)
    start = stop
  }

  for l := 0; l < PARALLELISM; l++ {
    <-ch
  }

  return out
}

func (c *Client[T]) recoverAS(ans *HintAnswer) *matrix.Matrix[T] {
  sk := c.params.ctx.NewKey()
  defer sk.Free()

  sk.Load(c.params.ctx, c.outerSecret)

  out := matrix.Zeros[T](ans.MatrixRows, 1)
  maxLimbs := int(T(0).Bitlen()/BitsPerLimb)

  for b := 0; b < len(ans.HintCts); b++ {
    part := c.recoverASonce(sk, ans, b)
    part.MulConst(1 << (BitsPerLimb*(maxLimbs-b-1)))
    out.Add(part) 
  }

  return out
}

func (client *Client[T]) recoverASonce(sk *rlwe.Key, ans *HintAnswer, chunk int) *matrix.Matrix[T] {
  out := matrix.New[T](ans.MatrixRows, 1)
  n := client.params.ctx.N()

  vals := make([]uint64, n)
  cts := ans.HintCts[chunk]

  c := rlwe.NewCiphertext()
  defer c.Free()

  pt := rlwe.NewPlaintext()
  defer pt.Free()

  for i := 0; i < len(cts); i++ {
    c.Load(client.params.ctx, cts[i])
    sk.Decrypt(c, pt)

    pt.Dump(vals)
    for j := uint64(0); (j < n) && (uint64(i)*n + j < ans.MatrixRows); j++ {
      raw := fromModuloP[T](client.params.ctx.P(), uint64(vals[j]))
      out.Set(uint64(i)*n + j, 0, raw)
    }
  }
  
  return out
}
