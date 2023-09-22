package underhood

import (
  "fmt"
  "github.com/henrycg/simplepir/matrix"
)

// Bound on norm of entries of secret for the "inner" encryption scheme.
// We use ternary secrets in the range [0, 1, 2].
const SecretMin = 0
const SecretMax = 2

// Handle "negative" numbers mod p. Re-express them 
// as negative numbers mod 2^64.
func fromModuloP[T matrix.Elem](p uint64, v uint64) T {
  if v >= p {
    fmt.Printf("Bad input: %v >= %v\n", v, p)
    panic("Should not happen!")
  }

  if v > p/2 {
    realVal := int64(v) - int64(p)
    return T(realVal)
  }

  return T(v)
}

// Warning: works because secret values cna't be negative!
func inRange[T matrix.Elem](val T) bool {
  if (val >= SecretMin) && (val <= SecretMax) {
    return true
  }
  return false
}

func (c *Client[T]) encryptSecret(innerSecret *matrix.Matrix[T]) (KeyBlob, []CipherBlob) {
  outerSecret := c.params.ctx.NewKey()
  defer outerSecret.Free()

  if innerSecret.Cols() != 1 {
    panic("Secret should be a column vector")
  }

  if c.params.ctx.P() < SecretMax {
    panic("P is too small to encode secret")
  }

  // Encrypt each element of the secret key in its own ciphertext
  data := innerSecret.Data()
  cts := make([]CipherBlob, len(data))
  for i := 0; i < len(innerSecret.Data()); i++ {
    if !inRange[T](data[i]) {
      fmt.Printf("At %v: %v\n", i, data[i])
      panic("Secret is not in expected range")
    }

    vals := make([]uint64, c.params.ctx.N())
    vals[0] = uint64(data[i]) // Warning: works because secret can't be negative!

    cts[i] = outerSecret.EncryptSquishedSlice(c.params.ctx, vals)
  }

  return outerSecret.Store(), cts
}
