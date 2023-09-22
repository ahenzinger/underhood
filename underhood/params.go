package underhood

import (
  rlwe "github.com/ahenzinger/underhood/rlwe"
)

type params struct {
  ctx *rlwe.Context
}

// Beware! You must call Free() on this output EncScheme to clean up C++ objects.
// The best way to do it when you use the scheme within the scope of
// one function is:
//
//    scheme := NewEncScheme(...)
//    defer scheme.Free()
//    ... rest of your code
//
// If you need to keep the EncScheme around for a while, you're on your
// own as far as managing the memory goes.
func newParams() *params {
  return &params{
    ctx: rlwe.NewContext(),
  }
}

// Must call to clean up memory
func (p *params) Free() {
  p.ctx.Free()
}
