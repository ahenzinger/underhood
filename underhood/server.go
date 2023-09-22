package underhood

import (
  "github.com/henrycg/simplepir/matrix"
  "github.com/henrycg/simplepir/pir"
  "github.com/henrycg/simplepir/rand"
)

type Server[T matrix.Elem] struct {
  params    *params
  pirServer *pir.Server[T]
  hint      *hintDecomp
}

// Beware! You must call Free() on the output Server to clean up C++ objects.
func NewServer[T matrix.Elem](db *pir.Database[T], matrixAseed *rand.PRGKey) *Server[T] {
  pirServer := pir.NewServerSeed(db, matrixAseed)
  params := newParams()
  return &Server[T]{
    params: params,
    pirServer: pirServer,
    hint: decomposeHint(params, pirServer.Hint()),
  }
}

// Beware! You must call Free() on the output Server to clean up C++ objects.
func NewServerHintOnly[T matrix.Elem](hintIn *matrix.Matrix[T]) *Server[T] {
  params := newParams()
  return &Server[T]{
    params: params,
    pirServer: nil,
    hint: decomposeHint(params, hintIn),
  }
}

func (s *Server[T]) Free() {
  s.hint.Free()
  s.params.ctx.Free()
}

func (s *Server[T]) HintAnswer(q *HintQuery) *HintAnswer {
  return &HintAnswer{ 
    HintCts: s.params.applyHint(s.hint, *q),
    MatrixRows: s.hint.hintRows,
  }
}

func (s *Server[T]) Answer(q *pir.Query[T]) *pir.Answer[T] {
  return s.pirServer.Answer(q)
}
