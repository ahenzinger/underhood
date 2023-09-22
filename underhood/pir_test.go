package underhood

import (
  "testing"
  "github.com/henrycg/simplepir/lwe"
  "github.com/henrycg/simplepir/rand"
  "github.com/henrycg/simplepir/pir"
  "github.com/henrycg/simplepir/matrix"
)


func testPIR[IntT matrix.Elem](t *testing.T, dbSize uint64) {
  pMod := uint64(512)
  seed := rand.RandomPRGKey() // matrix A seed
  params := lwe.NewParamsFixedP(IntT(0).Bitlen(), 1<<10, pMod)
  db := pir.NewDatabaseRandomFixedParams[IntT](rand.NewRandomBufPRG(), dbSize, 1, params)

  server := NewServer(db, seed)
  defer server.Free()

  client := NewClient[IntT](seed, db.Info)
  defer client.Free()

  // Token-generation phase
  hq := client.HintQuery()
  hans := server.HintAnswer(hq)
  client.HintRecover(hans)
  client.PreprocessQuery()

  // Query phase
  idx := uint64(7)
  q := client.Query(idx)
  ans := server.Answer(q)
  msg := client.Recover(ans)

  for row := 0; row < len(msg); row++ {
    i := uint64(row) * db.Info.M + (idx % db.Info.M)
    if db.GetElem(i) != msg[row] {
      t.Fail()
    }
  }
}

func TestPIRSmall64(t *testing.T) {
  testPIR[matrix.Elem64](t, 1<<10)
}

func TestPIRMed64(t *testing.T) {
  testPIR[matrix.Elem64](t, 1<<16)
}

func TestPIRBig64(t *testing.T) {
  testPIR[matrix.Elem64](t, 1<<20)
}

func TestPIRHuge64(t *testing.T) {
  testPIR[matrix.Elem64](t, 1<<24)
}

func TestPIRSmall32(t *testing.T) {
  testPIR[matrix.Elem32](t, 1<<10)
}

func TestPIRMed32(t *testing.T) {
  testPIR[matrix.Elem32](t, 1<<16)
}

func TestPIRBig32(t *testing.T) {
  testPIR[matrix.Elem32](t, 1<<20)
}

func TestPIRHuge32(t *testing.T) {
  testPIR[matrix.Elem32](t, 1<<24)
}
