package underhood

import (
  "log"
  "time"
  "testing"
  "github.com/henrycg/simplepir/lwe"
  "github.com/henrycg/simplepir/rand"
  "github.com/henrycg/simplepir/pir"
  "github.com/henrycg/simplepir/matrix"
)

func testLHE[IntT matrix.Elem](t *testing.T, dbSize uint64, runs int) {
  pMod := uint64(512)
  seed := rand.RandomPRGKey() // matrix A seed
  params := lwe.NewParamsFixedP(IntT(0).Bitlen(), 1<<10, pMod)
  db := pir.NewDatabaseRandomFixedParams[IntT](rand.NewRandomBufPRG(), dbSize, 1, params)

  server := NewServer(db, seed)
  defer server.Free()

  for i := 0; i < runs; i++ {
    client := NewClient[IntT](seed, db.Info)
    defer client.Free()

    // Token-generation phase
    hq := client.HintQuery()
    start := time.Now()
    hans := server.HintAnswer(hq)
    elapsed := time.Since(start)
    log.Printf(" HintApply: %v\n", elapsed)
    client.HintRecover(hans)
    client.PreprocessQueryLHE()

    // Query phase
    rng := rand.NewRandomBufPRG()
    msg := matrix.Rand[IntT](rng, db.Info.M, 1, db.Info.P())
    q := client.QueryLHE(msg)
    ans := server.Answer(q)
    msg2 := client.RecoverLHE(ans)

    msg3 := matrix.Mul(db.Data, msg)
    msg3.ModConst(IntT(db.Info.P()))

    if !msg2.Equals(msg3) {
      for i := uint64(0); i < msg2.Rows(); i ++ {
        if msg2.Get(i, 0) != msg3.Get(i, 0) {
          log.Printf("[%v] %v vs. %v", i, msg2.Get(i, 0), msg3.Get(i, 0))
        }
      }
      t.Fail()
    }
  }
}

func TestEncryptionSmall64(t *testing.T) {
  testLHE[matrix.Elem64](t, 1<<10, 1)
}

func TestEncryptionMed64(t *testing.T) {
  testLHE[matrix.Elem64](t, 1<<16, 1)
}

func TestEncryptionBig64(t *testing.T) {
  testLHE[matrix.Elem64](t, 1<<20, 1)
}

func TestEncryptionHuge64(t *testing.T) {
  testLHE[matrix.Elem64](t, 1<<24, 10)
}

func TestEncryptionHuge64Many(t *testing.T) {
  testLHE[matrix.Elem64](t, 1<<24, 40)
}

func TestEncryptionGigantic64(t *testing.T) {
  testLHE[matrix.Elem64](t, 1<<25, 1)
}

func TestEncryptionSmall32(t *testing.T) {
  testLHE[matrix.Elem32](t, 1<<10, 1)
}

func TestEncryptionMed32(t *testing.T) {
  testLHE[matrix.Elem32](t, 1<<16, 1)
}

func TestEncryptionBig32(t *testing.T) {
  testLHE[matrix.Elem32](t, 1<<20, 1)
}

func TestEncryptionHuge32(t *testing.T) {
  testLHE[matrix.Elem32](t, 1<<24, 1)
}

func TestEncryptionHuge32Many(t *testing.T) {
  testLHE[matrix.Elem32](t, 1<<24, 40)
}

func testLHEMixed(t *testing.T, dbSize uint64) {
  pMod := uint64(512)
  seed := rand.RandomPRGKey() // matrix A seed
  params64 := lwe.NewParamsFixedP(64, 1<<10, pMod)
  params32 := lwe.NewParamsFixedP(32, 1<<10, pMod)
  db64 := pir.NewDatabaseRandomFixedParams[matrix.Elem64](rand.NewRandomBufPRG(), dbSize, 1, params64)
  db32 := pir.NewDatabaseRandomFixedParams[matrix.Elem32](rand.NewRandomBufPRG(), dbSize, 1, params32)

  server := NewServer(db32, seed)
  defer server.Free()

  client64 := NewClient[matrix.Elem64](seed, db64.Info)
  defer client64.Free()

  client32 := NewClient[matrix.Elem32](seed, db32.Info)
  defer client32.Free()

  // Token-generation phase
  hq := client64.HintQuery()
  client32.CopySecret(client64)
  toDrop := int(db64.Info.Params.N - db32.Info.Params.N)
  *hq = (*hq)[:len(*hq)-toDrop]
  hans := server.HintAnswer(hq)

  client32.HintRecover(hans)
  client32.PreprocessQueryLHE()

  // Query phase
  rng := rand.NewRandomBufPRG()
  msg := matrix.Rand[matrix.Elem32](rng, db32.Info.M, 1, db32.Info.P())

  q := client32.QueryLHE(msg)
  ans := server.Answer(q)
  msg2 := client32.RecoverLHE(ans)

  msg3 := matrix.Mul(db32.Data, msg)
  msg3.ModConst(matrix.Elem32(db32.Info.P()))

  if !msg2.Equals(msg3) {
    log.Printf("p=%v", db32.Info.P())
    msg2.Print()
    msg3.Print()
    t.Fail()
  }
}

func TestMixedSmall(t *testing.T) {
  testLHEMixed(t, 1<<10)
}
