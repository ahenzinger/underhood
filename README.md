# Tiptoe's linearly homomorphic encryption scheme

This repository contains the reference implementation of the cryptosystem presented in the paper ["Private Web Search with Tiptoe"](https://doi.org/10.1145/3600006.3613134) by Alexandra Henzinger, Emma Dauterman, Henry Corrigan-Gibbs, and Nickolai Zeldovich (SOSP 2023). The cryptosystem contains two components:
* a **linearly-homomorphic-encryption scheme** with high throughput and compact ciphertexts.
* a **private-information-retrieval scheme** with high throughput and no client-side storage.


The cryptosystem is described in section 6 and appendix A of the paper. At a high-level, it works by:
1. building on the high-throughput linearly homomorphic encryption scheme given in [SimplePIR](https://eprint.iacr.org/2022/949), and
2. using a second linearly homomorphic encryption scheme with compact ciphertexts to compress the server-to-client download and eliminate the client-side storage.


The code for the Tiptoe private-search-engine is available at [github.com/ahenzinger/tiptoe](https://github.com/ahenzinger/tiptoe).


*Warning: this code is a research prototype.*

## Contents
* [Overview](#overview)
* [Setup](#setup)
   * [Dependencies](#dependencies)
   * [Unit tests](#unit)
* [Using Tiptoe's private information retrieval scheme](#PIR)
   * [PIR syntax](#PIRsyntax)
   * [PIR example](#PIRexample)
* [Using Tiptoe's linearly homomorphic encryption scheme](#LHE)
   * [LHE syntax](#LHEsyntax)
   * [LHE example](#LHEexample)
* [Citation](#citation)

## Overview<a name="overview"></a>

The code is organized as follows:
* We use the implementation of SimplePIR available at [github.com/henrycg/simplepir](https://github.com/henrycg/simplepir).
* The `rlwe/` directory contains the second encryption scheme with compact ciphertexts. We use the [Microsoft SEAL](https://github.com/microsoft/SEAL) implementation of BFV encryption, based on the ring learning-with-errors assumption.
* The `underhood/` directory implements Tiptoe's cryptosystem, which composes SimplePIR with BFV encryption to eliminate the client-side SimplePIR hint.

## Setup<a name="setup"></a>

### Dependencies<a name="dependencies"></a>

To build the code, install the following dependencies:
- a C/C++ compiler (tested with GCC 11.4.0)
- [Go](https://go.dev/Go) (tested with version 1.20.2)
- [Microsoft SEAL](https://github.com/microsoft/SEAL) (tested with version 4.1.1). You must compile SEAL with `-DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=off`. We recommend also compiling with [Intel HEXL](https://github.com/intel/hexl) (`-DSEAL_USE_INTEL_HEXL=ON`) to use hardware acceleration.

Then, run:
```bash
git clone git@github.com:ahenzinger/underhood.git
cd underhood/
```

To run on systems that do not support the `-march=native` compiler flag, remove this flag from `rlwe/rlwe.go` (though this might cause some performance degradation).

### Unit tests<a name="unit"></a>

*[4s]* To run correctness tests for the RLWE code, run:
```bash
cd rlwe/
go test
cd ..
```
This command should run for roughly 4s and print `PASS`.

*[7 mins]* To run correctness tests for Tiptoe's linearly-homomorphic-encryption scheme, run:
```bash
cd underhood/
go test -run Encryption
cd ..
```
This command  runs Tiptoe's linearly homomorphic encryption scheme several times, applying random linear functions to encrypted messages of various lengths, and checks that all the outputs are correct. It should run for roughly 7 mins and prints logging information to the console. If all tests pass, it then prints `PASS`.

*[1 min]* To run correctness tests for Tiptoe's private-information-retrieval scheme, run:
```bash
cd underhood/
go test -run PIR
cd ..
```
This command runs Tiptoe's private-information-retrieval scheme over several random databases of varying sizes, and checks that the outputs are correct. It should run for roughly 1 min and prints logging information to the console. If all tests pass, it then prints `PASS`.

## Using Tiptoe's private information retrieval scheme<a name="PIR"></a>

### Syntax<a name="PIRsyntax"></a>

To use Tiptoe's private-information-retrieval scheme, import the Go package `github.com/ahenzinger/underhood/underhood`. 
Then, you can call the following routines that implement the PIR scheme:
* **Database setup**
  * `NewDatabaseRandom()` and `NewDatabase()` from [github.com/henrycg/simplepir/pir/database.go](https://github.com/henrycg/simplepir/blob/main/pir/database.go) generate a database with the given number of records, number of bits per record, and (optionally) record contents.
    
* **Server and client setup**
  * `NewServer()` takes as input a database and a public seed, and outputs a PIR server.
  * `NewClient()` takes as input public parameters about the database and a seed, and outputs a PIR client.
    
* **Methods invoked to make a PIR query**
  * `client.HintQuery()` generates the RLWE encryption of a SimplePIR secret key.
  * `server.HintAnswer()` takes as input the encrypted secret key, and returns a "token", which is the product of the server's SimplePIR hint with the encrypted key.
  * `client.HintRecover()` takes as input the token, and decrypts it with the RLWE secret key.
  * `client.PreprocessQuery()` performs the client's SimplePIR query-building operations that can happen ahead of time.
  * `client.Query()` takes as input an index, and builds the client's SimplePIR query for that index.
  * `server.Answer()` takes as input the client's SimplePIR query, and builds the server's SimplePIR answer.
  * `client.Recover()` takes as input the server's SimplePIR answer and, using the token, recovers the database record that the client wants to read (without ever needing to download the SimplePIR hint).

*Warning: the optimization that drops the lowest-order bits of the SimplePIR hint matrix (see lines 30 and 38 in `underhood/hint.go`, further described in section A.3 of the [paper](https://doi.org/10.1145/3600006.3613134)) depends on the SimplePIR parameters used. When using the PIR scheme with a different SimplePIR plaintext modulus, you may have to either (a) remove the optimization (by setting `NumLimbs64` to 16 and `NumLimbs32` to 8) or (b) ammend its parameters, to preserve correctness.*

### Example<a name="PIRexample"></a>

For an example of how to use these routines, see the method `testPIR` in the file `underhood/pir_test.go`. 
In particular, it contains the following code:
```go
// Create the server (which holds the database `db`)
seed := rand.RandomPRGKey()
server := NewServer(db, seed)
defer server.Free()

// Create the client (which makes PIR queries)
client := NewClient[IntT](seed, db.Info) 
defer client.Free()

// Token-generation phase (happens before the client knows what index it wants to read)
hq := client.HintQuery()
hans := server.HintAnswer(hq)
client.HintRecover(hans)
client.PreprocessQuery()

// Online phase (happens once the client knows what index it wants to read)
q := client.Query(idx)
ans := server.Answer(q)
msg := client.Recover(ans)
// here, `msg` is the 'idx'-th record in the server's database `db`
```

## Using Tiptoe's linearly homomorphic encryption scheme<a name="LHE"></a>

### Syntax<a name="LHEsyntax"></a>

To use Tiptoe's linearly-homomorphic encryption scheme, import the Go package `github.com/ahenzinger/underhood/underhood`. 
Then, you can call the following routines that implement the LHE scheme:

* **Linear function setup**
  * `NewDatabaseRandom()` and `NewDatabase()` from [github.com/henrycg/simplepir/pir/database.go](https://github.com/henrycg/simplepir/blob/main/pir/database.go) generate a linear function (represented as a matrix) with the given number of entries, number of bits per entries, and (optionally) entry contents.
    
* **Evaluator and encryptor setup**
  * `NewServer()` takes as input a linear function and a public seed, and outputs a server that is responsible for performing the homomorphic evaluation (i.e., applying this linear function to ciphertexts under encryption).
  * `NewClient()` takes as input public parameters and a seed, and outputs a client that is responsible for encrypting/decrypting ciphertexts.
    
* **Methods invoked to build a ciphertext, apply a linear function to the ciphertext, and then decrypt it**
  * `client.HintQuery()` generates the RLWE encryption of a SimplePIR secret key.
  * `server.HintAnswer()` takes as input the encrypted secret key, and returns a "token", which is the product of the server's "hint" data structure (which depends on the server-held linear function) with the encrypted key.
  * `client.HintRecover()` takes as input the token, and decrypts it with the RLWE secret key.
  * `client.PreprocessQueryLHE()` performs the client's SimplePIR ciphertext-building operations that can happen ahead of time.
  * `client.QueryLHE()` takes as input a message, and encrypts it to get a SimplePIR ciphertext.
  * `server.Answer()` takes as input the client's SimplePIR ciphertext, applies the server's linear function to the ciphertext, and outputs the resulting ciphertext.
  * `client.RecoverLHE()` takes as input the server's answer and, using the token, decrypts to recover its original message to which the server-held linear function has been applied.

*Warning: the optimization that drops the lowest-order bits of the SimplePIR hint matrix (see lines 30 and 38 in `underhood/hint.go`, further described in section A.3 of the [paper](https://doi.org/10.1145/3600006.3613134)) depends on the SimplePIR parameters used. When using the LHE scheme with a different SimplePIR plaintext modulus, you may have to either (a) remove the optimization (by setting `NumLimbs64` to 16 and `NumLimbs32` to 8) or (b) ammend its parameters, to preserve correctness.*

### Example<a name="LHEexample"></a>

For an example of how to use these routines, see the method `testLHE` in the file `underhood/lhe_test.go`. 
In particular, it contains the following code:
```go
// Create the server/evaluator (which applies the linear function `db` to ciphertexts)
seed := rand.RandomPRGKey()
server := NewServer(db, seed)
defer server.Free()

// Create the client/encryptor+decryptor (which builds and decrypts ciphertexts)
// `db.Info` denotes public parameters of the LHE scheme + of the linear function
client := NewClient[IntT](seed, db.Info) 
defer client.Free()

// Token-generation phase (happens before the client knows what message it wants to encrypt)
hq := client.HintQuery()
hans := server.HintAnswer(hq)
client.HintRecover(hans)
client.PreprocessQueryLHE()

// Online phase (happens once the client knows what message it wants to encrypt)
q := client.QueryLHE(msg)
ans := server.Answer(q)
msg2 := client.RecoverLHE(ans)
// here, `msg2` is the plaintext result of applying the server's linear function (`db`) to the message (`msg`) 
```

## Citation<a name="citation"></a>
```bibtex
@inproceedings{tiptoe,
      author = {Alexandra Henzinger and Emma Dauterman and Henry Corrigan-Gibbs and and Nickolai Zeldovich},
      title = {Private Web Search with {Tiptoe}},
      booktitle = {29th ACM Symposium on Operating Systems Principles (SOSP)},
      year = {2023},
      address = {Koblenz, Germany},
      month = oct,
}
```

