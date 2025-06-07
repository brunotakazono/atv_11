package main

import (
    "encoding/base64"
    "fmt"
    "io/ioutil"
    "log"
	"C"

    oqs "github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {
    ciphertextB64, err := ioutil.ReadFile("ciphertext.b64")
    if err != nil {
        log.Fatalf("Erro lendo ciphertext.b64: %v", err)
    }
    privateKeyB64, err := ioutil.ReadFile("private_key.b64")
    if err != nil {
        log.Fatalf("Erro lendo private_key.b64: %v", err)
    }

    ciphertext, err := base64.StdEncoding.DecodeString(string(ciphertextB64))
    if err != nil {
        log.Fatalf("Erro decodificando ciphertext base64: %v", err)
    }
    privateKey, err := base64.StdEncoding.DecodeString(string(privateKeyB64))
    if err != nil {
        log.Fatalf("Erro decodificando private key base64: %v", err)
    }

    kem := oqs.KeyEncapsulation{}
    err = kem.Init("Kyber768", privateKey)
    if err != nil {
        log.Fatalf("Erro inicializando KEM: %v", err)
    }
    defer kem.Clean()

    sharedSecret, err := kem.DecapSecret(ciphertext)
    if err != nil {
        log.Fatalf("Erro decapsulando ciphertext: %v", err)
    }

    fmt.Println(base64.StdEncoding.EncodeToString(sharedSecret))
}
