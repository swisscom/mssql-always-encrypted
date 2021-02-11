package alwaysencrypted

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/swisscom/mssql-always-encrypted/pkg/algorithms"
	"github.com/swisscom/mssql-always-encrypted/pkg/encryption"
	"github.com/swisscom/mssql-always-encrypted/pkg/keys"
	"github.com/stretchr/testify/assert"
	"golang.org/x/text/encoding/unicode"
	"io/ioutil"
	"os"
	"testing"
)

func TestLoadCEKV(t *testing.T) {
	certFile, err := os.Open("../test/always-encrypted_pub.pem")
	if err != nil {
		t.Fatal(err)
	}

	certBytes, err := ioutil.ReadAll(certFile)
	if err != nil {
		t.Fatal(err)
	}
	pemB, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(pemB.Bytes)
	if err != nil {
		t.Fatal(nil)
	}

	cekvFile, err := os.Open("../test/cekv.key")
	if err != nil {
		t.Fatal(err)
	}
	cekvBytes, err := ioutil.ReadAll(cekvFile)

	cekv := LoadCEKV(cekvBytes)
	assert.Equal(t, 1, cekv.Version)
	assert.True(t, cekv.Verify(cert))
}
func TestDecrypt(t *testing.T) {
	certFile, err := os.Open("../test/always-encrypted.pem")
	if err != nil {
		t.Fatal(err)
	}

	certBytes, err := ioutil.ReadAll(certFile)
	if err != nil {
		t.Fatal(err)
	}
	pemB, _ := pem.Decode(certBytes)
	privKey, err := x509.ParsePKCS8PrivateKey(pemB.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	rsaPrivKey := privKey.(*rsa.PrivateKey)

	cekvFile, err := os.Open("../test/cekv.key")
	if err != nil {
		t.Fatal(err)
	}
	cekvBytes, err := ioutil.ReadAll(cekvFile)

	cekv := LoadCEKV(cekvBytes)
	rootKey, err := cekv.Decrypt(rsaPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "0ff9e45335df3dec7be0649f741e6ea870e9d49d16fe4be7437ce22489f48ead", fmt.Sprintf("%02x", rootKey))
	assert.Equal(t, 1, cekv.Version)
	assert.NotNil(t, rootKey)


	columnBytesFile, err := os.Open("../test/column_value.enc")
	if err != nil {
		t.Fatal(err)
	}

	columnBytes, err := ioutil.ReadAll(columnBytesFile)
	if err != nil {
		t.Fatal(err)
	}

	key := keys.NewAeadAes256CbcHmac256(rootKey)
	alg := algorithms.NewAeadAes256CbcHmac256Algorithm(key, encryption.Deterministic, 1)
	cleartext, err := alg.Decrypt(columnBytes)

	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	decoder := enc.NewDecoder()
	cleartextUtf8, err := decoder.Bytes(cleartext)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("column value: \"%02X\"", cleartextUtf8)
	assert.Equal(t, "12345     ", string(cleartextUtf8))
}
func TestDecryptCEK(t *testing.T) {
	certFile, err := os.Open("../test/always-encrypted.pem")
	if err != nil {
		t.Fatal(err)
	}

	certFileBytes, err := ioutil.ReadAll(certFile)
	if err != nil {
		t.Fatal(err)
	}

	pemBlock, _ := pem.Decode(certFileBytes)
	cert, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	cekvFile, err := os.Open("../test/cekv.key")
	if err != nil {
		t.Fatal(err)
	}

	cekvBytes, err := ioutil.ReadAll(cekvFile)
	if err != nil {
		t.Fatal(err)
	}

	cekv := LoadCEKV(cekvBytes)
	fmt.Printf("Cert: %v\n", cert)

	rsaKey := cert.(*rsa.PrivateKey)

	// RSA/ECB/OAEPWithSHA-1AndMGF1Padding
	bytes, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, rsaKey, cekv.Ciphertext, nil)
	fmt.Printf("Key: %02x\n", bytes)
}
