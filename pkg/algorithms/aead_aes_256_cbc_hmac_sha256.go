package algorithms

import (
	"bytes"
	"fmt"
	"github.com/swisscom/mssql-always-encrypted/pkg/crypto"
	"github.com/swisscom/mssql-always-encrypted/pkg/encryption"
	"github.com/swisscom/mssql-always-encrypted/pkg/keys"
)

// https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05
// https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-TDS/%5bMS-TDS%5d.pdf

var _ Algorithm = &AeadAes256CbcHmac256Algorithm{}

type AeadAes256CbcHmac256Algorithm struct {
	algorithmVersion                        byte
	deterministic                           bool
	blockSizeBytes                          int
	keySizeBytes                            int
	minimumCipherTextLengthBytesNoAuthTag   int
	minimumCipherTextLengthBytesWithAuthTag int
	cek                                     keys.AeadAes256CbcHmac256
	version                                 []byte
	versionSize                             []byte
}

func NewAeadAes256CbcHmac256Algorithm(key keys.AeadAes256CbcHmac256, encType encryption.Type, algorithmVersion byte) AeadAes256CbcHmac256Algorithm {
	const keySizeBytes = 256 / 8
	const blockSizeBytes = 16
	const minimumCipherTextLengthBytesNoAuthTag = 1 + 2*blockSizeBytes
	const minimumCipherTextLengthBytesWithAuthTag = minimumCipherTextLengthBytesNoAuthTag + keySizeBytes

	a := AeadAes256CbcHmac256Algorithm{
		algorithmVersion:                        algorithmVersion,
		deterministic:                           encType.Deterministic,
		blockSizeBytes:                          blockSizeBytes,
		keySizeBytes:                            keySizeBytes,
		cek:                                     key,
		minimumCipherTextLengthBytesNoAuthTag:   minimumCipherTextLengthBytesNoAuthTag,
		minimumCipherTextLengthBytesWithAuthTag: minimumCipherTextLengthBytesWithAuthTag,
		version:                                 []byte{0x01},
		versionSize:                             []byte{1},
	}

	a.version[0] = algorithmVersion
	return a
}

func (a *AeadAes256CbcHmac256Algorithm) Encrypt(bytes []byte) ([]byte, error) {
	panic("implement me")
}

func (a *AeadAes256CbcHmac256Algorithm) Decrypt(ciphertext []byte) ([]byte, error) {
	// This algorithm always has the auth tag!
	minimumCiphertextLength := a.minimumCipherTextLengthBytesWithAuthTag

	if len(ciphertext) < minimumCiphertextLength {
		return nil, fmt.Errorf("invalid ciphertext length: at least %v bytes expected", minimumCiphertextLength)
	}

	idx := 0
	if ciphertext[idx] != a.algorithmVersion {
		return nil, fmt.Errorf("invalid algorithm version used: %v found but %v expected", ciphertext[idx],
			a.algorithmVersion)
	}

	idx++
	authTag := ciphertext[idx:idx+a.keySizeBytes]
	idx += a.keySizeBytes

	iv := ciphertext[idx : idx+a.blockSizeBytes]
	idx += len(iv)


	realCiphertext := ciphertext[idx:]
	ourAuthTag := a.prepareAuthTag(iv, realCiphertext)

	if bytes.Compare(ourAuthTag, authTag) != 0 {
		return nil, fmt.Errorf("invalid auth tag")
	}

	// decrypt

	aescdbc := crypto.NewAESCbcPKCS5(a.cek.EncryptionKey(), iv)
	cleartext := aescdbc.Decrypt(realCiphertext)

	return cleartext, nil

}

func (a *AeadAes256CbcHmac256Algorithm) prepareAuthTag(iv []byte, ciphertext []byte) []byte {
	var input = make([]byte, 0)
	input = append(input, a.algorithmVersion)
	input = append(input, iv...)
	input = append(input, ciphertext...)
	input = append(input, a.versionSize...)
	return crypto.Sha256Hmac(input, a.cek.MacKey())
}
