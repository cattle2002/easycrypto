package ecrypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"github.com/wumansgy/goEncrypt/rsa"
	"io"
	"os"
	"strings"
)

func generateRandomHexString(length int) (string, error) {
	bytes := make([]byte, length/2)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
func GenerateRsaPem() (string, string, error) {
	RsaKey, err := rsa.GenerateRsaKeyBase64(2048)
	if err != nil {
		return "", "", err
	}
	pubReader := strings.NewReader(RsaKey.PublicKey)
	privReader := strings.NewReader(RsaKey.PrivateKey)
	pubf, err := os.Create("rsapublic.pem")
	if err != nil {
		return "", "", err
	}
	privf, err := os.Create("rsaprivate.pem")
	if err != nil {
		return "", "", err
	}
	num, err := io.Copy(pubf, pubReader)
	if err != nil {
		return "", "", err
	} else {
		if int64(len(RsaKey.PublicKey)) != (num) {
			return "", "", err
		}
	}
	num, err = io.Copy(privf, privReader)
	if err != nil {
		return "", "", err
	} else {
		if int64(len(RsaKey.PrivateKey)) != (num) {
			return "", "", errors.New("write private pem error")
		}
	}
	return RsaKey.PublicKey, RsaKey.PrivateKey, nil
}
func GenerateSM2Pem() (string, string, error) {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	PrivPem, err := x509.WritePrivateKeyToPem(key, []byte("12345678"))
	if err != nil {
		return "", "", err
	}
	PublicPem, err := x509.WritePublicKeyToPem(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubf, err := os.Create("sm2publickey.pem")
	if err != nil {
		return "", "", err
	}
	reader := strings.NewReader(string(PublicPem))
	written, err := io.Copy(pubf, reader)
	if err != nil {
		return "", "", err

	} else {
		if written != int64(len(PublicPem)) {
			return "", "", errors.New("write error")
		}
	}
	privf, err := os.Create("sm2privatekey.pem")
	if err != nil {
		return "", "", err
	}
	newReader := strings.NewReader(string(PrivPem))
	written, err = io.Copy(privf, newReader)
	if err != nil {
		return "", "", err

	} else {
		if written != int64(len(PrivPem)) {
			return "", "", errors.New("write error")
		}
	}
	return string(PublicPem), string(PrivPem), nil
}
