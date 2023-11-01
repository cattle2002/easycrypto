package product

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/cattle2002/easycrypto/ecrypto"
	"github.com/jlaffaye/ftp"
	"os"
	"time"
)

// 创建数据产品 给定文件位置 去读取文件
func NewOriginalProduct(filePosition string) ([]byte, error) {
	fb, err := os.ReadFile(filePosition)
	if err != nil {
		return nil, err
	}
	return fb, nil
}

// 创建对称密钥 16字节
func NewOriginalSymmetricKey(length int) ([]byte, error) {
	bytes := make([]byte, length/2)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	toString := hex.EncodeToString(bytes)
	OriginalSymmetricKey, err := hex.DecodeString(toString)
	if err != nil {
		return nil, err
	}
	return OriginalSymmetricKey, nil
}

func NewEncryptOriginalSymmetricKeyEncoder(algo string, publicKeyPem string, OriginalSymmetricKey []byte) (string, error) {
	if algo == "rsa" {
		return ecrypto.RsaPublicKeyEncryptSymmetricKey(OriginalSymmetricKey, publicKeyPem)
	}
	if algo == "sm2" {
		return ecrypto.Sm2PublicKeyEncryptSymmetricKey(OriginalSymmetricKey, publicKeyPem)
	}
	return "no algo", errors.New("no algo")
}

func NewOriginalProductEncoder(algo string, OriginalSymmetricKey []byte, data []byte) ([]byte, error) {
	if algo == "aes" {
		encrypt, err := ecrypto.AesEncrypt(data, OriginalSymmetricKey, []byte("1234567812345678"))
		return encrypt, err
	}
	if algo == "sm4" {
		encrypt, err := ecrypto.Sm4Encrypt(data, OriginalSymmetricKey)
		return encrypt, err
	}
	return nil, errors.New("no algo")
}
func NewProductToFileServer(fileName string, addr string) error {
	f, err := ftp.Dial(addr, ftp.DialWithTimeout(time.Duration(10)*time.Second))
	if err != nil {
		return err
	}
	err = f.Login("GodEater", "GodEater!@#")
	if err != nil {
		return err
	}
	err = f.ChangeDir("/product")
	if err != nil {
		return err
	}
	//localFile, err := os.ReadFile(fileName)
	//localFileSize := len(localFile)
	open, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer open.Close()
	err = f.Stor(fileName, open)
	return err
}
