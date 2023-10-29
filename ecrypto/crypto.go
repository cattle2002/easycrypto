package ecrypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"github.com/wumansgy/goEncrypt/rsa"
	"os"

	"github.com/tjfoc/gmsm/sm4"
	"github.com/wumansgy/goEncrypt/aes"
	"github.com/wumansgy/goEncrypt/des"
)

func RsaPublicKeyEncryptSymmetricKey(SymmetricKey []byte, publicPemKey string) (string, error) {

	cipherSymmetricKey, err := rsa.RsaEncryptToBase64(SymmetricKey, publicPemKey)
	if err != nil {
		return "", err
	}
	return cipherSymmetricKey, nil
}
func RsaPrivateKeyDecryptSymmetricKey(cipherSymmetricKey string, privatePemKey string) ([]byte, error) {
	plainSymmetricKey, err := rsa.RsaDecryptByBase64(cipherSymmetricKey, privatePemKey)
	if err != nil {
		return nil, err
	}
	return plainSymmetricKey, nil
}
func Sm2PublicKeyEncryptSymmetricKey(SymmetricKey []byte, PublicKey string) (string, error) {
	fromPem, err := x509.ReadPublicKeyFromPem([]byte(PublicKey))
	if err != nil {
		return "", err
	}
	cryptoRes, err := sm2.Encrypt(fromPem, SymmetricKey, rand.Reader, 1)
	if err != nil {
		return "", err
	}
	toString := base64.StdEncoding.EncodeToString(cryptoRes)
	return toString, nil
}
func Sm2PrivateDecryptSymmetricKey(cipherSymmetricKey string, privatePemKey string) ([]byte, error) {
	pem, err := x509.ReadPrivateKeyFromPem([]byte(privatePemKey), []byte("12345678"))
	if err != nil {
		return nil, err
	}
	plainSymmetricKey, err := sm2.Decrypt(pem, []byte(cipherSymmetricKey), 1)
	if err != nil {
		return nil, err
	}
	return plainSymmetricKey, nil
}
func AesEncrypt(data []byte, AesKey []byte, AesIv []byte) ([]byte, error) {
	if len(AesKey) != 16 {
		return nil, errors.New("aes Key is illegal")
	}
	if len(AesIv) != 16 {
		return nil, errors.New("aes iv is illegal")
	}
	cipherText, err := aes.AesCbcEncrypt(data, AesKey, AesIv)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
	//text, err := aes.AesCbcDecrypt(cipherText, []byte("1234567812345678"), []byte("1234567887654321"))
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println(string(text))
}
func AesDecrypt(cipherText []byte, AesKey []byte, AesIv []byte) ([]byte, error) {
	if len(AesKey) != 16 {
		return nil, errors.New("aes Key is illegal")
	}
	if len(AesIv) != 16 {
		return nil, errors.New("aes iv is illegal")
	}
	plainText, err := aes.AesCbcDecrypt(cipherText, AesKey, AesIv)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}
func DesEncrypt(data []byte, DesKey []byte, DesIv []byte) ([]byte, error) {
	if len(DesKey) != 8 {
		return nil, errors.New("des Key is illegal")
	}
	if len(DesIv) != 8 {
		return nil, errors.New("des Iv is illegal")
	}
	cipherText, err := des.DesCbcEncrypt(data, DesKey, DesIv)
	if err != nil {
		return nil, err
	}
	return cipherText, nil
}
func DesDecrypt(data []byte, DesKey []byte, DesIv []byte) ([]byte, error) {
	if len(DesKey) != 8 {
		return nil, errors.New("des Key is illegal")
	}
	if len(DesIv) != 8 {
		return nil, errors.New("des Iv is illegal")
	}
	plainText, err := des.DesCbcDecrypt(data, DesKey, DesIv)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}
func TripleDesEncrypt(data []byte, TripleDesKey []byte, TripleDesIv []byte) ([]byte, error) {
	if len(TripleDesKey) != 24 {
		return nil, errors.New("triple des Key is illegal")
	}
	if len(TripleDesIv) != 8 {
		return nil, errors.New("triple  des Iv illegal")
	}
	cipherText, err := des.TripleDesEncrypt(data, TripleDesKey, TripleDesIv)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return cipherText, nil
}
func TripleDesDecrypt(data []byte, TripleDesKey []byte, TripleDesIv []byte) ([]byte, error) {
	if len(TripleDesKey) != 24 {
		return nil, errors.New("triple des Key is illegal")
	}
	if len(TripleDesIv) != 8 {
		return nil, errors.New("triple  des Iv illegal")
	}
	plainText, err := des.TripleDesDecrypt(data, TripleDesKey, TripleDesIv)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}
func Sm4Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("key is not illeagl")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// 创建一个block模式
	blockMode := cipher.NewCBCEncrypter(block, make([]byte, sm4.BlockSize))
	// 填充明文
	plaintext = PKCS7Padding(plaintext, sm4.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	// 加密
	blockMode.CryptBlocks(ciphertext, plaintext)
	//toString := base64.StdEncoding.EncodeToString(ciphertext)
	return ciphertext, nil
}
func Sm4Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("key is not illeagl")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// 创建一个block模式
	blockMode := cipher.NewCBCDecrypter(block, make([]byte, sm4.BlockSize))
	//decodeString, _ := base64.StdEncoding.DecodeString(ciphertext)
	// 解密
	decryptedText := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(decryptedText, ciphertext)
	// 去除填充
	decryptedText, err = PKCS7UnPadding(decryptedText, sm4.BlockSize)
	return decryptedText, err
}
func PKCS7UnPadding(plainText []byte, blockSize int) ([]byte, error) {
	length := len(plainText)
	number := int(plainText[length-1])
	if number >= length || number > blockSize {
		return nil, errors.New("invalid plaintext")
	}
	return plainText[:length-number], nil
}
func PKCS7Padding(plainText []byte, blockSize int) []byte {
	padding := blockSize - (len(plainText) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	newText := append(plainText, padText...)
	return newText
}
func SymmetricEncrypt(algo string, data []byte) ([]byte, error) {
	if algo == "aes" {
		CipherText, err := AesEncrypt(data, []byte("1234567833333333"), []byte("0000000011111111"))
		return CipherText, err
	}
	if algo == "des" {
		CipherText, err := DesEncrypt(data, []byte("12345678"), []byte("00000000"))
		return CipherText, err
	}
	if algo == "3des" {
		CipherText, err := TripleDesEncrypt(data, []byte("123456781234567812345678"), []byte("00000000"))
		return CipherText, err
	}
	if algo == "sm4" {
		CipherText, err := Sm4Encrypt(data, []byte("1111111122222222"))
		return CipherText, err
	}
	return nil, errors.New("no algo")
}
func SymmetricDecrypt(algo string, data []byte) ([]byte, error) {
	if algo == "aes" {
		decrypt, err := AesDecrypt(data, []byte("1234567833333333"), []byte("0000000011111111"))
		return decrypt, err
	}
	if algo == "des" {
		decrypt, err := DesDecrypt(data, []byte("12345678"), []byte("00000000"))
		return decrypt, err
	}
	if algo == "3des" {
		decrypt, err := TripleDesDecrypt(data, []byte("123456781234567812345678"), []byte("00000000"))
		return decrypt, err
	}
	if algo == "sm4" {
		decrypt, err := Sm4Decrypt(data, []byte("1111111122222222"))
		return decrypt, err
	}
	return nil, errors.New("no algo")
}
func aes1() {
	encrypt, err := SymmetricEncrypt("aes", []byte("1234\\n"))
	if err != nil {
		fmt.Println(err)
	}
	decrypt, err := SymmetricDecrypt("aes", encrypt)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(decrypt))
}
func des1() {
	encrypt, err := SymmetricEncrypt("des", []byte("123^*4\\n"))
	if err != nil {
		fmt.Println(err)
	}
	decrypt, err := SymmetricDecrypt("des", encrypt)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(decrypt))
}
func des3() {
	encrypt, err := SymmetricEncrypt("3des", []byte("123^*4\\n"))
	if err != nil {
		fmt.Println(err)
	}
	decrypt, err := SymmetricDecrypt("3des", encrypt)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(decrypt))
}
func sm41() {
	encrypt, err := SymmetricEncrypt("sm4", []byte("123^*422222\\n"))
	if err != nil {
		fmt.Println(err)
	}
	decrypt, err := SymmetricDecrypt("sm4", encrypt)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(decrypt))
}

/*
through read some content from file,
then we encrypt this content,and decrypt this
cipher data,compare before encrypt hash and decrypt
hash to verify
*/

func Verify(filename string, algo string) bool {
	fb, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("error:", err)
	}
	sum256 := sha256.Sum256(fb)
	sum256Hex := fmt.Sprintf("%x", sum256)
	encrypt, err := SymmetricEncrypt(algo, fb)
	if err != nil {
		fmt.Println("error:", err)
	}
	decrypt, err := SymmetricDecrypt(algo, encrypt)
	if err != nil {
		fmt.Println("error:", err)
	}
	Dencryptsum256 := sha256.Sum256(decrypt)
	Dencryptsum256Hex := fmt.Sprintf("%x", Dencryptsum256)
	if sum256Hex == Dencryptsum256Hex {
		return true
	} else {
		return false
	}
}
