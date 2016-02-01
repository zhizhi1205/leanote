package yuyu

import (
	"bytes"
	"crypto/des"
	"errors"
)
//func main() {
//	keyStr := "RYJWh3iRSjCTpkN++UkKuVrJudN4p738"
//	key, _ := base64.StdEncoding.DecodeString(keyStr)
//	data := []byte("zhizhi1205")
//
//	out, _ := DesEncrypt(data, key)
//	fmt.Println( out)
//	fmt.Println(base64.StdEncoding.EncodeToString(out))
//	out, _ = DesDecrypt(out, key)
//	fmt.Println(string(out))
//}
//des加密ecb模式
func DesEncrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	data = PKCS5Padding(data, bs)
	if len(data)%bs != 0 {
		return nil, errors.New("Need a multiple of the blocksize")
	}
	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		block.Encrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}

	return out, nil
}

//des解密ecb模式
func DesDecrypt(data []byte, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}
	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		block.Decrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	out = PKCS5UnPadding(out)
	return out, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
