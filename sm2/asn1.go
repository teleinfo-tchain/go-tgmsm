package sm2

import (
	"encoding/asn1"
	"io"
	"math/big"
)

type sm2Cipher struct {
	XCoordinate *big.Int
	YCoordinate *big.Int
	HASH        []byte
	CipherText  []byte
}

/*
EncryptAsn1
sm2加密，返回asn.1编码格式的密文内容
*/
func EncryptAsn1(pub *PublicKey, data []byte, rand io.Reader) ([]byte, error) {
	cipher, err := Encrypt(pub, data)
	if err != nil {
		return nil, err
	}
	return CipherMarshal(cipher)
}

/*
DecryptAsn1
sm2解密，解析asn.1编码格式的密文内容
*/
func DecryptAsn1(pub *PrivateKey, data []byte) ([]byte, error) {
	cipher, err := CipherUnmarshal(data)
	if err != nil {
		return nil, err
	}
	return Decrypt(pub, cipher)
}

/*
CipherMarshal
*sm2密文转asn.1编码格式
*sm2密文结构如下:
*  x
*  y
*  hash
*  CipherText
*/
func CipherMarshal(data []byte) ([]byte, error) {
	data = data[1:]
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64])
	hash := data[64:96]
	cipherText := data[96:]
	return asn1.Marshal(sm2Cipher{x, y, hash, cipherText})
}

/*
CipherUnmarshal
sm2密文asn.1编码格式转C1|C3|C2拼接格式
*/
func CipherUnmarshal(data []byte) ([]byte, error) {
	var cipher sm2Cipher
	_, err := asn1.Unmarshal(data, &cipher)
	if err != nil {
		return nil, err
	}
	x := cipher.XCoordinate.Bytes()
	y := cipher.YCoordinate.Bytes()
	hash := cipher.HASH
	if err != nil {
		return nil, err
	}
	cipherText := cipher.CipherText
	if err != nil {
		return nil, err
	}
	if n := len(x); n < 32 {
		x = append(zeroByteSlice()[:32-n], x...)
	}
	if n := len(y); n < 32 {
		y = append(zeroByteSlice()[:32-n], y...)
	}
	c := []byte{}
	c = append(c, x...)          // x分量
	c = append(c, y...)          // y分
	c = append(c, hash...)       // x分量
	c = append(c, cipherText...) // y分
	return append([]byte{0x04}, c...), nil
}
