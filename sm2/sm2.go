/*
Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sm2

// reference to ecdsa
import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/teleinfo-bif/bit-gmsm/sm3"
)

var (
	ErrInvalidMsgLen = errors.New("invalid message length, need 32 bytes")
)

var (
	default_uid = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}
)

const (
	aesIV = "IV for <SM2> CTR"
)

const (
	pubkeyCompressed   byte = 0x2 // y_bit + x coord
	pubkeyUncompressed byte = 0x4 // x coord + y coord
	pubkeyHybrid       byte = 0x6 // y_bit + x coord + y coord
)

const (
	PubKeyBytesLenCompressed   = 33
	PubKeyBytesLenUncompressed = 65
	PubKeyBytesLenHybrid       = 65
)

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

type Sm2Signature struct {
	R, S *big.Int
	V    int
}

// The SM2's private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

func SignDigitToSignData(r, s *big.Int, v int) ([]byte, error) {
	return asn1.Marshal(Sm2Signature{r, s, v})
}

func SignDataToSignDigit(sign []byte) (*big.Int, *big.Int, error) {
	var sm2Sign Sm2Signature

	_, err := asn1.Unmarshal(sign, &sm2Sign)
	if err != nil {
		return nil, nil, err
	}
	return sm2Sign.R, sm2Sign.S, nil
}

// sign format = 30 + len(z) + 02 + len(r) + r + 02 + len(s) + s, z being what follows its size, ie 02+len(r)+r+02+len(s)+s
func (priv *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	// r, s, err := Sign(priv, msg)
	sig, err := Sm2Sign(priv, msg, nil)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(sig)
}

func (priv *PrivateKey) Decrypt(data []byte) ([]byte, error) {
	return Decrypt(priv, data)
}

func (p *PublicKey) SerializeUncompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenUncompressed)
	b = append(b, pubkeyUncompressed)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}

func (pub *PublicKey) Verify(msg []byte, sign []byte) bool {
	var sm2Sign Sm2Signature

	_, err := asn1.Unmarshal(sign, &sm2Sign)
	if err != nil {
		return false
	}
	return Sm2Verify(pub, msg, nil, sm2Sign.R, sm2Sign.S)
	// return Verify(pub, msg, sm2Sign.R, sm2Sign.S)
}

func (pub *PublicKey) Encrypt(data []byte) ([]byte, error) {
	return Encrypt(pub, data)
}

var one = new(big.Int).SetInt64(1)

func intToBytes(x int) []byte {
	var buf = make([]byte, 4)

	binary.BigEndian.PutUint32(buf, uint32(x))
	return buf
}

func kdf(x, y []byte, length int) ([]byte, bool) {
	var c []byte

	ct := 1
	h := sm3.New()
	x = append(x, y...)
	for i, j := 0, (length+31)/32; i < j; i++ {
		h.Reset()
		h.Write(x)
		h.Write(intToBytes(ct))
		hash := h.Sum(nil)
		if i+1 == j && length%32 != 0 {
			c = append(c, hash[:length%32]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}

/*
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}
*/
func randFieldElement(c elliptic.Curve, rnd io.Reader) (k *big.Int, err error) {
	params := c.Params()
	intOne := new(big.Int).SetInt64(1)
	for {
		k, err = rand.Int(rnd, params.N)
		if err != nil {
			return nil, err
		}
		if k.Cmp(intOne) >= 0 {
			return k, err
		}
	}

}

func GenerateKey() (*PrivateKey, error) {
	c := P256Sm2()
	k, err := randFieldElement(c, rand.Reader)
	if err != nil {
		return nil, err
	}
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func GenerateKeyBySeed(seed []byte, strict bool) (*PrivateKey, error) {
	c := P256Sm2()
	priv := new(PrivateKey)
	priv.D = new(big.Int).SetBytes(seed)

	priv.PublicKey.Curve = c
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(seed)
	return priv, nil
}

var errZeroParam = errors.New("zero parameter")

func Sign(priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	entropylen := (priv.Curve.Params().BitSize + 7) / 16
	if entropylen > 32 {
		entropylen = 32
	}
	entropy := make([]byte, entropylen)
	_, err = io.ReadFull(rand.Reader, entropy)
	if err != nil {
		return
	}

	// Initialize an SHA-512 hash context; digest ...
	md := sha512.New()
	md.Write(priv.D.Bytes()) // the private key,
	md.Write(entropy)        // the entropy,
	md.Write(hash)           // and the input hash;
	key := md.Sum(nil)[:32]  // and compute ChopMD-256(SHA-512),
	// which is an indifferentiable MAC.

	// Create an AES-CTR instance to use as a CSPRNG.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Create a CSPRNG that xors a stream of zeros with
	// the output of the AES-CTR instance.
	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	// See [NSA] 3.4.1
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	var k *big.Int
	e := new(big.Int).SetBytes(hash)
	for { // 调整算法细节以实现SM2
		for {
			k, err = randFieldElement(c, csprng)
			if err != nil {
				r = nil
				return
			}
			r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)
			if r.Sign() != 0 {
				if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
					break
				}
			}
		}
		rD := new(big.Int).Mul(priv.D, r)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(priv.D, one)
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}
	return
}

func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	// 调整算法细节以实现SM2
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}

	var x *big.Int
	x1, y1 := c.ScalarBaseMult(s.Bytes())
	x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, _ = c.Add(x1, y1, x2, y2)

	e := new(big.Int).SetBytes(hash)
	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

func Sm2Sign(priv *PrivateKey, msg, uid []byte) ([]byte, error) {
	var (
		sign []byte
		err  error
	)
	var sig Sm2Signature
	za, err := ZA(nil, nil)
	if err != nil {
		return sign, err
	}
	e, err := msgHash(za, msg)
	if err != nil {
		return sign, err
	}
	//fmt.Printf("sign e is %v\n", e)
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return sign, err
	}
	var ry, k *big.Int

	for { // 调整算法细节以实现SM2
		for {
			k, err = randFieldElement(c, rand.Reader)

			if err != nil {
				sig.R = nil
				return sign, err
			}
			sig.R, ry = priv.Curve.ScalarBaseMult(k.Bytes())
			//rx := new(big.Int).SetBytes(sig.R.Bytes())
			//fmt.Printf("sign rx is %v\n", rx)
			//fmt.Printf("sign ry is %v\n", ry)
			sig.R.Add(sig.R, e)
			sig.R.Mod(sig.R, N)

			if sig.R.Sign() != 0 {
				intZero := new(big.Int).SetInt64(0)
				if t := new(big.Int).Add(sig.R, k); t.Cmp(N) != 0 && t.Cmp(intZero) != 0 {
					break
				}
			}
		}
		tmp := new(big.Int).Mod(ry, new(big.Int).SetInt64(2))
		if tmp.Cmp(new(big.Int).SetInt64(1)) == 0 {
			sig.V = 1 //奇数
		} else {
			sig.V = 0 //偶数
		}
		rD := new(big.Int).Mul(priv.D, sig.R)
		sig.S = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(priv.D, one)
		d1Inv := new(big.Int).ModInverse(d1, N)
		sig.S.Mul(sig.S, d1Inv)
		sig.S.Mod(sig.S, N)

		if sig.S.Sign() != 0 {
			break
		}
	}
	//fmt.Printf("sign sig.R is %v\n", sig.R)
	//fmt.Printf("sign sig.s is %v\n", sig.S)
	rlen := len(sig.R.Bytes())
	//fmt.Printf("sign sig.R len is %d\n", rlen)
	start := 0
	if rlen < 32 {
		start = 32 - rlen
	}
	sign = make([]byte, 66)
	copy(sign[start:32], sig.R.Bytes())
	copy(sign[32:64], sig.S.Bytes())
	if sig.V == 0 {
		sign[64] = 0
	} else {
		sign[64] = 1
	}
	sign[65] = 0

	return sign, err

	////fmt.Printf("sign sig is %v\n", sign)
	////R := new(big.Int).SetBytes(sign[start:32])
	////r := new(big.Int).SetBytes(sign[:32])
	////s := new(big.Int).SetBytes(sign[32:64])
	////fmt.Printf("test sign sig.R is %v\n", r)
	////fmt.Printf("test sign sig.S is %v\n", s)
	////fmt.Printf("test sign sig.R is %v\n", R)
	//
	//recoverPubKey, err := RecoverPubKey(msg, sign[:65])
	//x := new(big.Int).SetBytes(recoverPubKey[1:33])
	//y := new(big.Int).SetBytes(recoverPubKey[33:65])
	//if err == nil && priv.PublicKey.X.Cmp(x) == 0 && priv.PublicKey.Y.Cmp(y) == 0 {
	//	return sign, err
	//} else {
	//	return Sm2Sign(priv, msg, uid)
	//}
}

func Sm2Verify(pub *PublicKey, msg, uid []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N
	one := new(big.Int).SetInt64(1)
	if r.Cmp(one) < 0 || s.Cmp(one) < 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	za, err := ZA(pub, uid)
	if err != nil {
		return false
	}
	e, err := msgHash(za, msg)
	if err != nil {
		return false
	}
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}
	var x *big.Int
	x1, y1 := c.ScalarBaseMult(s.Bytes())
	x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, _ = c.Add(x1, y1, x2, y2)

	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

func msgHash(za, msg []byte) (*big.Int, error) {
	e := sm3.New()
	e.Write(za)
	e.Write(msg)
	return new(big.Int).SetBytes(e.Sum(nil)[:32]), nil
}

// ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
// 公式修正为如下
// ZA = H256(a || b || xG || yG)
func ZA(pub *PublicKey, uid []byte) ([]byte, error) {
	za := sm3.New()
	za.Write(sm2P256ToBig(&sm2P256.a).Bytes())
	za.Write(sm2P256.B.Bytes())
	za.Write(sm2P256.Gx.Bytes())
	za.Write(sm2P256.Gy.Bytes())
	return za.Sum(nil)[:32], nil
}

// 32byte
func zeroByteSlice() []byte {
	return []byte{
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
}

/*
 * sm2密文结构如下:
 *  x
 *  y
 *  hash
 *  CipherText
 */
func Encrypt(pub *PublicKey, data []byte) ([]byte, error) {
	length := len(data)
	for {
		c := []byte{}
		curve := pub.Curve
		k, err := randFieldElement(curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		x1, y1 := curve.ScalarBaseMult(k.Bytes())
		x2, y2 := curve.ScalarMult(pub.X, pub.Y, k.Bytes())
		x1Buf := x1.Bytes()
		y1Buf := y1.Bytes()
		x2Buf := x2.Bytes()
		y2Buf := y2.Bytes()
		if n := len(x1Buf); n < 32 {
			x1Buf = append(zeroByteSlice()[:32-n], x1Buf...)
		}
		if n := len(y1Buf); n < 32 {
			y1Buf = append(zeroByteSlice()[:32-n], y1Buf...)
		}
		if n := len(x2Buf); n < 32 {
			x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
		}
		if n := len(y2Buf); n < 32 {
			y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
		}
		c = append(c, x1Buf...) // x分量
		c = append(c, y1Buf...) // y分量
		tm := []byte{}
		tm = append(tm, x2Buf...)
		tm = append(tm, data...)
		tm = append(tm, y2Buf...)
		h := sm3.Sm3Sum(tm)
		c = append(c, h...)
		ct, ok := kdf(x2Buf, y2Buf, length) // 密文
		if !ok {
			continue
		}
		c = append(c, ct...)
		for i := 0; i < length; i++ {
			c[96+i] ^= data[i]
		}
		return append([]byte{0x04}, c...), nil
	}
}

func Decrypt(priv *PrivateKey, data []byte) ([]byte, error) {
	data = data[1:]
	length := len(data) - 96
	curve := priv.Curve
	x := new(big.Int).SetBytes(data[:32])
	y := new(big.Int).SetBytes(data[32:64])
	x2, y2 := curve.ScalarMult(x, y, priv.D.Bytes())
	x2Buf := x2.Bytes()
	y2Buf := y2.Bytes()
	if n := len(x2Buf); n < 32 {
		x2Buf = append(zeroByteSlice()[:32-n], x2Buf...)
	}
	if n := len(y2Buf); n < 32 {
		y2Buf = append(zeroByteSlice()[:32-n], y2Buf...)
	}
	c, ok := kdf(x2Buf, y2Buf, length)
	if !ok {
		return nil, errors.New("Decrypt: failed to decrypt")
	}
	for i := 0; i < length; i++ {
		c[i] ^= data[i+96]
	}
	tm := []byte{}
	tm = append(tm, x2Buf...)
	tm = append(tm, c...)
	tm = append(tm, y2Buf...)
	h := sm3.Sm3Sum(tm)
	if bytes.Compare(h, data[64:96]) != 0 {
		return c, errors.New("Decrypt: failed to decrypt")
	}
	return c, nil
}

type zr struct {
	io.Reader
}

func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}

func getLastBit(a *big.Int) uint {
	return a.Bit(0)
}

func Compress(a *PublicKey) []byte {
	buf := []byte{}
	yp := getLastBit(a.Y)
	buf = append(buf, a.X.Bytes()...)
	if n := len(a.X.Bytes()); n < 32 {
		buf = append(zeroByteSlice()[:(32-n)], buf...)
	}
	buf = append([]byte{byte(yp)}, buf...)
	return buf
}

func Decompress(a []byte) *PublicKey {
	var aa, xx, xx3 sm2P256FieldElement

	P256Sm2()
	x := new(big.Int).SetBytes(a[1:])
	curve := sm2P256
	sm2P256FromBig(&xx, x)
	sm2P256Square(&xx3, &xx)       // x3 = x ^ 2
	sm2P256Mul(&xx3, &xx3, &xx)    // x3 = x ^ 2 * x
	sm2P256Mul(&aa, &curve.a, &xx) // a = a * x
	sm2P256Add(&xx3, &xx3, &aa)
	sm2P256Add(&xx3, &xx3, &curve.b)

	y2 := sm2P256ToBig(&xx3)
	y := new(big.Int).ModSqrt(y2, sm2P256.P)
	if getLastBit(y) != uint(a[0]) {
		y.Sub(sm2P256.P, y)
	}
	return &PublicKey{
		Curve: P256Sm2(),
		X:     x,
		Y:     y,
	}
}

/*
根据msg和sig计算公钥的过程如下：
点R（X1，Y1）, X1 = r - e, e = H(ZA || M)
R = s·G + （r+s)·P
P = （R - s·G）/(r + s)
s = (k-r*d)/(1+d) //k是随机数，d是私钥
*/

func RecoverPubKey(msg []byte, sig []byte) ([]byte, error) {
	if len(msg) > 32 {
		return []byte{}, nil
	}
	if len(sig) != 65 {
		return []byte{}, nil
	}
	za, _ := ZA(nil, nil)
	c := P256Sm2()
	//fmt.Printf("RecoverPubKey sig is %v\n", sig)

	if bytes.Count(sig[:32], []byte{0}) == 32 {
		return nil, errors.New("r of sig of RecoverPubKey is nil")
	}

	if bytes.Count(sig[32:64], []byte{0}) == 32 {
		return nil, errors.New("s of sig of RecoverPubKey is nil")
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	//fmt.Printf("RecoverPubKey sig.R is %v\n", r)
	//fmt.Printf("RecoverPubKey sig.S is %v\n", s)
	e, _ := msgHash(za, msg)
	Rx := new(big.Int).Sub(r, e)
	//fmt.Printf("RecoverPubKey e is %v\n", e)
	for {
		if Rx.Sign() > 0 { //不可能出现rx + e - N > e 的情况，因为rx < N
			break
		}
		Rx.Mod(Rx, c.Params().N)
	}

	//fmt.Printf("RecoverPubKey rx is %v\n", Rx)
	Ry, err := decompressPoint(c, Rx, int(sig[64])%2 == 1)

	//fmt.Printf("RecoverPubKey ry is %v\n", Ry)
	if err != nil {
		fmt.Println("decompressPoint Ry failed,err is ", err)
		return []byte{}, err
	}

	t := new(big.Int).Add(r, s)
	invt := new(big.Int).ModInverse(t, c.Params().N)
	//s·G
	sGx, sGy := c.ScalarBaseMult(s.Bytes())

	// -s·G
	sGy1 := new(big.Int).Sub(c.Params().P, sGy)

	//t·P = R + (-s·G)
	tPx, tPy := c.Add(Rx, Ry, sGx, sGy1)

	//P = t·P / t
	Px, Py := c.ScalarMult(tPx, tPy, invt.Bytes())

	pb := PublicKey{
		Curve: c,
		X:     Px,
		Y:     Py,
	}
	return pb.SerializeUncompressed(), nil

}

func decompressPoint(curve elliptic.Curve, x *big.Int, ybit bool) (*big.Int, error) {
	// TODO: This will probably only work for secp256k1 due to
	// optimizations.

	// Y = +-sqrt(x^3 + AX + B)
	a, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	ax := new(big.Int).Mul(x, a)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, ax)
	x3.Add(x3, curve.Params().B)
	x3.Mod(x3, curve.Params().P)

	y := new(big.Int).ModSqrt(x3, curve.Params().P)

	if y == nil {
		return nil, errors.New(fmt.Sprintf("x3^exp mod Curve.P is error, x3=%s", hex.EncodeToString(x3.Bytes())))
	}

	if ybit != isOdd(y) {
		y.Sub(curve.Params().P, y)
	}

	// Check that y is a square root of x^3 + B.
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.Params().P)
	if y2.Cmp(x3) != 0 {
		return nil, fmt.Errorf("invalid square root")
	}

	// Verify that y-coord has expected parity.
	if ybit != isOdd(y) {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}

	return y, nil
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func intToByte(i *big.Int) []byte {
	b1, b2 := [32]byte{}, i.Bytes()
	copy(b1[32-len(b2):], b2)
	return b1[:]
}
