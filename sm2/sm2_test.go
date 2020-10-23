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

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"testing"
)

/*
func TestSm2(t *testing.T) {
	priv, err := GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
	pub := &priv.PublicKey
	msg := []byte("123456")
	d0, err := pub.Encrypt(msg)
	if err != nil {
		fmt.Printf("Error: failed to encrypt %s: %v\n", msg, err)
		return
	}
	// fmt.Printf("Cipher text = %v\n", d0)
	d1, err := priv.Decrypt(d0)
	if err != nil {
		fmt.Printf("Error: failed to decrypt: %v\n", err)
	}
	fmt.Printf("clear text = %s\n", d1)
	ok, err := WritePrivateKeytoPem("priv.pem", priv, nil) // 生成密钥文件
	if ok != true {
		log.Fatal(err)
	}
	pubKey, _ := priv.Public().(*PublicKey)
	ok, err = WritePublicKeytoPem("pub.pem", pubKey, nil) // 生成公钥文件
	if ok != true {
		log.Fatal(err)
	}
	msg = []byte("test")
	err = ioutil.WriteFile("ifile", msg, os.FileMode(0644)) // 生成测试文件
	if err != nil {
		log.Fatal(err)
	}
	privKey, err := ReadPrivateKeyFromPem("priv.pem", nil) // 读取密钥
	if err != nil {
		log.Fatal(err)
	}
	pubKey, err = ReadPublicKeyFromPem("pub.pem", nil) // 读取公钥
	if err != nil {
		log.Fatal(err)
	}
	msg, _ = ioutil.ReadFile("ifile")                // 从文件读取数据
	sign, err := privKey.Sign(rand.Reader, msg, nil) // 签名
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("ofile", sign, os.FileMode(0644))
	if err != nil {
		log.Fatal(err)
	}
	signdata, _ := ioutil.ReadFile("ofile")
	ok = privKey.Verify(msg, signdata) // 密钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
	ok = pubKey.Verify(msg, signdata) // 公钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
	templateReq := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,
	}
	_, err = CreateCertificateRequestToPem("req.pem", &templateReq, privKey)
	if err != nil {
		log.Fatal(err)
	}
	req, err := ReadCertificateRequestFromPem("req.pem")
	if err != nil {
		log.Fatal(err)
	}
	err = req.CheckSignature()
	if err != nil {
		log.Fatalf("Request CheckSignature error:%v", err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"TEST"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA: true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	pubKey, _ = priv.Public().(*PublicKey)
	ok, _ = CreateCertificateToPem("cert.pem", &template, &template, pubKey, privKey)
	if ok != true {
		fmt.Printf("failed to create cert file\n")
	}
	cert, err := ReadCertificateFromPem("cert.pem")
	if err != nil {
		fmt.Printf("failed to read cert file")
	}
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
}
*/
func TestRecoverPubKey(t *testing.T) {
	priv, err := GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
	pub := &priv.PublicKey
	fmt.Printf("pub.X %v\n", pub.X)
	fmt.Printf("pub.Y %v\n", pub.Y)
	msg := []byte("123456")
	uid := []byte("0")
	sig, err1 := Sm2Sign(priv, msg, uid)
	if err1 != nil {
		fmt.Printf("failde err is %v\n", err1)
	}

	pubkey, err := RecoverPubKey(msg, sig)
	if err == nil {
		fmt.Println(pubkey)
		//fmt.Printf("pubkey.X %v\n", pubkey.X)
		//fmt.Printf("pubkey.Y %v\n", pubkey.Y)
		//if pub.Y.Cmp(pubkey.Y) != 0 {
		//	log.Fatalf("RecoverPubKey Y failed")
		//}
		//
		//if pub.X.Cmp(pubkey.X) != 0 {
		//	log.Fatalf("RecoverPubKey X failed")
		//}
	}

}

/*
func BenchmarkSM2(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	priv, err := GenerateKey() // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sign, err := priv.Sign(rand.Reader, msg, nil) // 签名
		if err != nil {
			log.Fatal(err)
		}
		priv.Verify(msg, sign) // 密钥验证
		// if ok != true {
		// 	fmt.Printf("Verify error\n")
		// } else {
		// 	fmt.Printf("Verify ok\n")
		// }
	}
}
*/

func TestSm2Sign(t *testing.T) {

	total := 100
	fail := 0

	for i := 0; i < total; i++ {

		flag := test()
		if flag {
			fmt.Println("===第", i, "次===============================成功")
		} else {
			fail++
			fmt.Println("===第", i, "次===============================失败")
		}
	}
	fmt.Println("失败了", fail, "次", "总共", total, "次")
}
func test() (flag bool) {
	flag = true
	//x, _ := new(big.Int).SetString("33f24533ccfb46ea91f9f060008d4728f671b1e3092dbdf63cc4ce2e2ffe3915", 16)
	//y, _ := new(big.Int).SetString("b4a3baf837807c51c0197d866b9c0887f643bcd845dab36c95988df12b3a57ea", 16)
	//d, _ := new(big.Int).SetString("bfce850d58038cbe9b5bf4e3327a3c13bc85a948fb49c196b2067a07eab959cc", 16)

	//x, _ := new(big.Int).SetString("87029e148d31cc49ff6a95316c32ab2b1312e361239296661d9156bea560110a", 16)
	//y, _ := new(big.Int).SetString("b9c0fda4d00733507742575a670f5bfa9c6baeaca2037696141cf39fd4a4192", 16)
	//d, _ := new(big.Int).SetString("112393630900846926471192965881774283959259921930569784013236943944151771808341", 10)

	//x, _ := new(big.Int).SetString("11969f62eb5b618acda39f16575c98f02f04c8aa99fa4f1aa714cb6ee4ea3a9c", 16)
	//y, _ := new(big.Int).SetString("86294a908440cce539e69fe402dfd42062f7d3713ea35389572651af37ce5c78", 16)
	x, _ := new(big.Int).SetString("58101c2c82dce8db7a90b1d5506a0decde46e0558cce64dcb2205d9b03ca3108", 16)
	y, _ := new(big.Int).SetString("5aebc775000a1f533cee10bd282e4f500c2556cb2af26d425757e8968065a6e2", 16)

	d, _ := new(big.Int).SetString("eea9354b98fd51d7b962cb4c7e61d691e4d540951e1cf277dd72f2a37544c1da", 16)

	key, _ := GenerateKeyBySeed(d.Bytes(), false)
	fmt.Println(hex.EncodeToString(key.X.Bytes()))
	fmt.Println(hex.EncodeToString(key.Y.Bytes()))

	pub := PublicKey{
		Curve: P256Sm2(),
		X:     x,
		Y:     y,
	}
	prv := PrivateKey{
		PublicKey: pub,
		D:         d,
	}
	//msg := []byte("a")
	msg := []byte("abcdefg")
	uid := []byte("")

	sign, err := Sm2Sign(&prv, msg, uid)
	if err != nil {
		flag = false
		fmt.Println(err)
	}

	_ = prv
	//sign, _ := hex.DecodeString("72f5d313a0c4bf32e0e5d715e7fb731d0a914c8505fa0abab9b20df4a58889cf9d97711ca2f1ba06464b6875626fb3678ae8c5d48534bd84adc6056e15bb881c01")
	//sign, _ := hex.DecodeString("75a6508116b7ab0e056dcb844904872bb2c6d6fd4f3e3b72dee358a485a894e25acd951decc5fc075213ed3943e1d0049dc66fb41d1b002cb2708b9ad98d42eb00")
	//sign, _ := hex.DecodeString("3e702736165d9f472cb0d3ae9bb05ecdeef478b7ff12b971ed321e2332cc8299383e6a4415f9424421281d238142a08c80715058fdbf54b9bf39da43d7f62add00")

	flag = Sm2Verify(&pub, msg, uid, new(big.Int).SetBytes(sign[:32]), new(big.Int).SetBytes(sign[32:64]))
	fmt.Println(flag)
	//if !flag {
	//	return
	//}
	//
	//fmt.Println(len(sign))
	//fmt.Println(sign)
	//fmt.Println(hex.EncodeToString(sign))

	pubKey, _ := RecoverPubKey(msg, sign[:65])
	fmt.Println(pubKey)
	pubK := pub.SerializeUncompressed()
	fmt.Println(pubK)
	if len(pubKey) == 0 {
		flag = false
		return
	}

	flag = bytes.Equal(pubKey, pubK)
	return
}

func TestCalValue(t *testing.T) {
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)

	x3, _ := new(big.Int).SetString("7a3ffc62032463f5335bb040fc76e965d721eec925fe1e21ab71884cfd3c6059", 16)
	//x3, _ := new(big.Int).SetString("a1f6711ab4d4a2f1f013d71be84ed4f85f5859bb2e8733a1dfdf260fc5cabd5c", 16)

	//y := new(big.Int).ModSqrt(x3, p)
	y := new(big.Int).Sqrt(x3)
	y.Mod(y, p)

	fmt.Println(y)
}
