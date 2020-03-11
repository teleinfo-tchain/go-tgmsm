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
	x, _ := new(big.Int).SetString("33f24533ccfb46ea91f9f060008d4728f671b1e3092dbdf63cc4ce2e2ffe3915", 16)
	y, _ := new(big.Int).SetString("b4a3baf837807c51c0197d866b9c0887f643bcd845dab36c95988df12b3a57ea", 16)
	d, _ := new(big.Int).SetString("bfce850d58038cbe9b5bf4e3327a3c13bc85a948fb49c196b2067a07eab959cc", 16)
	pub := PublicKey{
		Curve: P256Sm2(),
		X:     x,
		Y:     y,
	}
	prv := PrivateKey{
		PublicKey: pub,
		D:         d,
	}
	msg := []byte("a")
	uid := []byte("did:bid:23")

	sign, err := Sm2Sign(&prv, msg, uid)
	if err != nil {
		fmt.Println(err)
	}

	//signature := Sm2Verify(&pub, msg, uid, new(big.Int).SetBytes(sign[:32]), new(big.Int).SetBytes(sign[32:64]))
	//fmt.Println(signature)

	fmt.Println(sign)

	pubKey, _ := RecoverPubKey(msg, sign)
	fmt.Println(pubKey)
	fmt.Println(pub.SerializeUncompressed())
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
