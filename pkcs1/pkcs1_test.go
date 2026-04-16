package pkcs1_test

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"github.com/pduveau/gocert/asn1"
	"github.com/pduveau/gocert/pkcs1"
)

func bigFromString(s string) *big.Int {
	ret := new(big.Int)
	ret.SetString(s, 10)
	return ret
}

var rsaPrivateKey = &rsa.PrivateKey{
	PublicKey: rsa.PublicKey{
		N: bigFromString("124737666279038955318614287965056875799409043964547386061640914307192830334599556034328900586693254156136128122194531292927142396093148164407300419162827624945636708870992355233833321488652786796134504707628792159725681555822420087112284637501705261187690946267527866880072856272532711620639179596808018872997"),
		E: 65537,
	},
	D: bigFromString("69322600686866301945688231018559005300304807960033948687567105312977055197015197977971637657636780793670599180105424702854759606794705928621125408040473426339714144598640466128488132656829419518221592374964225347786430566310906679585739468938549035854760501049443920822523780156843263434219450229353270690889"),
	Primes: []*big.Int{
		bigFromString("11405025354575369741595561190164746858706645478381139288033759331174478411254205003127028642766986913445391069745480057674348716675323735886284176682955723"),
		bigFromString("10937079261204603443118731009201819560867324167189758120988909645641782263430128449826989846631183550578761324239709121189827307416350485191350050332642639"),
	},
}

func TestParsePKCS1PrivateKey(t *testing.T) {
	block, _ := pem.Decode([]byte(pemPrivateKey))
	priv, err := pkcs1.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse private key: %s", err)
		return
	}
	if priv.PublicKey.N.Cmp(rsaPrivateKey.PublicKey.N) != 0 ||
		priv.PublicKey.E != rsaPrivateKey.PublicKey.E ||
		priv.D.Cmp(rsaPrivateKey.D) != 0 ||
		priv.Primes[0].Cmp(rsaPrivateKey.Primes[0]) != 0 ||
		priv.Primes[1].Cmp(rsaPrivateKey.Primes[1]) != 0 {
		t.Errorf("got:%+v want:%+v", priv, rsaPrivateKey)
	}

	// This private key includes an invalid prime that
	// rsa.PrivateKey.Validate should reject.
	data := []byte("0\x16\x02\x00\x02\x02\u007f\x00\x02\x0200\x02\x0200\x02\x02\x00\x01\x02\x02\u007f\x00")
	if _, err := pkcs1.ParsePKCS1PrivateKey(data); err == nil {
		t.Errorf("parsing invalid private key did not result in an error")
	}

	// A partial key without CRT values should still parse.
	b, _ := asn1.Marshal(struct {
		Version int
		N       *big.Int
		E       int
		D       *big.Int
		P       *big.Int
		Q       *big.Int
	}{
		N: priv.N,
		E: priv.PublicKey.E,
		D: priv.D,
		P: priv.Primes[0],
		Q: priv.Primes[1],
	})
	p2, err := pkcs1.ParsePKCS1PrivateKey(b)
	if err != nil {
		t.Fatalf("parsing partial private key resulted in an error: %v", err)
	}
	if !p2.Equal(priv) {
		t.Errorf("partial private key did not match original key")
	}
	if p2.Precomputed.Dp == nil || p2.Precomputed.Dq == nil || p2.Precomputed.Qinv == nil {
		t.Errorf("precomputed values not recomputed")
	}
}

func TestPKCS1MismatchPublicKeyFormat(t *testing.T) {

	const pkixPublicKey = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100dd5a0f37d3ca5232852ccc0e81eebec270e2f2c6c44c6231d852971a0aad00aa7399e9b9de444611083c59ea919a9d76c20a7be131a99045ec19a7bb452d647a72429e66b87e28be9e8187ed1d2a2a01ef3eb2360706bd873b07f2d1f1a72337aab5ec94e983e39107f52c480d404915e84d75a3db2cfd601726a128cb1d7f11492d4bdb53272e652276667220795c709b8a9b4af6489cbf48bb8173b8fb607c834a71b6e8bf2d6aab82af3c8ad7ce16d8dcf58373a6edc427f7484d09744d4c08f4e19ed07adbf6cb31243bc5d0d1145e77a08a6fc5efd208eca67d6abf2d6f38f58b6fdd7c28774fb0cc03fc4935c6e074842d2e1479d3d8787249258719f90203010001"
	const errorContains = "use ParsePKIXPublicKey instead"
	derBytes, _ := hex.DecodeString(pkixPublicKey)
	_, err := pkcs1.ParsePKCS1PublicKey(derBytes)
	if !strings.Contains(err.Error(), errorContains) {
		t.Errorf("expected error containing %q, got %s", errorContains, err)
	}
}

var pemPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCxoeCUW5KJxNPxMp+KmCxKLc1Zv9Ny+4CFqcUXVUYH69L3mQ7v
IWrJ9GBfcaA7BPQqUlWxWM+OCEQZH1EZNIuqRMNQVuIGCbz5UQ8w6tS0gcgdeGX7
J7jgCQ4RK3F/PuCM38QBLaHx988qG8NMc6VKErBjctCXFHQt14lerd5KpQIDAQAB
AoGAYrf6Hbk+mT5AI33k2Jt1kcweodBP7UkExkPxeuQzRVe0KVJw0EkcFhywKpr1
V5eLMrILWcJnpyHE5slWwtFHBG6a5fLaNtsBBtcAIfqTQ0Vfj5c6SzVaJv0Z5rOd
7gQF6isy3t3w9IF3We9wXQKzT6q5ypPGdm6fciKQ8RnzREkCQQDZwppKATqQ41/R
vhSj90fFifrGE6aVKC1hgSpxGQa4oIdsYYHwMzyhBmWW9Xv/R+fPyr8ZwPxp2c12
33QwOLPLAkEA0NNUb+z4ebVVHyvSwF5jhfJxigim+s49KuzJ1+A2RaSApGyBZiwS
rWvWkB471POAKUYt5ykIWVZ83zcceQiNTwJBAMJUFQZX5GDqWFc/zwGoKkeR49Yi
MTXIvf7Wmv6E++eFcnT461FlGAUHRV+bQQXGsItR/opIG7mGogIkVXa3E1MCQARX
AAA7eoZ9AEHflUeuLn9QJI/r0hyQQLEtrpwv6rDT1GCWaLII5HJ6NUFVf4TTcqxo
6vdM4QGKTJoO+SaCyP0CQFdpcxSAuzpFcKv0IlJ8XzS/cy+mweCMwyJ1PFEc4FX6
wg/HcAJWY60xZTJDFN+Qfx8ZQvBEin6c2/h+zZi5IVY=
-----END RSA PRIVATE KEY-----
`

const hexPKCS1TestPKCS8Key = "30820278020100300d06092a864886f70d0101010500048202623082025e02010002818100cfb1b5bf9685ffa97b4f99df4ff122b70e59ac9b992f3bc2b3dde17d53c1a34928719b02e8fd17839499bfbd515bd6ef99c7a1c47a239718fe36bfd824c0d96060084b5f67f0273443007a24dfaf5634f7772c9346e10eb294c2306671a5a5e719ae24b4de467291bc571014b0e02dec04534d66a9bb171d644b66b091780e8d020301000102818100b595778383c4afdbab95d2bfed12b3f93bb0a73a7ad952f44d7185fd9ec6c34de8f03a48770f2009c8580bcd275e9632714e9a5e3f32f29dc55474b2329ff0ebc08b3ffcb35bc96e6516b483df80a4a59cceb71918cbabf91564e64a39d7e35dce21cb3031824fdbc845dba6458852ec16af5dddf51a8397a8797ae0337b1439024100ea0eb1b914158c70db39031dd8904d6f18f408c85fbbc592d7d20dee7986969efbda081fdf8bc40e1b1336d6b638110c836bfdc3f314560d2e49cd4fbde1e20b024100e32a4e793b574c9c4a94c8803db5152141e72d03de64e54ef2c8ed104988ca780cd11397bc359630d01b97ebd87067c5451ba777cf045ca23f5912f1031308c702406dfcdbbd5a57c9f85abc4edf9e9e29153507b07ce0a7ef6f52e60dcfebe1b8341babd8b789a837485da6c8d55b29bbb142ace3c24a1f5b54b454d01b51e2ad03024100bd6a2b60dee01e1b3bfcef6a2f09ed027c273cdbbaf6ba55a80f6dcc64e4509ee560f84b4f3e076bd03b11e42fe71a3fdd2dffe7e0902c8584f8cad877cdc945024100aa512fa4ada69881f1d8bb8ad6614f192b83200aef5edf4811313d5ef30a86cbd0a90f7b025c71ea06ec6b34db6306c86b1040670fd8654ad7291d066d06d031"
const hexPKCS1TestECKey = "3081a40201010430bdb9839c08ee793d1157886a7a758a3c8b2a17a4df48f17ace57c72c56b4723cf21dcda21d4e1ad57ff034f19fcfd98ea00706052b81040022a16403620004feea808b5ee2429cfcce13c32160e1c960990bd050bb0fdf7222f3decd0a55008e32a6aa3c9062051c4cba92a7a3b178b24567412d43cdd2f882fa5addddd726fe3e208d2c26d733a773a597abb749714df7256ead5105fa6e7b3650de236b50"

var pkcs1MismatchKeyTests = []struct {
	hexKey        string
	errorContains string
}{
	{hexKey: hexPKCS1TestPKCS8Key, errorContains: "use ParsePKCS8PrivateKey instead"},
	{hexKey: hexPKCS1TestECKey, errorContains: "use ParseECPrivateKey instead"},
}

func TestPKCS1MismatchKeyFormat(t *testing.T) {
	for i, test := range pkcs1MismatchKeyTests {
		derBytes, _ := hex.DecodeString(test.hexKey)
		_, err := pkcs1.ParsePKCS1PrivateKey(derBytes)
		if !strings.Contains(err.Error(), test.errorContains) {
			t.Errorf("#%d: expected error containing %q, got %s", i, test.errorContains, err)
		}
	}
}
