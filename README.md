Crypto-gm
=========

> Guomi crypto algorithm implement.

## Table of Contents

- [Usage](#usage)
- [API](#api)
- [Mockgen](#mockgen)
- [GitCZ](#gitcz)
- [Contribute](#contribute)
- [License](#license)

## Usage
### Sm3 computing hash
```
    msg := "abc"
    sm3 := NewSM3Hasher()
	h, err := sm3.Hash([]byte(msg))     //h is the result
```
### Sm4 encryption and decryption
```
    msg := "abc"
    sm4 := new(SM4)
    key := []byte("1234567812345678")
    c, err := sm4.Encrypt(key, []byte(msg))
    //handle err
    o, err := sm4.Decrypt(key, c)
    //handle err
```
### sm2
```
    privateKey, _ := GenerateSM2Key()
    pub, _ := privateKey.PublicKey()
    h := HashBeforeSM2(pub, []byte(msg))
    s, _ := privateKey.Sign(nil, h)
    b, _ := pub.Verify(nil, s, h)
```
### sm9
```
    kgc := GenerateKGC()
    key := kgc.GenerateKey([]byte("hyperchain"))
    s, _ := key.Sign(nil, []byte(msg))
    ID, _ := key.PublicKey()
    b, _ := ID.Verify(nil, s, []byte(msg))
```
## API
### sm3
Get Hasher：
```func NewSM3Hasher() *Hasher```

Computational hash：
```func (h *Hasher) Hash(msg []byte) (hash []byte, err error)```

### sm4
Encrypt：
```func (ea *SM4) Encrypt(key, originMsg []byte) (encryptedMsg []byte, err error)```

Decrypt：
```func (ea *SM4) Decrypt(key, encryptedMsg []byte) (originMsg []byte, err error)```

### sm2
Generate private key：
```func GenerateSM2Key() (SM2PrivateKey, error)```

signature：
```func (key *SM2PrivateKey) Sign(_ []byte, digest []byte) ([]byte, error)```

verify：
```func (id *ID) Verify(_ []byte, signature, msg []byte) (valid bool, err error)```

### sm9
generate signature：
```func (sm9 *SM9) Sign(k []byte, msg []byte) (signature []byte, err error)```

verify：
```func (sm9 *SM9) Verify(k []byte, signature, msg []byte) (valid bool, err error)```

## Mockgen

Install **mockgen** : `go get github.com/golang/mock/mockgen`

How to use?

- source： Specify interface file
- destination: Generated file name
- package:The package name of the generated file
- imports: Dependent package that requires import
- aux_files: Attach a file when there is more than one file in the interface file
- build_flags: Parameters passed to the build tool

Eg.`mockgen -destination mock/mock_crypto.go -package crypto -source crypto.go`

## GitCZ

**Note**: Please use command `npm install` if you are the first time to use `git cz` in this repo.

## Contribute

PRs are welcome!

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.


##CUDA
download : http://nexus.hyperchain.cn/repository/arch/cuda/libsm2cuda.so

## License

LGPL © Ultramesh
