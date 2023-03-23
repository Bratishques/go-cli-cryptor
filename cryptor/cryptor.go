package cryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const DefaultPBKDF2Iterations = 10000

// CredsGenerator are functions to derive a key and iv from a password and a salt
type CredsGenerator func(password, salt []byte) (Creds, error)

var (
	BytesToKeyMD5    = NewBytesToKeyGenerator(md5.New)
	BytesToKeySHA1   = NewBytesToKeyGenerator(sha1.New)
	BytesToKeySHA256 = NewBytesToKeyGenerator(sha256.New)
	BytesToKeySHA384 = NewBytesToKeyGenerator(sha512.New384)
	BytesToKeySHA512 = NewBytesToKeyGenerator(sha512.New)
	PBKDF2MD5        = NewPBKDF2Generator(md5.New, DefaultPBKDF2Iterations)
	PBKDF2SHA1       = NewPBKDF2Generator(sha1.New, DefaultPBKDF2Iterations)
	PBKDF2SHA256     = NewPBKDF2Generator(sha256.New, DefaultPBKDF2Iterations)
	PBKDF2SHA384     = NewPBKDF2Generator(sha512.New384, DefaultPBKDF2Iterations)
	PBKDF2SHA512     = NewPBKDF2Generator(sha512.New, DefaultPBKDF2Iterations)
)

// openSSLEvpBytesToKey follows the OpenSSL (undocumented?) convention for extracting the key and IV from passphrase.
// It uses the EVP_BytesToKey() method which is basically:
// D_i = HASH^count(D_(i-1) || password || salt) where || denotes concatentaion, until there are sufficient bytes available
// 48 bytes since we're expecting to handle AES-256, 32bytes for a key and 16bytes for the IV
func NewBytesToKeyGenerator(hashFunc func() hash.Hash) CredsGenerator {
	df := func(in []byte) []byte {
		h := hashFunc()
		h.Write(in)
		return h.Sum(nil)
	}

	return func(password, salt []byte) (Creds, error) {
		var m []byte
		prev := []byte{}
		for len(m) < 48 {
			a := make([]byte, len(prev)+len(password)+len(salt))
			copy(a, prev)
			copy(a[len(prev):], password)
			copy(a[len(prev)+len(password):], salt)

			prev = df(a)
			m = append(m, prev...)
		}
		return Creds{Key: m[:32], IV: m[32:48]}, nil
	}
}

func NewPBKDF2Generator(hashFunc func() hash.Hash, iterations int) CredsGenerator {
	return func(password, salt []byte) (Creds, error) {
		m := pbkdf2.Key(password, salt, iterations, 32+16, hashFunc)
		return Creds{Key: m[:32], IV: m[32:48]}, nil
	}
}

// ErrInvalidSalt is returned when a salt with a length of != 8 byte is passed
var ErrInvalidSalt = errors.New("Salt needs to have exactly 8 byte")

// OpenSSL is a helper to generate OpenSSL compatible U2FsdGVkX1+t1JrA7Ii45i++9LgZ4Vb2no2AggeCkTqaXTX2VREXIAvp+vyFKIU1ASkn+pI9W1uudMM/31GQdNP3vwpRl2Mz8q/gEQPBVL4=encryption
// with autmatic IV derivation and storage. As long as the key is known all
// data can also get decrypted using OpenSSL CLI.
// Code from http://dequeue.blogspot.de/2014/11/decrypting-something-encrypted-with.html
type OpenSSL struct {
	openSSLSaltHeader string
}

// Creds holds a key and an IV for encryption methods
type Creds struct {
	Key []byte
	IV  []byte
}

func (o Creds) equals(i Creds) bool {
	// If lengths does not match no chance they are equal
	if len(o.Key) != len(i.Key) || len(o.IV) != len(i.IV) {
		return false
	}

	// Compare keys
	for j := 0; j < len(o.Key); j++ {
		if o.Key[j] != i.Key[j] {
			return false
		}
	}

	// Compare IV
	for j := 0; j < len(o.IV); j++ {
		if o.IV[j] != i.IV[j] {
			return false
		}
	}

	return true
}

// New instanciates and initializes a new OpenSSL encrypter
func New() *OpenSSL {
	return &OpenSSL{
		openSSLSaltHeader: "Salted__", // OpenSSL salt is always this string + 8 bytes of actual salt
	}
}

// DecryptBytes takes a slice of bytes with base64 encoded, encrypted data to decrypt
// and a key-derivation function. The key-derivation function must match the function
// used to encrypt the data. (In OpenSSL the value of the `-md` parameter.)
//
// You should not just try to loop the digest functions as this will cause a race
// condition and you will not be able to decrypt your data properly.
func (o OpenSSL) DecryptBytes(passphrase string, encryptedBase64Data []byte, cg CredsGenerator) ([]byte, error) {
	data := make([]byte, base64.StdEncoding.DecodedLen(len(encryptedBase64Data)))
	n, err := base64.StdEncoding.Decode(data, encryptedBase64Data)
	if err != nil {
		return nil, fmt.Errorf("Could not decode data: %s", err)
	}

	// Truncate to real message length
	data = data[0:n]

	decrypted, err := o.DecryptBinaryBytes(passphrase, data, cg)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// DecryptBinaryBytes takes a slice of binary bytes, encrypted data to decrypt
// and a key-derivation function. The key-derivation function must match the function
// used to encrypt the data. (In OpenSSL the value of the `-md` parameter.)
//
// You should not just try to loop the digest functions as this will cause a race
// condition and you will not be able to decrypt your data properly.
func (o OpenSSL) DecryptBinaryBytes(passphrase string, encryptedData []byte, cg CredsGenerator) ([]byte, error) {
	if len(encryptedData) < aes.BlockSize {
		return nil, fmt.Errorf("Data is too short")
	}
	saltHeader := encryptedData[:aes.BlockSize]
	if string(saltHeader[:8]) != o.openSSLSaltHeader {
		return nil, fmt.Errorf("Does not appear to have been encrypted with OpenSSL, salt header missing")
	}
	salt := saltHeader[8:]

	creds, err := cg([]byte(passphrase), salt)
	if err != nil {
		return nil, err
	}
	return o.decrypt(creds.Key, creds.IV, encryptedData)
}

func (o OpenSSL) decrypt(key, iv, data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("bad blocksize(%v), aes.BlockSize = %v", len(data), aes.BlockSize)
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(data[aes.BlockSize:], data[aes.BlockSize:])
	out, err := o.pkcs7Unpad(data[aes.BlockSize:], aes.BlockSize)
	if out == nil {
		return nil, err
	}
	return out, nil
}

// EncryptBytes encrypts a slice of bytes that are base64 encoded in a manner compatible to OpenSSL encryption
// functions using AES-256-CBC as encryption algorithm. This function generates
// a random salt on every execution.
func (o OpenSSL) EncryptBytes(passphrase string, plainData []byte, cg CredsGenerator) ([]byte, error) {
	salt, err := o.GenerateSalt()
	if err != nil {
		return nil, err
	}

	return o.EncryptBytesWithSaltAndDigestFunc(passphrase, salt, plainData, cg)
}

// EncryptBinaryBytes encrypts a slice of bytes in a manner compatible to OpenSSL encryption
// functions using AES-256-CBC as encryption algorithm. This function generates
// a random salt on every execution.
func (o OpenSSL) EncryptBinaryBytes(passphrase string, plainData []byte, cg CredsGenerator) ([]byte, error) {
	salt, err := o.GenerateSalt()
	if err != nil {
		return nil, err
	}

	return o.EncryptBinaryBytesWithSaltAndDigestFunc(passphrase, salt, plainData, cg)
}

// EncryptBytesWithSaltAndDigestFunc encrypts a slice of bytes that are base64 encoded in a manner compatible to OpenSSL
// encryption functions using AES-256-CBC as encryption algorithm. The salt
// needs to be passed in here which ensures the same result on every execution
// on cost of a much weaker encryption as with EncryptString.
//
// The salt passed into this function needs to have exactly 8 byte.
//
// The hash function corresponds to the `-md` parameter of OpenSSL. For OpenSSL pre-1.1.0c
// DigestMD5Sum was the default, since then it is DigestSHA256Sum.
//
// If you don't have a good reason to use this, please don't! For more information
// see this: https://en.wikipedia.org/wiki/Salt_(cryptography)#Common_mistakes
func (o OpenSSL) EncryptBytesWithSaltAndDigestFunc(passphrase string, salt, plainData []byte, cg CredsGenerator) ([]byte, error) {
	enc, err := o.EncryptBinaryBytesWithSaltAndDigestFunc(passphrase, salt, plainData, cg)
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(enc)), nil
}

func (o OpenSSL) encrypt(key, iv, data []byte) ([]byte, error) {
	padded, err := o.pkcs7Pad(data, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(padded[aes.BlockSize:], padded[aes.BlockSize:])

	return padded, nil
}

// EncryptBinaryBytesWithSaltAndDigestFunc encrypts a slice of bytes in a manner compatible to OpenSSL
// encryption functions using AES-256-CBC as encryption algorithm. The salt
// needs to be passed in here which ensures the same result on every execution
// on cost of a much weaker encryption as with EncryptString.
//
// The salt passed into this function needs to have exactly 8 byte.
//
// The hash function corresponds to the `-md` parameter of OpenSSL. For OpenSSL pre-1.1.0c
// DigestMD5Sum was the default, since then it is DigestSHA256Sum.
//
// If you don't have a good reason to use this, please don't! For more information
// see this: https://en.wikipedia.org/wiki/Salt_(cryptography)#Common_mistakes
func (o OpenSSL) EncryptBinaryBytesWithSaltAndDigestFunc(passphrase string, salt, plainData []byte, cg CredsGenerator) ([]byte, error) {
	if len(salt) != 8 {
		return nil, ErrInvalidSalt
	}

	data := make([]byte, len(plainData)+aes.BlockSize)
	copy(data[0:], o.openSSLSaltHeader)
	copy(data[8:], salt)
	copy(data[aes.BlockSize:], plainData)

	creds, err := cg([]byte(passphrase), salt)
	if err != nil {
		return nil, err
	}

	enc, err := o.encrypt(creds.Key, creds.IV, data)
	if err != nil {
		return nil, err
	}

	return enc, nil
}

// GenerateSalt generates a random 8 byte salt
func (o OpenSSL) GenerateSalt() ([]byte, error) {
	salt := make([]byte, 8) // Generate an 8 byte salt
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	return salt, nil
}

// MustGenerateSalt is a wrapper around GenerateSalt which will panic on an error.
// This allows you to use this function as a parameter to EncryptBytesWithSaltAndDigestFunc
func (o OpenSSL) MustGenerateSalt() []byte {
	s, err := o.GenerateSalt()
	if err != nil {
		panic(err)
	}
	return s
}

// pkcs7Pad appends padding.
func (o OpenSSL) pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := 1
	for ((len(data) + padlen) % blocklen) != 0 {
		padlen++
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

// pkcs7Unpad returns slice of the original data without padding.
func (o OpenSSL) pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padlen], nil
}
