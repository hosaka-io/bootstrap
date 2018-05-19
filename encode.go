package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func getCipher(privkeyData []byte) (cipher.Block, error) {
	lines := strings.Split(string(privkeyData), "\n")
	sha := sha256.New()
	sha.Write([]byte(strings.Join(lines[1:len(lines)-2], "")))
	return aes.NewCipher(sha.Sum(nil))
}

func encrypt(block cipher.Block, text string) string {
	plaintext := []byte(text)
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}

func decrypt(block cipher.Block, cryptoText string) (string, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(cryptoText)
	if err != nil {
		return cryptoText, err
	}

	if len(ciphertext) < aes.BlockSize {
		return cryptoText, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext), nil
}

func main() {

	keyPath := os.Args[1]
	secret := os.Args[2]

	privkeyData, err := ioutil.ReadFile(keyPath)
	check(err)

	cipher, _ := getCipher(privkeyData)

	encryptedData := encrypt(cipher, secret)
	decryptedData, err := decrypt(cipher, encryptedData)
	check(err)

	fmt.Println("S:", encryptedData, decryptedData)

}
