package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func getKey(data []byte) (interface{}, error) {
	privkeyBlock, _ := pem.Decode(data)
	return x509.ParsePKCS8PrivateKey(privkeyBlock.Bytes)
}

func genToken(id string, key interface{}) (string, error) {
	dayDuration := time.Duration(12) * time.Hour
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": id,
		"aud": "keychain.dev.hosaka.io",
		"iss": id,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(dayDuration).Unix(),
	})

	token.Header["kid"] = id

	return token.SignedString(key)
}

func getConf(token string, serviceID string) (map[string]string, error) {
	buf := strings.NewReader(token)

	resp, err := http.Post("https://ceterus.dev.hosaka.io/configs/"+serviceID, "text/plain", buf)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("Invalid resp: " + resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	conf := make(map[string]string)

	if err := json.Unmarshal(body, &conf); err != nil {
		return nil, err
	}

	return conf, nil

}

func getCipher(privkeyData []byte) (cipher.Block, error) {
	lines := strings.Split(string(privkeyData), "\n")
	sha := sha256.New()
	sha.Write([]byte(strings.Join(lines[1:len(lines)-2], "")))
	return aes.NewCipher(sha.Sum(nil))
}

// encrypt string to base64 crypto using AES
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

// decrypt from base64 to decrypted string
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

func decryptSecrets(block cipher.Block, conf map[string]string) map[string]string {
	encrypted, exists := conf["encrypted"]

	if !exists {
		return conf
	}

	encryptedFields := strings.Split(encrypted, ";")

	for _, field := range encryptedFields {
		encryptedValue, exists := conf[field]
		if exists {
			decryptedValue, err := decrypt(block, encryptedValue)
			if err == nil {
				conf[field] = decryptedValue
			}
		}
	}

	return conf
}

func setEnv(conf map[string]string) {
	r := strings.NewReplacer(".", "_", "-", "_")
	for k, v := range conf {
		e := r.Replace(strings.ToUpper(k))
		os.Setenv(e, v)
	}
}

func main() {

	serviceID := os.Getenv("SERVICE_ID")
	keyPath := os.Getenv("SERVICE_KEY_PATH")
	if len(keyPath) == 0 {
		keyPath = "./resources/"
	}
	//	privkeyData, err := ioutil.ReadFile("./resources/0a603dd2-e63e-403e-833b-0b01fe212a9d.pem")
	privkeyData, err := ioutil.ReadFile(keyPath + serviceID + ".pem")
	check(err)

	privkey, err := getKey(privkeyData)
	check(err)

	cipher, _ := getCipher(privkeyData)

	tokenString, err := genToken(serviceID, privkey)
	check(err)

	//	fmt.Println(tokenString, err)

	conf, err := getConf(tokenString, serviceID)
	check(err)

	conf = decryptSecrets(cipher, conf)
	setEnv(conf)

	name, err := exec.LookPath(os.Args[1])
	check(err)

	err = syscall.Exec(name, os.Args[1:], os.Environ())
	check(err)
}
