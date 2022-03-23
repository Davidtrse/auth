package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

// type person struct {
// 	First string
// }
var key []byte

type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
}

func (u *UserClaims) Valid() error {
	if !u.VerifyExpiresAt(time.Now().Unix(), true) {
		return fmt.Errorf("token has expired")
	}

	if u.SessionID == 0 {
		return fmt.Errorf("Invalid session ID")
	}
	return nil
}

func main() {

	for i := 0; i <= 64; i++ {
		key = append(key, byte(i))
	}
	printBase64()

	password := "12345667"
	log.Println("Password is: ", password)
	hashedPass, err := hashPassword(password)
	log.Println("HashedPass is: ", hashedPass)
	if err != nil {
		panic(err)
	}

	err = comparePassword(password, hashedPass)
	if err != nil {
		log.Fatalln("Not logged in")
	}
	log.Println("Logged in")
}

func printBase64() {
	fmt.Println(base64.StdEncoding.EncodeToString([]byte("user:pass")))
}

func hashPassword(password string) ([]byte, error) {
	hs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Error while hash password")
		return nil, fmt.Errorf("error while hash password %w", err)
	}

	return hs, nil
}

func comparePassword(password string, hashedPass []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPass, []byte(password))
	if err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}
	return nil
}

func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha512.New, key)
	_, err := h.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("errror in signMessage while hashing message: %w", err)
	}

	signature := h.Sum(nil)
	return signature, nil
}

func checkSig(msg, sig []byte) (bool, error) {
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("error in checkSig while getting signature of message :%w", err)
	}
	same := hmac.Equal(newSig, sig)

	return same, nil
}

func createToken(c *UserClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	signedToken, err := t.SignedString(keys[currentKid])
	if err != nil {
		return "", fmt.Errorf("error in createToken when signing token: %w", err)
	}
	return signedToken, nil
}

func generateNewKey() error {
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("Error in generateNewKey while generating key: %w", err)
	}
	uid := uuid.NewV4()
	keys[uid.String()] = Key{
		key:     newKey,
		created: time.Now(),
	}
	return nil
}

type Key struct {
	key     []byte
	created time.Time
}

var currentKid = ""
var keys = map[string]Key{}

func parseToken(signedToken string) (*UserClaims, error) {
	claims := &UserClaims{}
	t, err := jwt.ParseWithClaims(signedToken, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() == jwt.SigningMethodES512.Alg() {
			return nil, fmt.Errorf("Invalid signing algorithum")
		}

		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("Invalid key ID")
		}
		k, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("invalid key ID")
		}

		return k.key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("error in pasrse Token while parsing token: %w", err)
	}
	if !t.Valid {
		return nil, fmt.Errorf("Error in parse Toekn, token is not valid")
	}
	claims = t.Claims.(*UserClaims)
	return claims, nil
}
