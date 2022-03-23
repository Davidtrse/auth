package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

// type person struct {
// 	First string
// }

func main() {
	printBase64()

	password := "12345667"
	hashedPass, err := hashPassword(password)
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
