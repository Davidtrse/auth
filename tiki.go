package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

func Sign(secret string, payload string) (string, error) {
	h := hmac.New(sha256.New, []byte(secret))
	_, err := h.Write([]byte(payload))
	if err != nil {
		return "", err
	}
	signature := hex.EncodeToString(h.Sum(nil))
	return signature, nil
}

func main() {
	clientKey := "RLCKb7Ae9kx4DXtXsCWjnDXtggFnM43W"
	clientSecret := "EhjGcsUUuRSJTHiYPbW5fxzyaKEx0JuAZIKRQ4HnIfNFidB2kMg6locQbTIEz3Vf"
	body := map[string]interface{}{
		"id": 123,
	}

	timestamp := int64(1620621619569)
	jsonBody, _ := json.Marshal(body)

	payload := fmt.Sprintf("%s.%s.%s", strconv.FormatInt(timestamp, 10), clientKey, string(jsonBody))
	fmt.Println("payload: ", payload)

	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	fmt.Println("encoded_payload: ", encodedPayload)

	signature, _ := Sign(clientSecret, encodedPayload)
	fmt.Println("signature: ", signature)
}
