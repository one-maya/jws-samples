package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("your-256-bit-secret-key-here-must-be-long-enough")

type TransactionPayload struct {
	UserID string  `json:"userId"`
	Action string  `json:"action"`
	Amount float64 `json:"amount"`
}

type CustomClaims struct {
	Data string `json:"data"`
	jwt.RegisteredClaims
}

func signJsonPayload(payload string) (string, error) {
	claims := CustomClaims{
		Data: payload,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func verifyAndExtractPayload(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		return "", fmt.Errorf("JWS signature verification failed: %w", err)
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims.Data, nil
	}

	return "", fmt.Errorf("invalid token claims")
}

func createSignedJWT(subject, issuer string) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   subject,
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func main() {
	payload := TransactionPayload{
		UserID: "12345",
		Action: "transfer",
		Amount: 100.50,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Fatalf("Error marshaling JSON: %v", err)
	}

	fmt.Printf("Original JSON payload: %s\n", jsonPayload)

	signedPayload, err := signJsonPayload(string(jsonPayload))
	if err != nil {
		log.Fatalf("Error signing payload: %v", err)
	}
	fmt.Printf("Signed JWS: %s\n", signedPayload)

	verifiedPayload, err := verifyAndExtractPayload(signedPayload)
	if err != nil {
		log.Fatalf("Error verifying payload: %v", err)
	}
	fmt.Printf("Verified payload: %s\n", verifiedPayload)

	jwt, err := createSignedJWT("user123", "example-issuer")
	if err != nil {
		log.Fatalf("Error creating JWT: %v", err)
	}
	fmt.Printf("Signed JWT: %s\n", jwt)
}