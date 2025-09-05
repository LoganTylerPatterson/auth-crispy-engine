package main

import "os"

func GetMongoURI() string {
	uri := os.Getenv("MONGO_URI")
	if uri == "" {
		uri = "mongodb://auth-mongo:27017"
	}
	return uri
}

func GetJWTSecret() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		os.Exit(1) // Ensure secret is set in production
	}
	return secret
}
