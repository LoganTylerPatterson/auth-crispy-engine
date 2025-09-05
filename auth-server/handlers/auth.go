package handlers

import (
	"auth-server/models"
	"auth-server/utils"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var client *mongo.Client
var userCollection *mongo.Collection

func init() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://auth-mongo:27017"))
	if err != nil {
		panic(err)
	}
	client = c
	userCollection = client.Database("auth").Collection("users")
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// Check if user exists
	count, err := userCollection.CountDocuments(r.Context(), bson.M{"username": req.Username})
	if err != nil || count > 0 {
		w.WriteHeader(http.StatusConflict)
		return
	}
	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	user := models.User{
		Username:     req.Username,
		PasswordHash: string(hash),
		CreatedAt:    time.Now(),
	}
	_, err = userCollection.InsertOne(r.Context(), user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var user models.User

	err := userCollection.FindOne(r.Context(), bson.M{"username": req.Username}).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	accessToken, err := utils.GenerateJWT(user.ID.Hex())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	refreshToken, err := utils.GenerateRefreshToken(user.ID.Hex())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp := TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	claims, err := utils.ParseJWT(req.RefreshToken)
	if err != nil || claims["type"] != "refresh" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	userID, ok := claims["user_id"].(string)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	accessToken, err := utils.GenerateJWT(userID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp := TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: req.RefreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
