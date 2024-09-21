package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/smtp"
	"time"
)

var (
	db      *sql.DB
	jwtKey  = []byte("qwerty")
	localIP = "192.168.0.103"
)

type Claims struct {
	UserID  string `json:"user_id"`
	IP      string `json:"ip"`
	TokenID string `json:"token_id"`
	jwt.StandardClaims
}
type smtpServer struct {
	host string
	port string
}

func generateTokens(userID, ip string) (string, string, error) {
	//Генерим уникальный токен ID, по которому будут связаны access и refresh токены
	tokenID := uuid.New()
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		UserID:  userID,
		IP:      ip,
		TokenID: tokenID.String(),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	//Создаем access токен
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessTokenString, err := accessToken.SignedString(jwtKey)
	if err != nil {
		return "", "", err
	}
	//Создаем рефреш токен
	refreshToken := base64.StdEncoding.EncodeToString([]byte(userID + ip + time.Now().String()))
	//Хэшируем рефреш токен частями, т.к. его длина больше 72 байтов
	var hashedRefreshToken string
	if len(refreshToken) > 72 {
		for i := 0; i < len(refreshToken); i += 72 {
			end := i + 72
			if end > len(refreshToken) {
				end = len(refreshToken)
			}
			part := refreshToken[i:end]
			hashedPart, err := bcrypt.GenerateFromPassword([]byte(part), bcrypt.DefaultCost)
			if err != nil {
				return "", "", err
			}
			hashedRefreshToken += string(hashedPart) // Объединяем хеши
		}
	} else {
		hashedRefreshTokenBytes, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
		if err != nil {
			return "", "", err
		}
		hashedRefreshToken = string(hashedRefreshTokenBytes)
	}
	userIDFormatted, err := uuid.Parse(userID)
	if err != nil {
		return "", "", err
	}
	//Добавляем рефреш токен в бд
	_, err = db.Exec("INSERT INTO tokens (token_id, user_id, refresh_token) VALUES ($1, $2, $3)", tokenID,
		userIDFormatted, hashedRefreshToken)
	if err != nil {
		return "", "", err
	}
	return accessTokenString, refreshToken, nil
}

func access(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	//Достаем ID из URL
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		http.Error(w, "Missing user_id", http.StatusBadRequest)
		return
	}
	ip := r.RemoteAddr
	//Генерируем токены и возвращаем их
	accessToken, refreshToken, err := generateTokens(userID, ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	//Достаем из реквеста JSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	//Проверяем подпись и парсим access токен
	tkn, err := jwt.Parse(req.AccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid token")
		}
		return jwtKey, nil
	})
	if err != nil || !tkn.Valid {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	claimsFromJWT := tkn.Claims.(jwt.MapClaims)
	claims := &Claims{
		UserID:         claimsFromJWT["user_id"].(string),
		IP:             claimsFromJWT["ip"].(string),
		TokenID:        claimsFromJWT["token_id"].(string),
		StandardClaims: jwt.StandardClaims{ExpiresAt: int64(claimsFromJWT["exp"].(float64))},
	}
	//Находим рефреш токен в БД по ID пользователя и уникальному ID access токена
	var storedHash string
	err = db.QueryRow("SELECT refresh_token FROM tokens WHERE user_id = $1 AND token_id=$2",
		claims.UserID, claims.TokenID).Scan(&storedHash)
	if err != nil {
		println(claims.IP)
		http.Error(w, "refresh token not found", http.StatusUnauthorized)
		return
	}
	//Сравниваем токен из БД с токеном в теле запроса
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.RefreshToken)); err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}
	//Проверяем IP и отправляем эмэйл, если не соответствует
	if claims.IP != r.RemoteAddr {
		if sendEmail() != nil {
			http.Error(w, sendEmail().Error(), http.StatusInternalServerError)
			return
		}
	}
	//Генерим новую пару токенов и возвращаем их
	newAccessToken, newRefreshToken, err := generateTokens(claims.UserID, claims.IP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	response := map[string]string{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
func sendEmail() error {
	from := "server@gmail.com"
	password := "MySecretPassword"
	to := "user@gmail.com"
	smtpServer := smtpServer{host: "smtp.gmail.com", port: "587"}
	auth := smtp.PlainAuth("", from, password, smtpServer.host)
	return smtp.SendMail(smtpServer.host+":"+smtpServer.port, auth, from, []string{to},
		[]byte("Your account's IP address has changed"))
}

func main() {
	var err error

	connStr := "host = " + localIP +
		" port = 5432 user=postgres password=qwerty dbname=postgres sslmode=disable"
	db, err = sql.Open("postgres", connStr)

	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	r := mux.NewRouter()
	r.HandleFunc("/access", access).Methods("GET")
	r.HandleFunc("/refresh", refresh).Methods("POST")

	log.Println("Starting server on :8000...")

	log.Fatal(http.ListenAndServe(":8000", r))

}
