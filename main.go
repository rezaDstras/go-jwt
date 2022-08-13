package main

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"log"
	"net/http"
	"time"
)

var users = map[string]string{
	"ehsan": "1234",
}

type loginInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string
	jwt.StandardClaims
}

var jwtKey = []byte("my_secret_key")

func main() {
	http.HandleFunc("/login", login)
	http.HandleFunc("/welcome", welcome)

	err := http.ListenAndServe(":8287", nil)
	if err != nil {
		log.Println(err)
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	var login loginInfo

	//decode json
	err := json.NewDecoder(r.Body).Decode(&login)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	pass, ok := users[login.Username]
	if !ok || pass != login.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//set expire date
	expTime := time.Now().Add(5 * time.Minute)

	//set jwt token
	cliams := &Claims{
		Username: login.Username,
		StandardClaims: jwt.StandardClaims{
			//expire time as a unix
			ExpiresAt: expTime.Unix(),
		},
	}
	//get method to hash token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cliams)

	stringToken, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	//set cookie for set token
	http.SetCookie(w, &http.Cookie{
		Name:     "JWTToken",
		Expires:  expTime,
		Value:    stringToken,
		HttpOnly: true,
	})

}

func welcome(w http.ResponseWriter, r *http.Request) {
	//get jwt token form token
	c, err := r.Cookie("JWTToken")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	//validate user
	tokenSting := c.Value
	//pars token
	climes := &Claims{}
	token, err := jwt.ParseWithClaims(tokenSting, climes, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}


	fmt.Fprintln(w, "welcome dear")
}
