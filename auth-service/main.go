package main
import (
	"fmt"
	"log"
	"net/http"

	"github.com/joho/godotenv"
	"github.com/Hoodk123/ldap-auth/api"
)

func main(){
	_ = godotenv.Load("../.env")

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", api.RateLimitMiddleware(api.LoginHandler))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	})
	log.Println("Auth service starting on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil{
		log.Fatal(err)
	}
}