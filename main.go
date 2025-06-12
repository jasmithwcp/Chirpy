package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jasmithwcp/Chirpy/internal/auth"
	"github.com/jasmithwcp/Chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	platform       string
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	secret         string
	polkaAPIKey    string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, req)
	})
}

func (cfg *apiConfig) hits(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load()))
}

func (cfg *apiConfig) reset(w http.ResponseWriter, req *http.Request) {
	cfg.fileserverHits.Store(0)
	cfg.dbQueries.ResetUsers(req.Context())
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

func (cfg *apiConfig) createUser(w http.ResponseWriter, req *http.Request) {
	if cfg.platform != "dev" {
		respondWithError(w, http.StatusForbidden, "Forbidden")
		return
	}

	type Parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := Parameters{}

	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, `{ "error": "Something went wrong" }`)
		return
	}

	hash, err := auth.HashPassword(params.Password)

	user, err := cfg.dbQueries.CreateUser(req.Context(), database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hash,
	})

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondWithJSON(w, http.StatusCreated, User{
		ID:          user.ID,
		Email:       user.Email,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		IsChirpyRed: user.IsChirpyRed,
	})
}

func respondWithJSON(w http.ResponseWriter, s int, p any) {
	j, err := json.Marshal(p)
	if err != nil {
		fmt.Println(err)
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(s)
	w.Write(j)
}

func respondWithError(w http.ResponseWriter, s int, msg string) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(s)
	io.WriteString(w, msg)
}

func cleanChirp(c string) string {
	badWords := [3]string{
		"kerfuffle",
		"sharbert",
		"fornax",
	}

	words := strings.Split(c, " ")
	for i, w := range words {
		for _, b := range badWords {
			if strings.ToLower(w) == b {
				words[i] = "****"
				break
			}
		}
	}

	return strings.Join(words, " ")
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	UserId    uuid.UUID `json:"user_id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	userId, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	type Parameters struct {
		Body string `json:"body"`
	}

	decoder := json.NewDecoder(r.Body)
	params := Parameters{}

	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, `{ "error": "Something went wrong" }`)
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, `{ "error": "Chirp is too long" }`)
		return
	}

	clean := cleanChirp(params.Body)
	chirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
		Body:   clean,
		UserID: userId,
	})

	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Create Chirp failed")
		return
	}

	respondWithJSON(w, http.StatusCreated, Chirp{
		ID:        chirp.ID,
		UserId:    chirp.UserID,
		Body:      chirp.Body,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
	})
}

func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {
	authorId := r.URL.Query().Get("author_id")
	filterByUser := authorId != ""
	userId, _ := uuid.Parse(authorId)

	sortDirection := r.URL.Query().Get("sort")
	if sortDirection == "" {
		sortDirection = "asc"
	}

	rows, err := cfg.dbQueries.GetChirps(r.Context(), database.GetChirpsParams{
		UserID:  userId,
		Column2: filterByUser,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Get Chirps Failed.")
		return
	}

	slices.SortFunc(rows, func(a, b database.Chirp) int {
		dir := 1
		if sortDirection == "desc" {
			dir = -1
		}

		return a.CreatedAt.Compare(b.CreatedAt) * dir
	})

	chirps := []Chirp{}
	for _, row := range rows {
		chirps = append(chirps, Chirp{
			ID:        row.ID,
			UserId:    row.UserID,
			Body:      row.Body,
			CreatedAt: row.CreatedAt,
			UpdatedAt: row.UpdatedAt,
		})
	}

	respondWithJSON(w, http.StatusOK, chirps)
}

func (cfg *apiConfig) getChirp(w http.ResponseWriter, r *http.Request) {
	id, _ := uuid.Parse(r.PathValue("chirpID"))
	row, err := cfg.dbQueries.GetChirp(r.Context(), id)
	if err != nil {
		respondWithError(w, http.StatusNotFound, err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, Chirp{
		ID:        row.ID,
		UserId:    row.UserID,
		Body:      row.Body,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	})
}

func (cfg *apiConfig) Login(w http.ResponseWriter, r *http.Request) {
	type Parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := Parameters{}

	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, `{ "error": "Something went wrong" }`)
		return
	}

	user, err := cfg.dbQueries.GetUser(r.Context(), params.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	if err := auth.CheckPasswordHash(user.HashedPassword, params.Password); err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	token, err := auth.MakeJWT(user.ID, cfg.secret, time.Duration(time.Hour))

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	refreshToken, _ := auth.MakeRefreshToken()

	cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().AddDate(0, 0, 60),
	})

	respondWithJSON(w, http.StatusOK, User{
		ID:           user.ID,
		Email:        user.Email,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  user.IsChirpyRed,
	})
}

func (cfg *apiConfig) Refresh(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	savedToken, err := cfg.dbQueries.GetRefreshToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	if savedToken.RevokedAt.Valid {
		respondWithError(w, http.StatusUnauthorized, "Revoked")
		return
	}

	if savedToken.ExpiresAt.Before(time.Now().UTC()) {
		respondWithError(w, http.StatusUnauthorized, "Expired")
		return
	}

	newToken, err := auth.MakeJWT(savedToken.UserID, cfg.secret, time.Duration(time.Hour))

	type Token struct {
		Token string `json:"token"`
	}

	respondWithJSON(w, http.StatusOK, Token{
		Token: newToken,
	})
}

func (cfg *apiConfig) Revoke(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	revokeError := cfg.dbQueries.RevokeRefreshToken(r.Context(), token)
	if revokeError != nil {
		respondWithError(w, http.StatusInternalServerError, revokeError.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) UpdateUser(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	userId, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	type Body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	body := Body{}

	if err := decoder.Decode(&body); err != nil {
		respondWithError(w, http.StatusBadRequest, `{ "error": "Something went wrong" }`)
		return
	}

	hashed, err := auth.HashPassword(body.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Unable to hash password")
		return
	}

	user, err := cfg.dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             userId,
		Email:          body.Email,
		HashedPassword: hashed,
	})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Unable to update user")
		return
	}

	respondWithJSON(w, http.StatusOK, User{
		ID:          user.ID,
		Email:       user.Email,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		IsChirpyRed: user.IsChirpyRed,
	})
}

func (cfg *apiConfig) DeleteChirp(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	userId, err := auth.ValidateJWT(token, cfg.secret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error())
		return
	}

	id, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "chirpID is invalid")
		return
	}

	chirp, err := cfg.dbQueries.GetChirp(r.Context(), id)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Not Found")
		return
	}

	if chirp.UserID != userId {
		respondWithError(w, http.StatusForbidden, "Cannot delete other people's chirps")
		return
	}

	cfg.dbQueries.DeleteChirp(r.Context(), id)
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) EnrollInChirpyRed(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil || apiKey != cfg.polkaAPIKey {
		respondWithError(w, http.StatusUnauthorized, "ApiKey not specified")
		return
	}

	type Event struct {
		Event string `json:"event"`
		Data  struct {
			UserId uuid.UUID `json:"user_id"`
		}
	}

	decoder := json.NewDecoder(r.Body)
	event := Event{}

	if err := decoder.Decode(&event); err != nil {
		respondWithError(w, http.StatusBadRequest, `{ "error": "Something went wrong" }`)
		return
	}

	if event.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	} else {
		if err := cfg.dbQueries.EnrollInChirpyRed(r.Context(), event.Data.UserId); err != nil {
			respondWithError(w, http.StatusNotFound, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}

}

func main() {
	godotenv.Load()
	platform := os.Getenv("PLATFORM")
	dbURL := os.Getenv("DB_URL")
	secret := os.Getenv("SECRET")
	polkaAPIKey := os.Getenv("POLKA_API_KEY")
	db, _ := sql.Open("postgres", dbURL)

	mux := http.NewServeMux()
	c := apiConfig{
		dbQueries:   database.New(db),
		platform:    platform,
		secret:      secret,
		polkaAPIKey: polkaAPIKey,
	}

	mux.Handle("/app/", c.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /admin/metrics", c.hits)
	mux.HandleFunc("POST /admin/reset", c.reset)

	mux.HandleFunc("GET /api/healthz", func(res http.ResponseWriter, req *http.Request) {
		res.Header().Add("Content-Type", "text/plain; charset=utf-8")
		res.WriteHeader(http.StatusOK)
		io.WriteString(res, "OK")
	})

	mux.HandleFunc("POST /api/users", c.createUser)
	mux.HandleFunc("POST /api/chirps", c.createChirp)
	mux.HandleFunc("GET /api/chirps", c.getChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", c.getChirp)
	mux.HandleFunc("POST /api/login", c.Login)
	mux.HandleFunc("POST /api/refresh", c.Refresh)
	mux.HandleFunc("POST /api/revoke", c.Revoke)
	mux.HandleFunc("PUT /api/users", c.UpdateUser)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", c.DeleteChirp)
	mux.HandleFunc("POST /api/polka/webhooks", c.EnrollInChirpyRed)

	server := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	log.Fatal(server.ListenAndServe())
}
