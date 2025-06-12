package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
	token, err := MakeJWT(uuid.New(), "PaSsWoRd", 5*time.Minute)

	if token == "" || err != nil {
		t.Errorf("Unable to create token. %v", err)
	}
}

func TestValidateJWT(t *testing.T) {
	id := uuid.New()
	secret := "PaSsWoRd"
	token, _ := MakeJWT(id, secret, 5*time.Minute)
	tokenId, err := ValidateJWT(token, secret)

	if tokenId != id || err != nil {
		t.Errorf("Unable to validate token %v", err)
	}
}

func TestValidateJWTBadSecret(t *testing.T) {
	id := uuid.New()
	secret := "PaSsWoRd"
	token, _ := MakeJWT(id, secret, 5*time.Minute)
	_, err := ValidateJWT(token, "Bad")

	if err == nil {
		t.Errorf("ValidateJWT failed to return an error with a bad secret")
	}
}

func TestValidateJWTExpiredToken(t *testing.T) {
	id := uuid.New()
	secret := "PaSsWoRd"
	token, _ := MakeJWT(id, secret, -1*time.Minute)
	_, err := ValidateJWT(token, secret)

	if err == nil {
		t.Errorf("ValidateJWT failed to return an error with an expired token")
	}
}
