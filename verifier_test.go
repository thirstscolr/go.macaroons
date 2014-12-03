package macaroons

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestBasicSignatureVerification(t *testing.T) {
	m, _ := NewMacaroon(identifier, location)

	err := VerifySignature(m)
	if err != nil {
		t.Errorf("Error verifying macaroon: %s", err)
	}

	m.Signature = []byte("invalid signature modification")
	err = VerifySignature(m)
	if err == nil {
		t.Error("Invalid signature passed verification.")
	}
}

func TestFirstPartyCaveatSignatureVerification(t *testing.T) {
	m, _ := NewMacaroon(identifier, location)

	m.AddFirstPartyCaveat("expires", time.Now().String())
	err := VerifySignature(m)
	if err != nil {
		t.Errorf("Error verifying macaroon: %s", err)
	}

	err = m.AddFirstPartyCaveat("user", "admin")
	if err != nil {
		t.Errorf("Error adding caveat: %s", err)
	}

	err = VerifySignature(m)
	if err != nil {
		t.Errorf("Error verifying macaroon: %s", err)
	}

	m.Signature = []byte("invalid signature modification")
	err = VerifySignature(m)
	if err != invalidSignatureError {
		t.Error("Invalid signature passed verification.")
	}
}

func TestThirdPartyCaveatSignatureVerification(t *testing.T) {
	m, _ := NewMacaroon(identifier, location)

	m.AddThirdPartyCaveat([]byte(cKey), location, "expires", time.Now().String())
	err := VerifySignature(m)
	if err != nil {
		t.Errorf("Error verifying macaroon: %s", err)
	}

	c := m.Caveats[len(m.Caveats)-1]
	c.VerificationId = base64.StdEncoding.EncodeToString(
		[]byte("Unauthorized vId modification!!!"))
	m.Caveats = []Caveat{c}
	err = VerifySignature(m)
	if err != decryptionError {
		t.Errorf("Passed verification with invalid caveat root key.")
	}
}
