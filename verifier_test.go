package macaroons

import (
	"testing"
	"time"
)

func TestBasicVerification(t *testing.T) {
	m, _ := NewMacaroon(identifier, location)

	err := Verify(m)
	if err != nil {
		t.Errorf("Error verifying macaroon: %s", err)
	}

	m.Signature = []byte("invalid signature modification")
	err = Verify(m)
	if err == nil {
		t.Error("Invalid signature passed verification.")
	}
}

func TestFirstPartyCaveatVerification(t *testing.T) {
	m, _ := NewMacaroon(identifier, location)

	m.AddFirstPartyCaveat("expires", time.Now().String())
	err := Verify(m)
	if err != nil {
		t.Errorf("Error verifying macaroon: %s", err)
	}

	err = m.AddFirstPartyCaveat("user", "admin")
	if err != nil {
		t.Errorf("Error adding caveat: %s", err)
	}

	err = Verify(m)
	if err != nil {
		t.Errorf("Error verifying macaroon: %s", err)
	}

	m.Signature = []byte("invalid signature modification")
	err = Verify(m)
	if err != invalidSignatureError {
		t.Error("Invalid signature passed verification.")
	}
}
