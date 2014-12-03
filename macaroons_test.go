package macaroons

import (
	"testing"
	"time"
)

const (
	location   = "squareup.com"
	identifier = "identifier"
	cKey       = "caveat-root-key!"
)

func TestNewMacaroon(t *testing.T) {
	m, err := NewMacaroon(identifier, location)
	if err != nil {
		t.Errorf("Error creating macaroon: %s", err)
	}

	if m.Location != location {
		t.Error("Error setting location")
	}

	if m.Identifier != identifier {
		t.Error("Error setting identifier")
	}
}

func TestAddFirstPartyCaveat(t *testing.T) {
	m, _ := NewMacaroon(identifier, location)

	err := m.AddFirstPartyCaveat("expires", time.Now().String())
	if err != nil {
		t.Errorf("Error adding first party caveat: %s", err)
	}

	if len(m.Caveats) != 1 {
		t.Error("Error adding first party caveat")
	}
}

func TestAddThirdPartyCaveat(t *testing.T) {
	m, _ := NewMacaroon(identifier, location)
	err := m.AddThirdPartyCaveat([]byte(cKey), location, "authenticated", "true")
	if err != nil {
		t.Errorf("Error adding third party caveat: %s", err)
	}

	if len(m.Caveats) != 1 {
		t.Error("Error adding third party caveat")
	}
}

func TestCaveatLimit(t *testing.T) {
	m, _ := NewMacaroon(identifier, location)

	for c := 0; c < maxCaveats; c++ {
		m.AddFirstPartyCaveat("key_%i"+string(c), "constraint_"+string(c))
		err := VerifySignature(m)
		if err != nil {
			if err != maxCaveatsError {
				t.Errorf("Error adding caveat: %s", err)
			} else if len(m.Caveats) == maxCaveats {
				return
			}
		}
	}

	t.Error("Error testing caveat limit")
}

func TestBasicSerialization(t *testing.T) {
	m, _ := NewMacaroon(identifier, location)

	mm, err := m.Marshal()
	if err != nil {
		t.Error("Error marshaling macaroon: %s", err)
	}

	rm, err := Unmarshal(mm)
	if err != nil {
		t.Errorf("Error unmarshaling macaroon: %s", err)
	}

	if rm.Location != location {
		t.Error("Error marshaling location")
	}

	if rm.Identifier != identifier {
		t.Error("Error marshaling identifier")
	}

	err = VerifySignature(rm)
	if err != nil {
		t.Error("Error validating signature after unmarshaling")
	}
}
