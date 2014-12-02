package macaroons

import (
	"testing"
	"time"
)

const (
	location   = "squareup.com"
	identifier = "s2s-identifier"
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

	if len(m.FirstPartyCaveats) != 1 {
		t.Error("Error adding first party caveat")
	}
}

func TestCaveatLimit(t *testing.T) {
	m, _ := NewMacaroon(identifier, location)

	for c := 0; c < maxCaveats; c++ {
		m.AddFirstPartyCaveat("key_%i"+string(c), "constraint_"+string(c))
		err := Verify(m)
		if err != nil {
			if err != maxCaveatsError {
				t.Errorf("Error adding caveat: %s", err)
			} else if c == maxCaveats-1 {
				return
			}
		}
	}

	t.Error("Error testing caveat limit")
}

func TestSerialization(t *testing.T) {
	m, _ := NewMacaroon(identifier, location)
	m.AddFirstPartyCaveat("expires", time.Now().String())

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

	err = Verify(rm)
	if err != nil {
		t.Error("Error validating signature after unmarshaling")
	}
}
