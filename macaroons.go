// Package macaroons is a pure Go implementation of macaroons: flexible
// authorization credentials that support decentralized delegation, attenuation,
// and verification.
package macaroons

import (
	"encoding/json"
	"errors"
)

const (
	// the maximum number of caveats within a macaroon
	maxCaveats = 10
)

var (
	maxCaveatsError       = errors.New("Exceeded caveat limit")
	invalidSignatureError = errors.New("Invalid macaroon signature")
)

type FirstPartyCaveat struct {
	Key        string `json:"key"`
	Constraint string `json:"constraint"`
}

type Macaroon struct {
	Identifier        string             `json:"id"`
	Location          string             `json:"location"`
	FirstPartyCaveats []FirstPartyCaveat `json:"fp_caveats"`
	Signature         []byte             `json:"signature"`
}

// NewMacaroon returns a new macaroon with identifier and location. If the
// macaroon is successfully created this function will handle initializing the
// signature.
func NewMacaroon(identifier, location string) (*Macaroon, error) {
	m := &Macaroon{Identifier: identifier, Location: location}
	err := m.initializeSignature()
	if err != nil {
		return nil, err
	}

	return m, nil
}

// AddFirstPartyCaveat adds a new first party caveat to the macaroon. This
// function handles updating the macaroon's signature if the caveat is
// successfully added.
func (m *Macaroon) AddFirstPartyCaveat(key, constraint string) error {
	if len(m.FirstPartyCaveats) >= maxCaveats {
		return maxCaveatsError
	}

	c := &FirstPartyCaveat{Key: key, Constraint: constraint}
	m.FirstPartyCaveats = append(m.FirstPartyCaveats, *c)
	err := m.signFirstPartyCaveat()
	return err
}

// Marshal serializes a macaroon struct into a JSON formatted byte array. Refer
// to the Unmarshal documenation for details on the structure of the serialized
// JSON.
func (m *Macaroon) Marshal() ([]byte, error) {
	marshaled, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	return marshaled, nil
}

// Unmarshal eserializes a properly formatted JSON byte array into a Macaroon
// struct. The JSON keys that will be deserialized include: id, location,
// fp_caveats, and signature. id and location are both strings. fp_caveats is an
// array of JSON encoded byte arrays that consist of a key and constraint. The
// signature is a base64 encoded byte array.
func Unmarshal(macaroon []byte) (*Macaroon, error) {
	m := &Macaroon{}
	err := json.Unmarshal(macaroon, m)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (m *Macaroon) initializeSignature() error {
	key := deriveMacaroonKey(m.Identifier)
	m.Signature = signature(key, []byte(m.Location))
	return nil
}

func (m *Macaroon) signFirstPartyCaveat() error {
	// BUG(tdaniels): Lacks support for third-party caveats.
	caveat := m.FirstPartyCaveats[len(m.FirstPartyCaveats)-1]
	data := []byte(caveat.Key + caveat.Constraint)
	m.Signature = signature(m.Signature, data)
	return nil
}

func (m *Macaroon) signThirdPartyCaveat() error {
	return invalidSignatureError
}
