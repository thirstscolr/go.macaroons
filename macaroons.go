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
	decryptionError       = errors.New("Decryption failure")
)

type Caveat struct {
	VerificationId string `json:"verification_id"`
	Location       string `json:"location"`
	Key            string `json:"key"`
	Constraint     string `json:"constraint"`
}

type Macaroon struct {
	Identifier string   `json:"id"`
	Location   string   `json:"location"`
	Caveats    []Caveat `json:"caveats"`
	Signature  []byte   `json:"signature"`
}

// NewMacaroon returns a new macaroon with identifier and location. If the
// macaroon is successfully created this function will handle initializing the
// signature.
func NewMacaroon(identifier, location string) (*Macaroon, error) {
	m := &Macaroon{Identifier: identifier, Location: location}
	m.Signature = deriveMacaroonKey(m.Identifier)
	return m, nil
}

// AddFirstPartyCaveat adds a new first party caveat to the macaroon. This
// function handles updating the macaroon's signature if the caveat is
// successfully added.
func (m *Macaroon) AddFirstPartyCaveat(key, constraint string) error {
	err := m.addCaveat("", "", key, constraint)
	return err
}

// AddThirdPartyCaveat takes a caveat root key, constraint, and a location of
// the discharging principle. It generates a verification id by encrypting the
// root key with the current macaroon signature. The constraint payload is the
// (key, constraint) pair encrypted with the caveat root key.
func (m *Macaroon) AddThirdPartyCaveat(cKey []byte, loc, key, constraint string) error {
	vId, err := encrypt(m.Signature, cKey)
	data, err := encrypt(cKey, []byte(key+constraint))
	if err != nil {
		return err
	}
	err = m.addCaveat(vId, loc, key, string(data))

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

func (m *Macaroon) addCaveat(vId, loc, key, constraint string) error {
	if len(m.Caveats) >= maxCaveats {
		return maxCaveatsError
	}

	c := &Caveat{VerificationId: vId,
		Location:   loc,
		Key:        key,
		Constraint: constraint}

	m.Caveats = append(m.Caveats, *c)
	err := m.signCaveat(c)
	return err
}

func (m *Macaroon) signCaveat(c *Caveat) error {
	data := []byte(c.VerificationId + c.Key + c.Constraint)
	m.Signature = signature(m.Signature, data)
	return nil
}
