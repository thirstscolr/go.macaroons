package macaroons

import (
	"crypto/hmac"
	"crypto/sha256"
)

// Verify calculates the signature of the provided macaroon and compares it to
// the macaroon's signature field to determine the validity of the contained
// caveats and the overall integrity of the credential.
func Verify(m *Macaroon) error {
	if len(m.FirstPartyCaveats) >= maxCaveats {
		return maxCaveatsError
	}

	key := deriveMacaroonKey(m.Identifier)
	sig := signature(key, []byte(m.Location))

	for _, caveat := range m.FirstPartyCaveats {
		data := []byte(caveat.Key + caveat.Constraint)
		sig = signature(sig, data)
	}

	if hmac.Equal(sig, m.Signature) {
		return nil
	}

	return invalidSignatureError
}

func deriveMacaroonKey(identifier string) []byte {
	// BUG(tdaniels): Hard coded master key.
	mKey := []byte("secret")
	derivedKey := signature(mKey, []byte(identifier))

	return derivedKey
}

func signature(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
