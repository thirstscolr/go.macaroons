package macaroons

import (
	"crypto/hmac"
	"strings"
)

// VerifySignature calculates the signature of the provided macaroon and
// compares it to the macaroon's signature field to determine the validity of
// the contained caveats and the overall integrity of the credential.
func VerifySignature(m *Macaroon) error {
	// BUG(tdaniels): VerifySignature should be private (verifySignature)
	// and will be called by Verify once it is implemented.
	if len(m.Caveats) >= maxCaveats {
		return maxCaveatsError
	}

	sig := deriveMacaroonKey(m.Identifier)

	for _, c := range m.Caveats {
		// Third-party caveat
		if len(c.VerificationId) > 0 {
			err := verifyThirdPartyCaveat(sig, &c)
			if err != nil {
				return err
			}
		}

		// BUG(tdaniels): Verifying caveat constraints are met is not
		// yet implemented.
		data := []byte(c.VerificationId + c.Key + c.Constraint)
		sig = signature(sig, data)
	}

	if hmac.Equal(sig, m.Signature) {
		return nil
	}

	return invalidSignatureError
}

func verifyThirdPartyCaveat(sig []byte, c *Caveat) error {
	cKey, err := decrypt(sig, c.VerificationId)
	if err != nil {
		return err
	}

	constraint, err := decrypt(cKey, c.Constraint)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(string(constraint), c.Key) {
		return decryptionError
	}

	// BUG(tdaniels): Additional verification once
	// third-party caveats is successfully decrypted is not
	// yet implemented.

	return nil
}
