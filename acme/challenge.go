package acme

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.step.sm/crypto/jose"
)

// Challenge represents an ACME response Challenge type.
type Challenge struct {
	ID              string `json:"-"`
	AccountID       string `json:"-"`
	AuthorizationID string `json:"-"`
	Value           string `json:"-"`
	Type            string `json:"type"`
	Status          Status `json:"status"`
	Token           string `json:"token"`
	ValidatedAt     string `json:"validated,omitempty"`
	URL             string `json:"url"`
	Error           *Error `json:"error,omitempty"`
	RetryAfter      string `json:"retry_after,omitempty"`
	Retry           *Retry `json:"-"`
}

// ToLog enables response logging.
func (ch *Challenge) ToLog() (interface{}, error) {
	b, err := json.Marshal(ch)
	if err != nil {
		return nil, WrapErrorISE(err, "error marshaling challenge for logging")
	}
	return string(b), nil
}

// Validate attempts to validate the challenge. Stores changes to the Challenge
// type using the DB interface.
// satisfactorily validated, the 'status' and 'validated' attributes are
// updated.
func (ch *Challenge) Validate(ctx context.Context, db DB, jwk *jose.JSONWebKey, vo *ValidateChallengeOptions) error {
	// Check status - only validate pending or processing challenges
	switch ch.Status {
	case StatusPending, StatusProcessing:
		// Continue to validation
	case StatusValid, StatusInvalid:
		return nil
	default:
		return NewErrorISE("unexpected challenge status: %s", ch.Status)
	}
	switch ch.Type {
	case "http-01":
		return http01Validate(ctx, ch, db, jwk, vo)
	case "dns-01":
		return dns01Validate(ctx, ch, db, jwk, vo)
	case "tls-alpn-01":
		return tlsalpn01Validate(ctx, ch, db, jwk, vo)
	default:
		return NewErrorISE("unexpected challenge type '%s'", ch.Type)
	}
}

func http01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey, vo *ValidateChallengeOptions) error {
	url := &url.URL{Scheme: "http", Host: ch.Value, Path: fmt.Sprintf("/.well-known/acme-challenge/%s", ch.Token)}

	resp, err := vo.HTTPGet(url.String())
	if err != nil {
		// Transient error - don't mark invalid, allow retry
		return storeError(ctx, db, ch, false, WrapError(ErrorConnectionType, err,
			"error doing http GET for url %s", url))
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// Transient error - server responded but with error status
		return storeError(ctx, db, ch, false, NewError(ErrorConnectionType,
			"error doing http GET for url %s with status code %d", url, resp.StatusCode))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return WrapErrorISE(err, "error reading response body for url %s", url)
	}
	keyAuth := strings.TrimSpace(string(body))

	expected, err := KeyAuthorization(ch.Token, jwk)
	if err != nil {
		return err
	}
	if keyAuth != expected {
		// Terminal failure - wrong key authorization
		return storeError(ctx, db, ch, true, NewError(ErrorIncorrectResponseType,
			"keyAuthorization does not match; expected %s, but got %s", expected, keyAuth))
	}

	// Success
	ch.Status = StatusValid
	ch.Error = nil
	ch.Retry = nil
	ch.ValidatedAt = clock.Now().Format(time.RFC3339)

	if err = db.UpdateChallenge(ctx, ch); err != nil {
		return WrapErrorISE(err, "error updating challenge")
	}
	return nil
}

func tlsalpn01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey, vo *ValidateChallengeOptions) error {
	config := &tls.Config{
		NextProtos: []string{"acme-tls/1"},
		// https://tools.ietf.org/html/rfc8737#section-4
		// ACME servers that implement "acme-tls/1" MUST only negotiate TLS 1.2
		// [RFC5246] or higher when connecting to clients for validation.
		MinVersion:         tls.VersionTLS12,
		ServerName:         ch.Value,
		InsecureSkipVerify: true, // we expect a self-signed challenge certificate
	}

	hostPort := net.JoinHostPort(ch.Value, "443")

	conn, err := vo.TLSDial("tcp", hostPort, config)
	if err != nil {
		// Transient error - connection failed, allow retry
		return storeError(ctx, db, ch, false, WrapError(ErrorConnectionType, err,
			"error doing TLS dial for %s", hostPort))
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	certs := cs.PeerCertificates

	if len(certs) == 0 {
		// Terminal failure - no certificates
		return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
			"%s challenge for %s resulted in no certificates", ch.Type, ch.Value))
	}

	if cs.NegotiatedProtocol != "acme-tls/1" {
		// Terminal failure - wrong protocol
		return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
			"cannot negotiate ALPN acme-tls/1 protocol for tls-alpn-01 challenge"))
	}

	leafCert := certs[0]

	if len(leafCert.DNSNames) != 1 || !strings.EqualFold(leafCert.DNSNames[0], ch.Value) {
		// Terminal failure - wrong DNS name
		return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
			"incorrect certificate for tls-alpn-01 challenge: leaf certificate must contain a single DNS name, %v", ch.Value))
	}

	idPeAcmeIdentifier := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}
	idPeAcmeIdentifierV1Obsolete := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 30, 1}
	foundIDPeAcmeIdentifierV1Obsolete := false

	keyAuth, err := KeyAuthorization(ch.Token, jwk)
	if err != nil {
		return err
	}
	hashedKeyAuth := sha256.Sum256([]byte(keyAuth))

	for _, ext := range leafCert.Extensions {
		if idPeAcmeIdentifier.Equal(ext.Id) {
			if !ext.Critical {
				// Terminal failure - extension not critical
				return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
					"incorrect certificate for tls-alpn-01 challenge: acmeValidationV1 extension not critical"))
			}

			var extValue []byte
			rest, err := asn1.Unmarshal(ext.Value, &extValue)

			if err != nil || len(rest) > 0 || len(hashedKeyAuth) != len(extValue) {
				// Terminal failure - malformed extension
				return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
					"incorrect certificate for tls-alpn-01 challenge: malformed acmeValidationV1 extension value"))
			}

			if subtle.ConstantTimeCompare(hashedKeyAuth[:], extValue) != 1 {
				// Terminal failure - wrong key authorization
				return storeError(ctx, db, ch, true, NewError(ErrorIncorrectResponseType,
					"incorrect certificate for tls-alpn-01 challenge: "+
						"expected acmeValidationV1 extension value %s for this challenge but got %s",
					hex.EncodeToString(hashedKeyAuth[:]), hex.EncodeToString(extValue)))
			}

			// Success
			ch.Status = StatusValid
			ch.Error = nil
			ch.Retry = nil
			ch.ValidatedAt = clock.Now().Format(time.RFC3339)

			if err = db.UpdateChallenge(ctx, ch); err != nil {
				return WrapErrorISE(err, "error updating challenge")
			}
			return nil
		}

		if idPeAcmeIdentifierV1Obsolete.Equal(ext.Id) {
			foundIDPeAcmeIdentifierV1Obsolete = true
		}
	}

	if foundIDPeAcmeIdentifierV1Obsolete {
		// Terminal failure - obsolete extension
		return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
			"incorrect certificate for tls-alpn-01 challenge: obsolete id-pe-acmeIdentifier in acmeValidationV1 extension"))
	}

	// Terminal failure - missing extension
	return storeError(ctx, db, ch, true, NewError(ErrorRejectedIdentifierType,
		"incorrect certificate for tls-alpn-01 challenge: missing acmeValidationV1 extension"))
}

func dns01Validate(ctx context.Context, ch *Challenge, db DB, jwk *jose.JSONWebKey, vo *ValidateChallengeOptions) error {
	// Normalize domain for wildcard DNS names
	// This is done to avoid making TXT lookups for domains like
	// _acme-challenge.*.example.com
	// Instead perform txt lookup for _acme-challenge.example.com
	domain := strings.TrimPrefix(ch.Value, "*.")

	txtRecords, err := vo.LookupTxt("_acme-challenge." + domain)
	if err != nil {
		// Transient error - DNS lookup failed, allow retry
		return storeError(ctx, db, ch, false, WrapError(ErrorDNSType, err,
			"error looking up TXT records for domain %s", domain))
	}

	if len(txtRecords) == 0 {
		// Transient error - no records yet, allow retry
		return storeError(ctx, db, ch, false, NewError(ErrorDNSType,
			"no TXT record found at '%s'", "_acme-challenge."+domain))
	}

	expectedKeyAuth, err := KeyAuthorization(ch.Token, jwk)
	if err != nil {
		return err
	}
	h := sha256.Sum256([]byte(expectedKeyAuth))
	expected := base64.RawURLEncoding.EncodeToString(h[:])

	var found bool
	for _, r := range txtRecords {
		if r == expected {
			found = true
			break
		}
	}
	if !found {
		// Terminal failure - records exist but don't match
		return storeError(ctx, db, ch, true, NewError(ErrorIncorrectResponseType,
			"keyAuthorization does not match; expected %s, but got %s", expected, txtRecords))
	}

	// Success
	ch.Status = StatusValid
	ch.Error = nil
	ch.Retry = nil
	ch.ValidatedAt = clock.Now().Format(time.RFC3339)

	if err = db.UpdateChallenge(ctx, ch); err != nil {
		return WrapErrorISE(err, "error updating challenge")
	}
	return nil
}

// KeyAuthorization creates the ACME key authorization value from a token
// and a jwk.
func KeyAuthorization(token string, jwk *jose.JSONWebKey) (string, error) {
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", WrapErrorISE(err, "error generating JWK thumbprint")
	}
	encPrint := base64.RawURLEncoding.EncodeToString(thumbprint)
	return fmt.Sprintf("%s.%s", token, encPrint), nil
}

// storeError stores the given error to the Challenge and persists it.
// If terminal is true, the challenge is marked invalid and retry state is cleared.
// If terminal is false, the error is stored but the challenge remains eligible for retry.
func storeError(ctx context.Context, db DB, ch *Challenge, terminal bool, err *Error) error {
	ch.Error = err
	if terminal {
		ch.Status = StatusInvalid
		ch.Retry = nil
	}
	if err := db.UpdateChallenge(ctx, ch); err != nil {
		return WrapErrorISE(err, "failure saving error to acme challenge")
	}
	return nil
}

type httpGetter func(string) (*http.Response, error)
type lookupTxt func(string) ([]string, error)
type tlsDialer func(network, addr string, config *tls.Config) (*tls.Conn, error)

// ValidateChallengeOptions are ACME challenge validator functions.
type ValidateChallengeOptions struct {
	HTTPGet   httpGetter
	LookupTxt lookupTxt
	TLSDial   tlsDialer
}

// Retry information for challenges is internally relevant and needs to be stored in the DB, but should not be part
// of the public challenge API apart from the Retry-After header.
type Retry struct {
	Owner         int    `json:"owner"`
	ProvisionerID string `json:"provisionerid"`
	NumAttempts   int    `json:"numattempts"`
	MaxAttempts   int    `json:"maxattempts"`
	NextAttempt   string `json:"nextattempt"`
}

// Active returns a boolean indicating whether a Retry struct has remaining attempts or not.
func (r *Retry) Active() bool {
	return r.NumAttempts < r.MaxAttempts
}
