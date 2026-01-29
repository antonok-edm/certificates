package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/authority/provisioner"
)

func link(url, typ string) string {
	return fmt.Sprintf("<%s>;rel=\"%s\"", url, typ)
}

// Clock that returns time in UTC rounded to seconds.
type Clock struct{}

// Now returns the UTC time rounded to seconds.
func (c *Clock) Now() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

var clock Clock

// ordinal identifies this instance for retry ownership in multi-instance deployments.
var ordinal int

func init() {
	ordstr := os.Getenv("STEP_CA_ORDINAL")
	if ordstr == "" {
		ordinal = 0
	} else {
		ord, err := strconv.Atoi(ordstr)
		if err != nil {
			log.Fatal("Unrecognized ordinal integer value.")
		}
		ordinal = ord
	}
}

const (
	// retryInterval is the time between retry attempts.
	retryInterval = 12 * time.Second
	// maxRetryAttempts is the maximum number of retry attempts.
	maxRetryAttempts = 10
)

type payloadInfo struct {
	value       []byte
	isPostAsGet bool
	isEmptyJSON bool
}

// Handler is the ACME API request handler.
type Handler struct {
	db                       acme.DB
	backdate                 provisioner.Duration
	ca                       acme.CertificateAuthority
	linker                   Linker
	validateChallengeOptions *acme.ValidateChallengeOptions
}

// HandlerOptions required to create a new ACME API request handler.
type HandlerOptions struct {
	Backdate provisioner.Duration
	// DB storage backend that impements the acme.DB interface.
	DB acme.DB
	// DNS the host used to generate accurate ACME links. By default the authority
	// will use the Host from the request, so this value will only be used if
	// request.Host is empty.
	DNS string
	// Prefix is a URL path prefix under which the ACME api is served. This
	// prefix is required to generate accurate ACME links.
	// E.g. https://ca.smallstep.com/acme/my-acme-provisioner/new-account --
	// "acme" is the prefix from which the ACME api is accessed.
	Prefix string
	CA     acme.CertificateAuthority
}

// NewHandler returns a new ACME API handler.
func NewHandler(ops HandlerOptions) api.RouterHandler {
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}
	return &Handler{
		ca:       ops.CA,
		db:       ops.DB,
		backdate: ops.Backdate,
		linker:   NewLinker(ops.DNS, ops.Prefix),
		validateChallengeOptions: &acme.ValidateChallengeOptions{
			HTTPGet:   client.Get,
			LookupTxt: net.LookupTXT,
			TLSDial: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
				return tls.DialWithDialer(dialer, network, addr, config)
			},
		},
	}
}

// Route traffic and implement the Router interface.
func (h *Handler) Route(r api.Router) {
	getLink := h.linker.GetLinkExplicit
	// Standard ACME API
	r.MethodFunc("GET", getLink(NewNonceLinkType, "{provisionerID}", false, nil), h.baseURLFromRequest(h.lookupProvisioner(h.addNonce(h.addDirLink(h.GetNonce)))))
	r.MethodFunc("HEAD", getLink(NewNonceLinkType, "{provisionerID}", false, nil), h.baseURLFromRequest(h.lookupProvisioner(h.addNonce(h.addDirLink(h.GetNonce)))))
	r.MethodFunc("GET", getLink(DirectoryLinkType, "{provisionerID}", false, nil), h.baseURLFromRequest(h.lookupProvisioner(h.addNonce(h.GetDirectory))))
	r.MethodFunc("HEAD", getLink(DirectoryLinkType, "{provisionerID}", false, nil), h.baseURLFromRequest(h.lookupProvisioner(h.addNonce(h.GetDirectory))))

	extractPayloadByJWK := func(next nextHTTP) nextHTTP {
		return h.baseURLFromRequest(h.lookupProvisioner(h.addNonce(h.addDirLink(h.verifyContentType(h.parseJWS(h.validateJWS(h.extractJWK(h.verifyAndExtractJWSPayload(next)))))))))
	}
	extractPayloadByKid := func(next nextHTTP) nextHTTP {
		return h.baseURLFromRequest(h.lookupProvisioner(h.addNonce(h.addDirLink(h.verifyContentType(h.parseJWS(h.validateJWS(h.lookupJWK(h.verifyAndExtractJWSPayload(next)))))))))
	}

	r.MethodFunc("POST", getLink(NewAccountLinkType, "{provisionerID}", false, nil), extractPayloadByJWK(h.NewAccount))
	r.MethodFunc("POST", getLink(AccountLinkType, "{provisionerID}", false, nil, "{accID}"), extractPayloadByKid(h.GetOrUpdateAccount))
	r.MethodFunc("POST", getLink(KeyChangeLinkType, "{provisionerID}", false, nil, "{accID}"), extractPayloadByKid(h.NotImplemented))
	r.MethodFunc("POST", getLink(NewOrderLinkType, "{provisionerID}", false, nil), extractPayloadByKid(h.NewOrder))
	r.MethodFunc("POST", getLink(OrderLinkType, "{provisionerID}", false, nil, "{ordID}"), extractPayloadByKid(h.isPostAsGet(h.GetOrder)))
	r.MethodFunc("POST", getLink(OrdersByAccountLinkType, "{provisionerID}", false, nil, "{accID}"), extractPayloadByKid(h.isPostAsGet(h.GetOrdersByAccountID)))
	r.MethodFunc("POST", getLink(FinalizeLinkType, "{provisionerID}", false, nil, "{ordID}"), extractPayloadByKid(h.FinalizeOrder))
	r.MethodFunc("POST", getLink(AuthzLinkType, "{provisionerID}", false, nil, "{authzID}"), extractPayloadByKid(h.isPostAsGet(h.GetAuthorization)))
	r.MethodFunc("POST", getLink(ChallengeLinkType, "{provisionerID}", false, nil, "{authzID}", "{chID}"), extractPayloadByKid(h.GetChallenge))
	r.MethodFunc("POST", getLink(CertificateLinkType, "{provisionerID}", false, nil, "{certID}"), extractPayloadByKid(h.isPostAsGet(h.GetCertificate)))
}

// GetNonce just sets the right header since a Nonce is added to each response
// by middleware by default.
func (h *Handler) GetNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

// Directory represents an ACME directory for configuring clients.
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

// ToLog enables response logging for the Directory type.
func (d *Directory) ToLog() (interface{}, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, acme.WrapErrorISE(err, "error marshaling directory for logging")
	}
	return string(b), nil
}

// GetDirectory is the ACME resource for returning a directory configuration
// for client configuration.
func (h *Handler) GetDirectory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	api.JSON(w, &Directory{
		NewNonce:   h.linker.GetLink(ctx, NewNonceLinkType, true),
		NewAccount: h.linker.GetLink(ctx, NewAccountLinkType, true),
		NewOrder:   h.linker.GetLink(ctx, NewOrderLinkType, true),
		RevokeCert: h.linker.GetLink(ctx, RevokeCertLinkType, true),
		KeyChange:  h.linker.GetLink(ctx, KeyChangeLinkType, true),
	})
}

// NotImplemented returns a 501 and is generally a placeholder for functionality which
// MAY be added at some point in the future but is not in any way a guarantee of such.
func (h *Handler) NotImplemented(w http.ResponseWriter, r *http.Request) {
	api.WriteError(w, acme.NewError(acme.ErrorNotImplementedType, "this API is not implemented"))
}

// GetAuthorization ACME api for retrieving an Authz.
func (h *Handler) GetAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc, err := accountFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	az, err := h.db.GetAuthorization(ctx, chi.URLParam(r, "authzID"))
	if err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error retrieving authorization"))
		return
	}
	if acc.ID != az.AccountID {
		api.WriteError(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own authorization '%s'", acc.ID, az.ID))
		return
	}
	if err = az.UpdateStatus(ctx, h.db); err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error updating authorization status"))
		return
	}

	h.linker.LinkAuthorization(ctx, az)

	w.Header().Set("Location", h.linker.GetLink(ctx, AuthzLinkType, true, az.ID))
	api.JSON(w, az)
}

// GetChallenge is the ACME api for retrieving a Challenge resource.
//
// Potential Challenges are requested by the client when creating an order.
// Once the client knows the appropriate validation resources are provisioned,
// it makes a POST-as-GET request to this endpoint in order to initiate the
// validation flow.
//
// The validation state machine describes the flow for a challenge.
//
//   https://tools.ietf.org/html/rfc8555#section-7.1.6
//
// Once a validation attempt has completed without error, the challenge's
// status is updated depending on the result (valid|invalid) of the server's
// validation attempt. Once this is the case, a challenge cannot be reset.
//
// If a challenge cannot be completed because no suitable data can be
// acquired the server (whilst communicating retry information) and the
// client (whilst respecting the information from the server) may request
// retries of the validation.
//
//   https://tools.ietf.org/html/rfc8555#section-8.2
//
// Retry status is communicated using the error field and by sending a
// Retry-After header back to the client.
//
// The request body is challenge-specific. The current challenges (http-01,
// dns-01, tls-alpn-01) simply expect an empty object ("{}") in the payload
// of the JWT sent by the client. We don't gain anything by stricly enforcing
// nonexistence of unknown attributes, or, in these three cases, enforcing
// an empty payload. And the spec also says to just ignore it:
//
// > The server MUST ignore any fields in the response object
// > that are not specified as response fields for this type of challenge.
//
//    https://tools.ietf.org/html/rfc8555#section-7.5.1
//
func (h *Handler) GetChallenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc, err := accountFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	// Just verify that the payload was set since the client is required
	// to send _something_.
	_, err = payloadFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	prov, err := provisionerFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	azID := chi.URLParam(r, "authzID")
	ch, err := h.db.GetChallenge(ctx, chi.URLParam(r, "chID"), azID)
	if err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error retrieving challenge"))
		return
	}
	ch.AuthorizationID = azID
	if acc.ID != ch.AccountID {
		api.WriteError(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own challenge '%s'", acc.ID, ch.ID))
		return
	}

	// Short-circuit for terminal states
	switch ch.Status {
	case acme.StatusValid, acme.StatusInvalid:
		h.linker.LinkChallenge(ctx, ch, azID)
		w.Header().Add("Link", link(h.linker.GetLink(ctx, AuthzLinkType, true, azID), "up"))
		w.Header().Set("Location", h.linker.GetLink(ctx, ChallengeLinkType, true, azID, ch.ID))
		api.JSON(w, ch)
		return
	}

	jwk, err := jwkFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	// Take ownership for retry tracking
	if ch.Status == acme.StatusPending {
		ch.Status = acme.StatusProcessing
		ch.Retry = &acme.Retry{
			Owner:         ordinal,
			ProvisionerID: prov.GetID(),
			NumAttempts:   0,
			MaxAttempts:   maxRetryAttempts,
			NextAttempt:   clock.Now().Add(retryInterval).Format(time.RFC3339),
		}
		if err := h.db.UpdateChallenge(ctx, ch); err != nil {
			api.WriteError(w, acme.WrapErrorISE(err, "error updating challenge"))
			return
		}
	}

	// Perform validation
	if err = ch.Validate(ctx, h.db, jwk, h.validateChallengeOptions); err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error validating challenge"))
		return
	}

	// Populate RetryAfter for response if still processing
	if ch.Status == acme.StatusProcessing && ch.Retry != nil {
		ch.RetryAfter = ch.Retry.NextAttempt
	}

	// Schedule retry if still processing and retries remain
	if ch.Status == acme.StatusProcessing && ch.Retry != nil && ch.Retry.Active() {
		time.AfterFunc(retryInterval, func() {
			h.retryChallenge(ch.ID, azID, prov.GetID(), acc.ID)
		})
	}

	h.linker.LinkChallenge(ctx, ch, azID)

	w.Header().Add("Link", link(h.linker.GetLink(ctx, AuthzLinkType, true, azID), "up"))
	w.Header().Set("Location", h.linker.GetLink(ctx, ChallengeLinkType, true, azID, ch.ID))
	if ch.Status == acme.StatusProcessing && ch.RetryAfter != "" {
		w.Header().Add("Retry-After", ch.RetryAfter)
		// 200s are cachable. Don't cache this because it will likely change.
		w.Header().Add("Cache-Control", "no-cache")
	}
	api.JSON(w, ch)
}

// retryChallenge behaves similar to validation in GetChallenge, but simply attempts to perform a validation and
// write update the challenge record in the db if the challenge has remaining retry attempts.
//
// see: GetChallenge
func (h *Handler) retryChallenge(chID, azID, provID, accID string) {
	ctx := context.Background()

	ch, err := h.db.GetChallenge(ctx, chID, azID)
	if err != nil {
		log.Printf("retryChallenge: error loading challenge %s: %v", chID, err)
		return
	}

	// Only proceed if still processing
	if ch.Status != acme.StatusProcessing {
		log.Printf("retryChallenge: challenge %s no longer processing (status=%s)", chID, ch.Status)
		return
	}

	// Verify ownership
	if ch.Retry == nil || ch.Retry.Owner != ordinal {
		log.Printf("retryChallenge: challenge %s not owned by this instance", chID)
		return
	}

	// Check if it's time for retry
	nextAttempt, err := time.Parse(time.RFC3339, ch.Retry.NextAttempt)
	if err != nil {
		log.Printf("retryChallenge: error parsing NextAttempt for challenge %s: %v", chID, err)
		return
	}
	if time.Now().Before(nextAttempt) {
		// Not yet time, reschedule
		time.AfterFunc(time.Until(nextAttempt), func() {
			h.retryChallenge(chID, azID, provID, accID)
		})
		return
	}

	// Check if retries exhausted
	if !ch.Retry.Active() {
		// Mark as invalid - retries exhausted
		ch.Status = acme.StatusInvalid
		if ch.Error == nil {
			ch.Error = acme.NewError(acme.ErrorConnectionType, "challenge validation failed after %d attempts", ch.Retry.MaxAttempts)
		}
		ch.Retry = nil
		if err := h.db.UpdateChallenge(ctx, ch); err != nil {
			log.Printf("retryChallenge: error updating exhausted challenge %s: %v", chID, err)
		}
		return
	}

	// Update attempt counter and next attempt time
	ch.Retry.NumAttempts++
	ch.Retry.NextAttempt = clock.Now().Add(retryInterval).Format(time.RFC3339)
	if err := h.db.UpdateChallenge(ctx, ch); err != nil {
		log.Printf("retryChallenge: error updating retry state for challenge %s: %v", chID, err)
		return
	}

	// Load provisioner
	prov, err := h.ca.LoadProvisionerByID(provID)
	if err != nil {
		log.Printf("retryChallenge: error loading provisioner %s: %v", provID, err)
		return
	}
	acmeProv, ok := prov.(*provisioner.ACME)
	if !ok {
		log.Printf("retryChallenge: provisioner %s is not ACME type", provID)
		return
	}

	// Load account to get JWK
	acc, err := h.db.GetAccount(ctx, accID)
	if err != nil {
		log.Printf("retryChallenge: error loading account %s: %v", accID, err)
		return
	}

	// Build context with provisioner
	ctx = context.WithValue(ctx, provisionerContextKey, acme.Provisioner(acmeProv))

	// Perform validation
	ch.AuthorizationID = azID
	if err = ch.Validate(ctx, h.db, acc.Key, h.validateChallengeOptions); err != nil {
		log.Printf("retryChallenge: error validating challenge %s: %v", chID, err)
		return
	}

	// Schedule next retry if still processing
	if ch.Status == acme.StatusProcessing && ch.Retry != nil && ch.Retry.Active() {
		time.AfterFunc(retryInterval, func() {
			h.retryChallenge(chID, azID, provID, accID)
		})
	}
}

// GetCertificate ACME api for retrieving a Certificate.
func (h *Handler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acc, err := accountFromContext(ctx)
	if err != nil {
		api.WriteError(w, err)
		return
	}
	certID := chi.URLParam(r, "certID")

	cert, err := h.db.GetCertificate(ctx, certID)
	if err != nil {
		api.WriteError(w, acme.WrapErrorISE(err, "error retrieving certificate"))
		return
	}
	if cert.AccountID != acc.ID {
		api.WriteError(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own certificate '%s'", acc.ID, certID))
		return
	}

	var certBytes []byte
	for _, c := range append([]*x509.Certificate{cert.Leaf}, cert.Intermediates...) {
		certBytes = append(certBytes, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})...)
	}

	api.LogCertificate(w, cert.Leaf)
	w.Header().Set("Content-Type", "application/pem-certificate-chain; charset=utf-8")
	w.Write(certBytes)
}
