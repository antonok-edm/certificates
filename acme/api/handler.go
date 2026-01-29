package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority"
	"github.com/smallstep/certificates/authority/provisioner"
)

func link(url, typ string) string {
	return fmt.Sprintf("<%s>;rel=%q", url, typ)
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

// HandlerOptions required to create a new ACME API request handler.
type HandlerOptions struct {
	// DB storage backend that implements the acme.DB interface.
	//
	// Deprecated: use acme.NewContex(context.Context, acme.DB)
	DB acme.DB

	// CA is the certificate authority interface.
	//
	// Deprecated: use authority.NewContext(context.Context, *authority.Authority)
	CA acme.CertificateAuthority

	// Backdate is the duration that the CA will subtract from the current time
	// to set the NotBefore in the certificate.
	Backdate provisioner.Duration

	// DNS the host used to generate accurate ACME links. By default the authority
	// will use the Host from the request, so this value will only be used if
	// request.Host is empty.
	DNS string

	// Prefix is a URL path prefix under which the ACME api is served. This
	// prefix is required to generate accurate ACME links.
	// E.g. https://ca.smallstep.com/acme/my-acme-provisioner/new-account --
	// "acme" is the prefix from which the ACME api is accessed.
	Prefix string

	// PrerequisitesChecker checks if all prerequisites for serving ACME are
	// met by the CA configuration.
	PrerequisitesChecker func(ctx context.Context) (bool, error)
}

var mustAuthority = func(ctx context.Context) acme.CertificateAuthority {
	return authority.MustFromContext(ctx)
}

// handler is the ACME API request handler.
type handler struct {
	opts *HandlerOptions
}

// Route traffic and implement the Router interface. For backward compatibility
// this route adds will add a new middleware that will set the ACME components
// on the context.
//
// Note: this method is deprecated in step-ca, other applications can still use
// this to support ACME, but the recommendation is to use use
// api.Route(api.Router) and acme.NewContext() instead.
func (h *handler) Route(r api.Router) {
	client := acme.NewClient()
	linker := acme.NewLinker(h.opts.DNS, h.opts.Prefix)
	route(r, func(next nextHTTP) nextHTTP {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if ca, ok := h.opts.CA.(*authority.Authority); ok && ca != nil {
				ctx = authority.NewContext(ctx, ca)
			}
			ctx = acme.NewContext(ctx, h.opts.DB, client, linker, h.opts.PrerequisitesChecker)
			next(w, r.WithContext(ctx))
		}
	})
}

// NewHandler returns a new ACME API handler.
//
// Note: this method is deprecated in step-ca, other applications can still use
// this to support ACME, but the recommendation is to use use
// api.Route(api.Router) and acme.NewContext() instead.
func NewHandler(opts HandlerOptions) api.RouterHandler {
	return &handler{
		opts: &opts,
	}
}

// Route traffic and implement the Router interface. This method requires that
// all the acme components, authority, db, client, linker, and prerequisite
// checker to be present in the context.
func Route(r api.Router) {
	route(r, nil)
}

func route(r api.Router, middleware func(next nextHTTP) nextHTTP) {
	commonMiddleware := func(next nextHTTP) nextHTTP {
		handler := func(w http.ResponseWriter, r *http.Request) {
			// Linker middleware gets the provisioner and current url from the
			// request and sets them in the context.
			linker := acme.MustLinkerFromContext(r.Context())
			linker.Middleware(http.HandlerFunc(checkPrerequisites(next))).ServeHTTP(w, r)
		}
		if middleware != nil {
			handler = middleware(handler)
		}
		return handler
	}
	validatingMiddleware := func(next nextHTTP) nextHTTP {
		return commonMiddleware(addNonce(addDirLink(verifyContentType(parseJWS(validateJWS(next))))))
	}
	extractPayloadByJWK := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(extractJWK(verifyAndExtractJWSPayload(next)))
	}
	extractPayloadByKid := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(lookupJWK(verifyAndExtractJWSPayload(next)))
	}
	extractPayloadByKidOrJWK := func(next nextHTTP) nextHTTP {
		return validatingMiddleware(extractOrLookupJWK(verifyAndExtractJWSPayload(next)))
	}

	getPath := acme.GetUnescapedPathSuffix

	// Standard ACME API
	r.MethodFunc("GET", getPath(acme.NewNonceLinkType, "{provisionerID}"),
		commonMiddleware(addNonce(addDirLink(GetNonce))))
	r.MethodFunc("HEAD", getPath(acme.NewNonceLinkType, "{provisionerID}"),
		commonMiddleware(addNonce(addDirLink(GetNonce))))
	r.MethodFunc("GET", getPath(acme.DirectoryLinkType, "{provisionerID}"),
		commonMiddleware(GetDirectory))
	r.MethodFunc("HEAD", getPath(acme.DirectoryLinkType, "{provisionerID}"),
		commonMiddleware(GetDirectory))

	r.MethodFunc("POST", getPath(acme.NewAccountLinkType, "{provisionerID}"),
		extractPayloadByJWK(NewAccount))
	r.MethodFunc("POST", getPath(acme.AccountLinkType, "{provisionerID}", "{accID}"),
		extractPayloadByKid(GetOrUpdateAccount))
	r.MethodFunc("POST", getPath(acme.KeyChangeLinkType, "{provisionerID}", "{accID}"),
		extractPayloadByKid(NotImplemented))
	r.MethodFunc("POST", getPath(acme.NewOrderLinkType, "{provisionerID}"),
		extractPayloadByKid(NewOrder))
	r.MethodFunc("POST", getPath(acme.OrderLinkType, "{provisionerID}", "{ordID}"),
		extractPayloadByKid(isPostAsGet(GetOrder)))
	r.MethodFunc("POST", getPath(acme.OrdersByAccountLinkType, "{provisionerID}", "{accID}"),
		extractPayloadByKid(isPostAsGet(GetOrdersByAccountID)))
	r.MethodFunc("POST", getPath(acme.FinalizeLinkType, "{provisionerID}", "{ordID}"),
		extractPayloadByKid(FinalizeOrder))
	r.MethodFunc("POST", getPath(acme.AuthzLinkType, "{provisionerID}", "{authzID}"),
		extractPayloadByKid(isPostAsGet(GetAuthorization)))
	r.MethodFunc("POST", getPath(acme.ChallengeLinkType, "{provisionerID}", "{authzID}", "{chID}"),
		extractPayloadByKid(GetChallenge))
	r.MethodFunc("POST", getPath(acme.CertificateLinkType, "{provisionerID}", "{certID}"),
		extractPayloadByKid(isPostAsGet(GetCertificate)))
	r.MethodFunc("POST", getPath(acme.RevokeCertLinkType, "{provisionerID}"),
		extractPayloadByKidOrJWK(RevokeCert))
}

// GetNonce just sets the right header since a Nonce is added to each response
// by middleware by default.
func GetNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

type Meta struct {
	TermsOfService          string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CaaIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"`
}

// Directory represents an ACME directory for configuring clients.
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
	Meta       *Meta  `json:"meta,omitempty"`
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
func GetDirectory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	acmeProv, err := acmeProvisionerFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	linker := acme.MustLinkerFromContext(ctx)

	render.JSON(w, &Directory{
		NewNonce:   linker.GetLink(ctx, acme.NewNonceLinkType),
		NewAccount: linker.GetLink(ctx, acme.NewAccountLinkType),
		NewOrder:   linker.GetLink(ctx, acme.NewOrderLinkType),
		RevokeCert: linker.GetLink(ctx, acme.RevokeCertLinkType),
		KeyChange:  linker.GetLink(ctx, acme.KeyChangeLinkType),
		Meta:       createMetaObject(acmeProv),
	})
}

// createMetaObject creates a Meta object if the ACME provisioner
// has one or more properties that are written in the ACME directory output.
// It returns nil if none of the properties are set.
func createMetaObject(p *provisioner.ACME) *Meta {
	if shouldAddMetaObject(p) {
		return &Meta{
			TermsOfService:          p.TermsOfService,
			Website:                 p.Website,
			CaaIdentities:           p.CaaIdentities,
			ExternalAccountRequired: p.RequireEAB,
		}
	}
	return nil
}

// shouldAddMetaObject returns whether or not the ACME provisioner
// has properties configured that must be added to the ACME directory object.
func shouldAddMetaObject(p *provisioner.ACME) bool {
	switch {
	case p.TermsOfService != "":
		return true
	case p.Website != "":
		return true
	case len(p.CaaIdentities) > 0:
		return true
	case p.RequireEAB:
		return true
	default:
		return false
	}
}

// NotImplemented returns a 501 and is generally a placeholder for functionality which
// MAY be added at some point in the future but is not in any way a guarantee of such.
func NotImplemented(w http.ResponseWriter, _ *http.Request) {
	render.Error(w, acme.NewError(acme.ErrorNotImplementedType, "this API is not implemented"))
}

// GetAuthorization ACME api for retrieving an Authz.
func GetAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}
	az, err := db.GetAuthorization(ctx, chi.URLParam(r, "authzID"))
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving authorization"))
		return
	}
	if acc.ID != az.AccountID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own authorization '%s'", acc.ID, az.ID))
		return
	}
	if err = az.UpdateStatus(ctx, db); err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error updating authorization status"))
		return
	}

	linker.LinkAuthorization(ctx, az)

	w.Header().Set("Location", linker.GetLink(ctx, acme.AuthzLinkType, az.ID))
	render.JSON(w, az)
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
func GetChallenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)
	linker := acme.MustLinkerFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	payload, err := payloadFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	// NOTE: We should be checking that the request is either a POST-as-GET, or
	// that for all challenges except for device-attest-01, the payload is an
	// empty JSON block ({}). However, older ACME clients still send a vestigial
	// body (rather than an empty JSON block) and strict enforcement would
	// render these clients broken.
	prov, err := provisionerFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	azID := chi.URLParam(r, "authzID")
	ch, err := db.GetChallenge(ctx, chi.URLParam(r, "chID"), azID)
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving challenge"))
		return
	}
	ch.AuthorizationID = azID
	if acc.ID != ch.AccountID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
			"account '%s' does not own challenge '%s'", acc.ID, ch.ID))
		return
	}

	// Short-circuit for terminal states
	switch ch.Status {
	case acme.StatusValid, acme.StatusInvalid:
		linker.LinkChallenge(ctx, ch, azID)
		w.Header().Add("Link", link(linker.GetLink(ctx, acme.AuthzLinkType, azID), "up"))
		w.Header().Set("Location", linker.GetLink(ctx, acme.ChallengeLinkType, azID, ch.ID))
		render.JSON(w, ch)
		return
	}

	jwk, err := jwkFromContext(ctx)
	if err != nil {
		render.Error(w, err)
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
		if err := db.UpdateChallenge(ctx, ch); err != nil {
			render.Error(w, acme.WrapErrorISE(err, "error updating challenge"))
			return
		}
	}

	if err = ch.Validate(ctx, db, jwk, payload.value); err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error validating challenge"))
		return
	}

	// Populate RetryAfter for response if still processing
	if ch.Status == acme.StatusProcessing && ch.Retry != nil {
		ch.RetryAfter = ch.Retry.NextAttempt
	}

	// Schedule retry if still processing and retries remain
	if ch.Status == acme.StatusProcessing && ch.Retry != nil && ch.Retry.Active() {
		time.AfterFunc(retryInterval, func() {
			retryChallenge(ch.ID, azID, prov, acc.ID, payload.value)
		})
	}

	linker.LinkChallenge(ctx, ch, azID)

	w.Header().Add("Link", link(linker.GetLink(ctx, acme.AuthzLinkType, azID), "up"))
	w.Header().Set("Location", linker.GetLink(ctx, acme.ChallengeLinkType, azID, ch.ID))
	if ch.Status == acme.StatusProcessing && ch.RetryAfter != "" {
		w.Header().Add("Retry-After", ch.RetryAfter)
		// 200s are cachable. Don't cache this because it will likely change.
		w.Header().Add("Cache-Control", "no-cache")
	}
	render.JSON(w, ch)
}

// retryChallenge behaves similar to validation in GetChallenge, but simply attempts to perform a validation and
// write update the challenge record in the db if the challenge has remaining retry attempts.
//
// see: GetChallenge
func retryChallenge(chID, azID string, prov acme.Provisioner, accID string, value []byte) {
	ctx := context.Background()
	db := acme.MustDatabaseFromContext(ctx)

	ch, err := db.GetChallenge(ctx, chID, azID)
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
			retryChallenge(chID, azID, prov, accID, value)
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
		if err := db.UpdateChallenge(ctx, ch); err != nil {
			log.Printf("retryChallenge: error updating exhausted challenge %s: %v", chID, err)
		}
		return
	}

	// Update attempt counter and next attempt time
	ch.Retry.NumAttempts++
	ch.Retry.NextAttempt = clock.Now().Add(retryInterval).Format(time.RFC3339)
	if err := db.UpdateChallenge(ctx, ch); err != nil {
		log.Printf("retryChallenge: error updating retry state for challenge %s: %v", chID, err)
		return
	}

	acmeProv, ok := prov.(*provisioner.ACME)
	if !ok {
		log.Printf("retryChallenge: provisioner %s is not ACME type", prov.GetName())
		return
	}

	// Load account to get JWK
	acc, err := db.GetAccount(ctx, accID)
	if err != nil {
		log.Printf("retryChallenge: error loading account %s: %v", accID, err)
		return
	}

	// Build context with provisioner
	ctx = acme.NewProvisionerContext(ctx, acme.Provisioner(acmeProv))

	// Perform validation
	ch.AuthorizationID = azID
	if err = ch.Validate(ctx, db, acc.Key, value); err != nil {
		log.Printf("retryChallenge: error validating challenge %s: %v", chID, err)
		return
	}

	// Schedule next retry if still processing
	if ch.Status == acme.StatusProcessing && ch.Retry != nil && ch.Retry.Active() {
		time.AfterFunc(retryInterval, func() {
			retryChallenge(chID, azID, prov, accID, value)
		})
	}
}

// GetCertificate ACME api for retrieving a Certificate.
func GetCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := acme.MustDatabaseFromContext(ctx)

	acc, err := accountFromContext(ctx)
	if err != nil {
		render.Error(w, err)
		return
	}

	certID := chi.URLParam(r, "certID")
	cert, err := db.GetCertificate(ctx, certID)
	if err != nil {
		render.Error(w, acme.WrapErrorISE(err, "error retrieving certificate"))
		return
	}
	if cert.AccountID != acc.ID {
		render.Error(w, acme.NewError(acme.ErrorUnauthorizedType,
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
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write(certBytes)
}
