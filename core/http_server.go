package core

import (
	"context"
	"sync"

	"github.com/caddyserver/certmagic"
	"github.com/gorilla/mux"
	"github.com/mholt/acmez/acme"
	"net/http"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

type HttpServer struct {
	srv        *http.Server
	acmeTokens map[string]string
	tokenMtx   sync.RWMutex
	magic      *certmagic.Config
}

func NewHttpServer() (*HttpServer, error) {
	s := &HttpServer{}
	s.acmeTokens = make(map[string]string)

	r := mux.NewRouter()
	s.srv = &http.Server{
		Handler:      r,
		Addr:         ":80",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	r.HandleFunc("/.well-known/acme-challenge/{token}", s.handleACMEChallenge).Methods("GET")
	r.PathPrefix("/").HandlerFunc(s.handleRedirect)

	return s, nil
}

// SetMagic sets the certmagic config for distributed ACME challenge handling
func (s *HttpServer) SetMagic(magic *certmagic.Config) {
	s.magic = magic
	log.Info("http: certmagic integration enabled for ACME challenges")
}

func (s *HttpServer) Start() {
	log.Info("http: starting HTTP server on port 80 for ACME challenges")
	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("http: server error: %v", err)
		}
	}()
}

func (s *HttpServer) AddACMEToken(token string, keyAuth string) {
	s.tokenMtx.Lock()
	defer s.tokenMtx.Unlock()
	s.acmeTokens[token] = keyAuth
	log.Debug("http: added ACME token: %s", token)
}

func (s *HttpServer) RemoveACMEToken(token string) {
	s.tokenMtx.Lock()
	defer s.tokenMtx.Unlock()
	delete(s.acmeTokens, token)
	log.Debug("http: removed ACME token: %s", token)
}

func (s *HttpServer) ClearACMETokens() {
	s.tokenMtx.Lock()
	defer s.tokenMtx.Unlock()
	s.acmeTokens = make(map[string]string)
}

func (s *HttpServer) handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]

	// First, try our local token store
	s.tokenMtx.RLock()
	key, ok := s.acmeTokens[token]
	s.tokenMtx.RUnlock()

	if ok {
		log.Info("http: ACME challenge response (local) for token: %s", token)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(key))
		return
	}

	// If we have certmagic configured, try its distributed handler
	if s.magic != nil {
		// certmagic stores challenges in its storage, keyed by token
		// Try to get the challenge from certmagic's issuers
		for _, issuer := range s.magic.Issuers {
			if acmeIssuer, ok := issuer.(*certmagic.ACMEIssuer); ok {
				if acmeIssuer.HandleHTTPChallenge(w, r) {
					log.Info("http: ACME challenge response (certmagic) for token: %s", token)
					return
				}
			}
		}
	}

	log.Warning("http: ACME token not found: %s", token)
	w.WriteHeader(http.StatusNotFound)
}

func (s *HttpServer) handleRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.URL.String(), http.StatusFound)
}

// HTTP01Solver implements acmez.Solver for HTTP-01 ACME challenges.
// It uses our HttpServer on port 80 to serve challenge responses.
type HTTP01Solver struct {
	httpServer *HttpServer
}

// NewHTTP01Solver creates a new HTTP-01 solver that uses the given HttpServer
func NewHTTP01Solver(hs *HttpServer) *HTTP01Solver {
	return &HTTP01Solver{httpServer: hs}
}

// Present is called before the ACME server validates the challenge.
// It stores the challenge token and key authorization so our HTTP server can respond.
func (s *HTTP01Solver) Present(ctx context.Context, chal acme.Challenge) error {
	keyAuth := chal.KeyAuthorization
	s.httpServer.AddACMEToken(chal.Token, keyAuth)
	log.Info("http: presenting ACME HTTP-01 challenge for token: %s", chal.Token)
	return nil
}

// CleanUp is called after the ACME challenge is complete (success or failure).
// It removes the challenge token from our HTTP server.
func (s *HTTP01Solver) CleanUp(ctx context.Context, chal acme.Challenge) error {
	s.httpServer.RemoveACMEToken(chal.Token)
	log.Debug("http: cleaned up ACME HTTP-01 challenge for token: %s", chal.Token)
	return nil
}
