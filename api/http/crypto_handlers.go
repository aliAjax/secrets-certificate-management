package httpapi

import (
	"encoding/base64"
	"net/http"

	backenddomain "github.com/example/secrets-cert-platform/internal/backend/domain"
	cryptodomain "github.com/example/secrets-cert-platform/internal/crypto/domain"
	policydomain "github.com/example/secrets-cert-platform/internal/policy/domain"
)

func (s *Server) registerCryptoRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/crypto/encrypt", s.cryptoEncrypt)
	mux.HandleFunc("POST /v1/crypto/decrypt", s.cryptoDecrypt)
	mux.HandleFunc("POST /v1/crypto/sign", s.cryptoSign)
	mux.HandleFunc("POST /v1/crypto/verify", s.cryptoVerify)
	mux.HandleFunc("POST /v1/crypto/derive", s.cryptoDerive)
	mux.HandleFunc("POST /v1/crypto/random", s.cryptoRandom)
}

func (s *Server) cryptoEncrypt(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "*", "/crypto", policydomain.CapabilityCreate) {
		return
	}
	var req struct {
		Plaintext string `json:"plaintext"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ciphertext, err := s.crypto.Encrypt(r.Context(), cryptodomain.EncryptRequest{Plaintext: []byte(req.Plaintext)})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, "*", "/crypto", "crypto.encrypt", nil)
	writeJSON(w, http.StatusOK, map[string]string{
		"ciphertext":  base64.StdEncoding.EncodeToString(ciphertext.Data),
		"key_version": ciphertext.KeyVersion,
	})
}

func (s *Server) cryptoDecrypt(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "*", "/crypto", policydomain.CapabilityRead) {
		return
	}
	var req struct {
		Ciphertext string `json:"ciphertext"`
		KeyVersion string `json:"key_version"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	plaintext, err := s.crypto.Decrypt(r.Context(), cryptodomain.DecryptRequest{
		Ciphertext: backenddomain.Ciphertext{Data: data, KeyVersion: req.KeyVersion},
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, "*", "/crypto", "crypto.decrypt", nil)
	writeJSON(w, http.StatusOK, map[string]string{"plaintext": string(plaintext)})
}

func (s *Server) cryptoSign(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "*", "/crypto", policydomain.CapabilityUpdate) {
		return
	}
	var req struct {
		Data string `json:"data"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sig, err := s.crypto.Sign(r.Context(), cryptodomain.SignRequest{Data: []byte(req.Data)})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, "*", "/crypto", "crypto.sign", nil)
	writeJSON(w, http.StatusOK, map[string]string{
		"signature": base64.StdEncoding.EncodeToString(sig.Signature),
		"algorithm": sig.Algorithm,
	})
}

func (s *Server) cryptoVerify(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "*", "/crypto", policydomain.CapabilityRead) {
		return
	}
	var req struct {
		Data      string `json:"data"`
		Signature string `json:"signature"`
		Algorithm string `json:"algorithm"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ok, err := s.crypto.Verify(r.Context(), cryptodomain.VerifyRequest{
		Data:      []byte(req.Data),
		Signature: backenddomain.Signature{Signature: sig, Algorithm: req.Algorithm},
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, "*", "/crypto", "crypto.verify", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"valid": ok})
}

func (s *Server) cryptoDerive(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "*", "/crypto", policydomain.CapabilityCreate) {
		return
	}
	var req struct {
		Material string `json:"material"`
		Salt     string `json:"salt"`
		Length   int    `json:"length"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	derived, err := s.crypto.DeriveKey(r.Context(), cryptodomain.DeriveRequest{
		Material: []byte(req.Material),
		Salt:     []byte(req.Salt),
		Length:   req.Length,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, "*", "/crypto", "crypto.derive", nil)
	writeJSON(w, http.StatusOK, map[string]string{"derived": base64.StdEncoding.EncodeToString(derived)})
}

func (s *Server) cryptoRandom(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(w, r, "*", "/crypto", policydomain.CapabilityRead) {
		return
	}
	var req struct {
		Length int `json:"length"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	random, err := s.crypto.Random(r.Context(), cryptodomain.RandomRequest{Length: req.Length})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordSuccess(r, "*", "/crypto", "crypto.random", nil)
	writeJSON(w, http.StatusOK, map[string]string{"random": base64.StdEncoding.EncodeToString(random)})
}
