package chowder

import (
	"encoding/json"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
)

var okAsBytes = []byte("OK")

// Response is a baseline response
type Response struct {
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ScanResponse is a response with the result of a scan
type ScanResponse struct {
	Infected bool
	Response `json:",omitempty"`
}

// Proxy is a http proxy for a VirusScanner
type Proxy struct {
	AntiVirus VirusScanner
}

// Scan performs an scan on the body of the request
func (p *Proxy) Scan(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	infected, msg, err := p.AntiVirus.Scan(r.Body)
	if err != nil {
		log.Error().Err(err).Str("daemon", msg).Msg("Failed steam scan")
		writeResponse(w, r, &Response{
			Message: msg,
			Error:   err.Error(),
		}, http.StatusInternalServerError)
		return
	}
	writeResponse(w, r, &ScanResponse{
		Infected: infected,
		Response: Response{
			Message: http.StatusText(http.StatusInternalServerError),
			Error:   err.Error(),
		}}, http.StatusOK)
}

// Ok returns a response to a healthz request
func (p *Proxy) Ok(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ok, msg, err := p.AntiVirus.Ok()
	if err != nil {
		writeResponse(w, r, &Response{
			Message: msg,
			Error:   err.Error(),
		}, http.StatusInternalServerError)
		return
	}
	if !ok {
		writeResponse(w, r, &Response{
			Message: "Down",
			Error:   msg,
		}, http.StatusInternalServerError)
		return
	}
	writeResponse(w, r, &Response{
		Message: "Ok",
	}, http.StatusOK)
}

func writeResponse(w http.ResponseWriter, r *http.Request, resp interface{}, code int) {
	bytes, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes)
}