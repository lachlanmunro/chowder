package chowder

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
)

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
	log.Debug().Msg("recieved scan request")
	infected, msg, err := p.AntiVirus.Scan(r.Body)
	if err != nil {
		writeResponse(w, r, &Response{
			Message: msg,
			Error:   err.Error(),
		}, http.StatusInternalServerError)
		getLog(r.Context()).Error().Str("daemon-response", msg).Err(err).Msg("failed to scan")
		return
	}
	getLog(r.Context()).Info().Str("daemon-response", msg).Bool("infected", infected).Msg("scan completed")
	writeResponse(w, r, &ScanResponse{
		Infected: infected,
		Response: Response{
			Message: msg,
		}}, http.StatusOK)
}

// Ok returns a response to a healthz request
func (p *Proxy) Ok(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	log.Debug().Msg("recieved health request")
	ok, msg, err := p.AntiVirus.Ok()
	if err != nil {
		getLog(r.Context()).Error().Bool("ok", ok).Str("daemon-response", msg).Err(err).Msg("failed to ping daemon")
		writeResponse(w, r, &Response{
			Message: "Down",
			Error:   fmt.Sprintf("%v - daemon response: %v", err.Error(), msg),
		}, http.StatusInternalServerError)
		return
	}
	if !ok {
		writeResponse(w, r, &Response{
			Message: "Down",
			Error:   msg,
		}, http.StatusInternalServerError)
		getLog(r.Context()).Error().Bool("ok", ok).Str("daemon-response", msg).Msg("pinged daemon")
		return
	}
	getLog(r.Context()).Debug().Bool("ok", ok).Str("daemon-response", msg).Msg("pinged daemon")
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
