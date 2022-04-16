package chowder

import (
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// ScanResponse is a response with the result of a scan
type ScanResponse struct {
	Infected bool `json:"infected"`
	Response `json:",omitempty"`
}

// Proxy is a http proxy for a VirusScanner
type Proxy struct {
	AntiVirus VirusScanner
}

// Scan performs an scan on the body of the request
func (p *Proxy) Scan(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	log.Debug().Msg("received scan request")
	infected, msg, err := p.AntiVirus.Scan(r.Body)
	if err != nil {
		writeResponse(w, r, &Response{
			Message: msg,
			Error:   err.Error(),
		}, http.StatusInternalServerError)
		addLogFields(r.Context(), func(l zerolog.Context) zerolog.Context {
			return l.Str("daemon-response", msg).Err(err)
		})
		return
	}
	addLogFields(r.Context(), func(l zerolog.Context) zerolog.Context {
		return l.Str("daemon-response", msg).Bool("infected", infected)
	})
	writeResponse(w, r, &ScanResponse{
		Infected: infected,
		Response: Response{
			Message: msg,
		}}, http.StatusOK)
}

// Ok returns a response to a healthz request
func (p *Proxy) Ok(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	log.Debug().Msg("received health request")
	ok, msg, err := p.AntiVirus.Ok()
	if err != nil {
		addLogFields(r.Context(), func(l zerolog.Context) zerolog.Context {
			return l.Bool("ok", ok).Str("daemon-response", msg).Err(err)
		})
		writeResponse(w, r, &Response{
			Message: "Down",
			Error:   fmt.Sprintf("%v - daemon response: %v", err.Error(), msg),
		}, http.StatusInternalServerError)
		return
	}
	addLogFields(r.Context(), func(l zerolog.Context) zerolog.Context {
		return l.Bool("ok", ok).Str("daemon-response", msg)
	})
	if !ok {
		writeResponse(w, r, &Response{
			Message: "Down",
			Error:   msg,
		}, http.StatusInternalServerError)
		return
	}
	writeResponse(w, r, &Response{
		Message: "Up",
	}, http.StatusOK)
}
