package chowder

import (
	"encoding/json"
	"net/http"
)

// Response is a baseline response
type Response struct {
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

func writeResponse(w http.ResponseWriter, r *http.Request, resp interface{}, code int) {
	bytes, err := json.Marshal(resp)
	if err == nil {
		w.WriteHeader(code)
		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(bytes)
		if err == nil {
			return
		}
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
	return
}
