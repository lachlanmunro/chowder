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
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes)
}
