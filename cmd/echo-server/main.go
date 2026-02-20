package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"
)

type echoState struct {
	mu       sync.RWMutex
	lastBody string
}

func main() {
	state := &echoState{}

	http.HandleFunc("/last", func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		last := state.lastBody
		state.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"received": last}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		payload := string(body)
		log.Printf("ECHO SERVER RECEIVED: %s", payload)

		state.mu.Lock()
		state.lastBody = payload
		state.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"received": payload}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	log.Printf("echo server listening on :9000")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		log.Fatalf("echo server failed: %v", err)
	}
}
