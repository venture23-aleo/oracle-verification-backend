package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/edgelesssys/ego/eclient"
)

type DecodeQuoteRequest struct {
	Quote string `json:"quote"`
}

func DecodeQuoteHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		defer req.Body.Close()

		body, ok := readRequestBody(w, req)
		if !ok {
			return
		}

		var payload DecodeQuoteRequest
		if err := json.Unmarshal(body, &payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		reportBytes, err := base64.StdEncoding.DecodeString(payload.Quote)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		report, err := eclient.VerifyRemoteReport(reportBytes)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		decodedQuote, err := json.Marshal(report)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.WriteHeader(http.StatusOK)
		w.Write(decodedQuote)
	}
}