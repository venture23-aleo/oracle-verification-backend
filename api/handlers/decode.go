package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	aleo_wrapper "github.com/venture23-aleo/aleo-utils-go"

	"github.com/venture23-aleo/oracle-verification-backend/attestation"
)

type DecodeProofDataRequest struct {
	UserData string `json:"userData"`
}


type DecodedData interface {
	*attestation.DecodedProofData |
	[]*attestation.DecodedProofData
}

type DecodeProofDataResponse[T DecodedData] struct {
	DecodedData  T `json:"decodedData,omitempty"`
	Success      bool                          `json:"success"`
	ErrorMessage string                        `json:"errorMessage,omitempty"`
}


func respondDecode[T DecodedData](ctx context.Context, w http.ResponseWriter, decodedData T, err error) {
	r := &DecodeProofDataResponse[T]{
		DecodedData: decodedData,
		Success:     err == nil && decodedData != nil,
	}

	if err != nil {
		r.ErrorMessage = err.Error()
	}

	log := GetContextLogger(ctx)

	msg, err := json.Marshal(r)
	if err != nil {
		log.Println("failed to marshal response:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Write(msg)
}

func CreateDecodeHandler(aleo aleo_wrapper.Wrapper) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if !strings.HasPrefix(strings.ToLower(req.Header.Get("Content-Type")), "application/json") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		log := GetContextLogger(req.Context())

		defer req.Body.Close()

		body, ok := readRequestBody(w, req)
		if !ok {
			return
		}

		request := new(DecodeProofDataRequest)
		err := json.Unmarshal(body, request)
		if err != nil {
			log.Println("error reading request", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if request.UserData == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		aleoSession, err := aleo.NewSession()
		if err != nil {
			log.Println("error creating new aleo session:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer aleoSession.Close()

		recoveredMessage, err := aleoSession.RecoverMessage([]byte(request.UserData))
		if err != nil {
			log.Println("error recovering formatted message:", err)
			respondDecode[*attestation.DecodedProofData](req.Context(), w, nil, err)
			return
		}

		//split in the range of 512 bytes
		recoveredMessages := make([][]byte, 0)
		for i := 0; i < len(recoveredMessage); i += 512 {
			end := i + 512
			if end > len(recoveredMessage) {
				end = len(recoveredMessage)
			}
			recoveredMessages = append(recoveredMessages, recoveredMessage[i:end])
		}
		
		decodedData := make([]*attestation.DecodedProofData, 0)

		for _, message := range recoveredMessages {
			if message[0] == 0 {
				break
			}
			decodedDataItem, err := attestation.DecodeProofData(message)
			if err != nil {
				log.Println("error decoding proof data:", err)
				respondDecode[*attestation.DecodedProofData](req.Context(), w, nil, err)
				return
			}
			decodedData = append(decodedData, decodedDataItem)
		}

		if len(decodedData) == 0 {
			respondDecode[*attestation.DecodedProofData](req.Context(), w, nil, errors.New("no decoded data"))
			return
		}

		if len(decodedData) > 1 {
			respondDecode[[]*attestation.DecodedProofData](req.Context(), w, decodedData, nil)
			return
		} else {
			respondDecode[*attestation.DecodedProofData](req.Context(), w, decodedData[0], nil)
			return
		}
	}
}
