package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/venture23-aleo/oracle-verification-backend/attestation/nitro"
	"github.com/venture23-aleo/oracle-verification-backend/u128"
)

type infoHandler struct {
	uniqueId         string
	pcrValues        [3]string
	liveCheckProgram string
	startTime        time.Time
}

func CreateInfoHandler(uniqueId string, pcrValues [3]string, liveCheckProgram string) http.Handler {
	return &infoHandler{
		uniqueId:         uniqueId,
		pcrValues:        pcrValues,
		liveCheckProgram: liveCheckProgram,
		startTime:        time.Now().UTC(),
	}
}

type uniqueIdInfo struct {
	Hex    string `json:"hexEncoded"`
	Base64 string `json:"base64Encoded"`
	Aleo   string `json:"aleoEncoded"`
}

type pcrValuesInfo struct {
	Hex    [3]string `json:"hexEncoded"`
	Base64 [3]string `json:"base64Encoded"`
	Aleo   string    `json:"aleoEncoded"`
}

type InfoResponse struct {
	TargetUniqueId   uniqueIdInfo  `json:"targetUniqueId"`
	TargetPcrValues  pcrValuesInfo `json:"targetPcrValues"`
	LiveCheckProgram string        `json:"liveCheckProgram"`
	StartTime        string        `json:"startTimeUTC"`
}

func (h *infoHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	log := GetContextLogger(req.Context())

	response := new(InfoResponse)

	uniqueIdBytes, err := hex.DecodeString(h.uniqueId)
	if err != nil {
		log.Println("failed to hex-decode unique ID:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(uniqueIdBytes) < 32 {
		log.Println("unique ID is shorter than 32 bytes")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	uniqueIdAleo1, err := u128.SliceToU128(uniqueIdBytes[0:16])
	if err != nil {
		log.Println("failed to parse unique ID chunk 1:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	uniqueIdAleo2, err := u128.SliceToU128(uniqueIdBytes[16:32])
	if err != nil {
		log.Println("failed to parse unique ID chunk 2:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response.TargetUniqueId = uniqueIdInfo{
		Hex:    h.uniqueId,
		Base64: base64.StdEncoding.EncodeToString(uniqueIdBytes),
		Aleo:   fmt.Sprintf("{ chunk_1: %su128, chunk_2: %su128 }", uniqueIdAleo1.String(), uniqueIdAleo2.String()),
	}

	var pcrBytes [3][48]byte

	for idx, pcr := range h.pcrValues {
		if pcr == "" {
			continue
		}
		buf, err := hex.DecodeString(pcr)
		if err != nil {
			log.Println("failed to hex-decode PCR value:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if len(buf) < 48 {
			log.Println("PCR value shorter than 48 bytes")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		copy(pcrBytes[idx][:], buf[:48])
	}

	response.TargetPcrValues = pcrValuesInfo{
		Hex: h.pcrValues,
		Base64: [3]string{
			base64.StdEncoding.EncodeToString(pcrBytes[0][:]),
			base64.StdEncoding.EncodeToString(pcrBytes[1][:]),
			base64.StdEncoding.EncodeToString(pcrBytes[2][:]),
		},
		Aleo: nitro.FormatPcrValues(pcrBytes),
	}

	response.LiveCheckProgram = h.liveCheckProgram
	response.StartTime = h.startTime.Format(time.DateTime)

	responseBody, err := json.Marshal(response)
	if err != nil {
		log.Println("failed to marshal response:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = w.Write(responseBody)
	if err != nil {
		log.Println("failed to write response:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
