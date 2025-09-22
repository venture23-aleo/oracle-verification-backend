package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/venture23-aleo/oracle-verification-backend/attestation"
	"github.com/venture23-aleo/oracle-verification-backend/config"

	aleo_wrapper "github.com/venture23-aleo/aleo-utils-go"
)

type verifyHandler struct {
	aleoWrapper     aleo_wrapper.Wrapper
	targetUniqueId  string
	targetPcrValues [3]string
}

type VerifyReportsRequest struct {
	Reports []attestation.AttestationResponse `json:"reports"`
}

type VerifyReportsResponse struct {
	Success      bool   `json:"success"`
	ValidReports []int  `json:"validReports"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

func respondVerify(ctx context.Context, w http.ResponseWriter, validReports []int, errors string) {
	log := GetContextLogger(ctx)

	r := &VerifyReportsResponse{
		ValidReports: validReports,
		Success:      true,
	}

	if len(errors) != 0 {
		r.Success = false
		r.ErrorMessage = errors
	}

	msg, err := json.Marshal(r)
	if err != nil {
		log.Println("failed to marshal response:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(msg)
}

func CreateVerifyHandler(aleoWrapper aleo_wrapper.Wrapper, uniqueId string, pcrValues [3]string) http.Handler {
	return &verifyHandler{
		aleoWrapper:     aleoWrapper,
		targetUniqueId:  uniqueId,
		targetPcrValues: pcrValues,
	}
}

func readRequestBody(w http.ResponseWriter, req *http.Request) ([]byte, bool) {
	if req.ContentLength != -1 && req.ContentLength > config.MAX_REQUEST_BODY_SIZE {
		log.Println("request body is too large")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return nil, false
	}
	limitReader := io.LimitReader(req.Body, config.MAX_REQUEST_BODY_SIZE+1)
	body, err := io.ReadAll(limitReader)
	if err != nil {
		log.Println("error reading request body:", err)
		w.WriteHeader(http.StatusBadRequest)
		return nil, false
	}

	if int64(len(body)) > config.MAX_REQUEST_BODY_SIZE {
		log.Println("request body is too large")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return nil, false
	}

	return body, true
}

func (vh *verifyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if req.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	log := GetContextLogger(req.Context())

	defer req.Body.Close()

	body, ok := readRequestBody(w, req)
	if !ok {
		return
	}

	request := new(VerifyReportsRequest)
	err := json.Unmarshal(body, request)
	if err != nil {
		log.Println("error reading request", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if len(request.Reports) == 0 {
		log.Println("no reports to verify")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	aleoSession, err := vh.aleoWrapper.NewSession()
	if err != nil {
		log.Println("error creating new aleo session:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer aleoSession.Close()

	validReports := make([]int, 0)
	var errors []string
	for i, v := range request.Reports {
		reportBytes, err := base64.StdEncoding.DecodeString(v.AttestationReport)
		if err != nil {
			log.Printf("failed to decode base64 %s report: %s\n", v.ReportType, err)
			errors = append(errors, err.Error())
			break
		}

		_, userData, err := attestation.VerifyReport(v.ReportType, reportBytes, v.Nonce, vh.targetUniqueId, vh.targetPcrValues)
		if err != nil {
			log.Printf("error verifying %s report: %s\n", v.ReportType, err)
			errors = append(errors, err.Error())
			break
		}

		err = attestation.VerifyReportData(aleoSession, userData, &v)
		if err != nil {
			log.Printf("error verifying %s report: %s\n", v.ReportType, err)
			errors = append(errors, err.Error())
			break
		}

		validReports = append(validReports, i)
	}

	respondVerify(req.Context(), w, validReports, strings.Join(errors, "; "))
}
