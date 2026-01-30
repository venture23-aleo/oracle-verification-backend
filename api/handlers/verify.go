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

type VerifyReportsRequestMultipleTokens struct {
	Reports []attestation.AttestationResponseMultipleTokens `json:"reports"`
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

	var request struct {
		Reports []interface{} `json:"reports"`
	}
	var err error
	if err = json.Unmarshal(body, &request); err != nil {
		log.Println("error reading request:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	reports := request.Reports
	if len(reports) == 0 {
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
	for i, v := range reports {
		reportJsonBytes, err := json.Marshal(v)
		if err != nil {
			log.Printf("failed to marshal report to JSON: %s\n", err)
			errors = append(errors, err.Error())
			continue
		}
		var tempMap map[string]interface{}
		if err := json.Unmarshal(reportJsonBytes, &tempMap); err != nil {
			log.Printf("failed to unmarshal JSON for type checking: %s\n", err)
			errors = append(errors, err.Error())
			continue
		}

		isMultipleToken := false
		if results, ok := tempMap["attestationResults"]; ok {
			// Check if it's an array and if it has elements
			if resultsSlice, ok := results.([]interface{}); ok && len(resultsSlice) > 0 {
				isMultipleToken = true
			}
		}

		if isMultipleToken {
			err := vh.VerifyMultipleTokensReport(aleoSession, reportJsonBytes)
			if err != nil {
				log.Printf("error verifying multiple tokens report: %s\n", err)
				errors = append(errors, err.Error())
				continue
			}
		} else {
			err := vh.VerifySingleTokenReport(aleoSession, reportJsonBytes)
			if err != nil {
				log.Printf("error verifying single token report: %s\n", err)
				errors = append(errors, err.Error())
				continue
			}
		}
		
			

		validReports = append(validReports, i)	
	}

	respondVerify(req.Context(), w, validReports, strings.Join(errors, "; "))
}

func (vh *verifyHandler) VerifySingleTokenReport(aleoSession aleo_wrapper.Session, reportJsonBytes []byte) error {

	var report attestation.AttestationResponse
	err := json.Unmarshal(reportJsonBytes, &report)
	if err != nil {
		log.Printf("failed to unmarshal report: %s\n", err)
		return err
	}

	reportBytes, err := base64.StdEncoding.DecodeString(report.AttestationReport)
	if err != nil {
		log.Printf("failed to decode base64 %s report: %s\n", report.ReportType, err)
		return err
	}

	_, userData, err := attestation.VerifyReport(report.ReportType, reportBytes, report.Nonce, vh.targetUniqueId, vh.targetPcrValues)
	if err != nil {
		log.Printf("error verifying %s report: %s\n", report.ReportType, err)
		return err
	}

	err = attestation.VerifyReportData(aleoSession, userData, &report)
	if err != nil {
		log.Printf("error verifying %s report: %s\n", report.ReportType, err)
		return err
	}

	return nil
}

func (vh *verifyHandler) VerifyMultipleTokensReport(aleoSession aleo_wrapper.Session, reportJsonBytes []byte) error {
	var report attestation.AttestationResponseMultipleTokens
	err := json.Unmarshal(reportJsonBytes, &report)
	if err != nil {
		log.Printf("failed to unmarshal report: %s\n", err)
		return err
	}

	reportBytes, err := base64.StdEncoding.DecodeString(report.AttestationReport)
	if err != nil {
		log.Printf("failed to decode base64 %s report: %s\n", report.ReportType, err)
		return err
	}

	_, userData, err := attestation.VerifyReport(report.ReportType, reportBytes, report.Nonce, vh.targetUniqueId, vh.targetPcrValues)
	if err != nil {
		log.Printf("error verifying %s report: %s\n", report.ReportType, err)
		return err
	}

	err = attestation.VerifyReportDataForMultipleTokens(aleoSession, userData, &report)
	if err != nil {
		log.Printf("error verifying %s report: %s\n", report.ReportType, err)
		return err
	}

	return nil
}