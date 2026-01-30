package attestation

import (
	"bytes"
	"errors"
	"log"

	"github.com/venture23-aleo/oracle-verification-backend/attestation/nitro"
	"github.com/venture23-aleo/oracle-verification-backend/attestation/sgx"
	"github.com/venture23-aleo/oracle-verification-backend/common"
	"github.com/venture23-aleo/oracle-verification-backend/constants"

	encoding "github.com/venture23-aleo/aleo-oracle-encoding"
	aleo_wrapper "github.com/venture23-aleo/aleo-utils-go"
)

// Tee types
const (
	// AWS Nitro enclave
	TEE_TYPE_NITRO string = "nitro"
	// Intel SGX
	TEE_TYPE_SGX string = "sgx"

	ALEO_STRUCT_REPORT_DATA_SIZE = 10
)

type AttestationRequest struct {
	Url string `json:"url"`

	RequestMethod  string  `json:"requestMethod"`
	Selector       string  `json:"selector,omitempty"`
	ResponseFormat string  `json:"responseFormat"`
	HTMLResultType *string `json:"htmlResultType,omitempty"`

	RequestBody        *string `json:"requestBody,omitempty"`
	RequestContentType *string `json:"requestContentType,omitempty"`

	RequestHeaders map[string]string `json:"requestHeaders,omitempty"`

	EncodingOptions encoding.EncodingOptions `json:"encodingOptions"`

	DebugRequest bool `json:"debugRequest,omitempty"`
}

type AttestationResponse struct {
	AttestationReport  string             `json:"attestationReport"`
	ReportType         string             `json:"reportType"`
	AttestationData    string             `json:"attestationData"`
	ResponseBody       string             `json:"responseBody"`
	ResponseStatusCode int                `json:"responseStatusCode"`
	Nonce              string             `json:"nonce,omitempty"`
	Timestamp          int64              `json:"timestamp"`
	AttestationRequest AttestationRequest `json:"attestationRequest"`
}

type AttestationResponseMultipleTokens struct {
	AttestationReport  string             `json:"attestationReport"`
	ReportType         string             `json:"reportType"`
	Nonce              string             `json:"nonce,omitempty"`
	Timestamp          int64              `json:"timestamp"`
	AttestationResults []AttestationResultForEachToken `json:"attestationResults"`
}


type AttestationResultForEachToken struct {
	// Index int `json:"index,omitempty"` // The index of the token.
	// UserDataChunk []byte `json:"userDataChunk,omitempty"` // The user data chunk.
	AttestationData string `json:"attestationData"` // The attestation data.
	AtttestationRequest AttestationRequest `json:"attestationRequest"` // The attestation request.
	ResponseBody string `json:"responseBody"` // The response body.
	ResponseStatusCode int `json:"responseStatusCode"`
	AttestationTimestamp int64 `json:"timestamp"` // The attestation timestamp.
}


var (
	ErrVerificationFailedToPrepare   = errors.New("verification error: failed to prepare data for report verification")
	ErrVerificationFailedToFormat    = errors.New("verification error: failed to format message for report verification")
	ErrVerificationFailedToHash      = errors.New("verification error: failed to hash message for report verification")
	ErrVerificationFailedToMatchData = errors.New("verification error: userData hashes don't match")
	ErrUnsupportedReportType         = errors.New("unsupported report type")
)

func VerifyReport(reportType string, report []byte, nonce string, targetUniqueId string, targetPcrValues [3]string) (interface{}, []byte, error) {
	switch reportType {
	case TEE_TYPE_SGX:
		parsedReport, err := sgx.VerifySgxReport(report, targetUniqueId)
		if err != nil {
			return nil, nil, err
		}

		return parsedReport, parsedReport.Data, nil

	case TEE_TYPE_NITRO:
		parsedReport, err := nitro.VerifyNitroReport(report, nonce, targetPcrValues)
		if err != nil {
			return nil, nil, err
		}

		return parsedReport, parsedReport.UserData, nil

	default:
		return nil, nil, ErrUnsupportedReportType
	}
}

func VerifyReportData(aleoSession aleo_wrapper.Session, userData []byte, resp *AttestationResponse) error {
	if resp == nil {
		return ErrVerificationFailedToPrepare
	}

	dataBytes, err := PrepareProofData(resp.ResponseStatusCode, resp.AttestationData, resp.Timestamp, &resp.AttestationRequest)
	if err != nil {
		log.Printf("prepareProofData: %v", err)
		return ErrVerificationFailedToPrepare
	}

	// Ensure dataBytes is non-empty before writing special-case overrides
	if len(dataBytes) > 0 {
		if resp.AttestationRequest.Url == PriceFeedAleoUrl {
			dataBytes[21] = 8
		} else if resp.AttestationRequest.Url == PriceFeedBtcUrl {
			dataBytes[21] = 12
		} else if resp.AttestationRequest.Url == PriceFeedEthUrl {
			dataBytes[21] = 11
		} else if resp.AttestationRequest.Url == PriceFeedUsdtUrl {
			dataBytes[21] = 9
		} else if resp.AttestationRequest.Url == PriceFeedUsdcUrl {
			dataBytes[21] = 10
		}
	}

	formattedData, err := aleoSession.FormatMessage(dataBytes, ALEO_STRUCT_REPORT_DATA_SIZE)
	if err != nil {
		log.Printf("aleo.FormatMessage(): %v\n", err)
		return ErrVerificationFailedToFormat
	}

	attestationHash, err := aleoSession.HashMessage(formattedData)
	if err != nil {
		log.Printf("aleo.HashMessage(): %v\n", err)
		return ErrVerificationFailedToHash
	}

	// Poseidon8 hash is 16 bytes when represented in bytes so here we compare
	// the resulting hash only with 16 out of 64 bytes of the report's user data.
	// IMPORTANT! this needs to be adjusted if we put more data in the report
	if len(userData) < 16 {
		return ErrVerificationFailedToMatchData
	}
	if !bytes.Equal(attestationHash, userData[:16]) {
		return ErrVerificationFailedToMatchData
	}

	return nil
}



func PrepareOracleUserDataChunk(statusCode int,
	attestationData string,
	timestamp uint64,
	attestationRequest AttestationRequest) (userDataChunk []byte, err error) {
	// Step 2: Prepare the proof data.
	userDataProof, err := PrepareProofData(statusCode, attestationData, int64(timestamp), &attestationRequest)
	
	if err != nil {
		return nil, err
	}

	if common.IsPriceFeedURL(attestationRequest.Url) {
		tokenID := common.GetTokenIDFromPriceFeedURL(attestationRequest.Url)
		if tokenID == 0 {
			return nil, errors.New("unsupported price feed URL")
		}
		// MetaHeaders is 32 bytes total.
		// - The first 21 bytes are reserved for other metadata.
		// - The token ID is stored at byte index 21 (0-based).
		userDataProof[21] = byte(tokenID)
	}

	userDataChunk = make([]byte, constants.ChunkSizeInBytes)
	copy(userDataChunk, userDataProof)

	return userDataChunk, nil
}

func VerifyReportDataForMultipleTokens(aleoSession aleo_wrapper.Session, userData []byte, resp *AttestationResponseMultipleTokens) error {
	if resp == nil {
		return ErrVerificationFailedToPrepare
	}

	dataBytes := make([]byte, 0)

	for _, result := range resp.AttestationResults {
		userDataChunk, err := PrepareOracleUserDataChunk(result.ResponseStatusCode, result.AttestationData, uint64(result.AttestationTimestamp), result.AtttestationRequest)
		if err != nil {
			log.Printf("PrepareOracleUserDataChunk(): %v", err)
			return err
		}
		dataBytes = append(dataBytes, userDataChunk...)
	}
	
	formattedData, err := aleoSession.FormatMessage(dataBytes, ALEO_STRUCT_REPORT_DATA_SIZE)
	if err != nil {
		log.Printf("aleo.FormatMessage(): %v\n", err)
		return ErrVerificationFailedToFormat
	}

	attestationHash, err := aleoSession.HashMessage(formattedData)
	if err != nil {
		log.Printf("aleo.HashMessage(): %v\n", err)
		return ErrVerificationFailedToHash
	}

	// Poseidon8 hash is 16 bytes when represented in bytes so here we compare
	// the resulting hash only with 16 out of 64 bytes of the report's user data.
	// IMPORTANT! this needs to be adjusted if we put more data in the report
	if len(userData) < 16 {
		return ErrVerificationFailedToMatchData
	}
	if !bytes.Equal(attestationHash, userData[:16]) {
		return ErrVerificationFailedToMatchData
	}

	return nil
}