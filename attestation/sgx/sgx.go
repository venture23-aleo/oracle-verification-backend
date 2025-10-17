package sgx

import (
	"encoding/hex"
	"errors"
	"log"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/ego/eclient"
)

var allowedAdvisories = map[string]bool{
	// these are allowed under current policy
	"INTEL-SA-00615": true,
}

func VerifySgxReport(reportBytes []byte, targetUniqueId string) (*attestation.Report, error) {
	report, err := eclient.VerifyRemoteReport(reportBytes)

	if err == attestation.ErrTCBLevelInvalid {
		switch report.TCBStatus {
		case tcbstatus.ConfigurationNeeded, tcbstatus.ConfigurationAndSWHardeningNeeded:
			// tolerate these under current policy
		default:
			return nil, errors.New("report has invalid TCB level")
		}
	}

	if err != nil {
		return nil, err
	}

	uniqueId := hex.EncodeToString(report.UniqueID)

	if uniqueId != targetUniqueId {
		log.Printf("reporting enclave unique ID doesn't match the expected one, expected=%s, got=%s", targetUniqueId, uniqueId)
		return nil, errors.New("report unique ID doesn't match target")
	}

	// check TCB status and advisories
	// if not up to date, check advisories against allowed list
	// if any advisory is not in allowed list, reject report
	// if all advisories are in allowed list, accept report
	// if up to date, accept report
	if report.TCBStatus != tcbstatus.UpToDate && len(report.TCBAdvisories) > 0 {
		for _, adv := range report.TCBAdvisories {
			if allowedAdvisories[adv] {
				// this is allowed under current policy
				continue
			} else {
				return nil, errors.New("report has disallowed TCB advisory: " + adv)
			}
		}
  	}
  
	if report.Debug {
		log.Printf("SGX quote is in debug mode")
		return nil, errors.New("quote is in debug mode")
	}

	return &report, nil
}
