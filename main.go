package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/venture23-aleo/oracle-verification-backend/api"
	"github.com/venture23-aleo/oracle-verification-backend/attestation/nitro"
	"github.com/venture23-aleo/oracle-verification-backend/config"
	"github.com/venture23-aleo/oracle-verification-backend/contract"

	aleo_utils "github.com/venture23-aleo/aleo-utils-go"
)

const (
	IdleTimeout      = 30
	ReadWriteTimeout = 20
)

func main() {
	confContent, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalln(err)
	}

	conf, err := config.LoadConfig(confContent)
	if err != nil {
		log.Fatalln(err)
	}

	if !conf.LiveCheck.Skip {
		log.Println("Requesting SGX Unique ID and Nitro PCR values from", conf.LiveCheck.ContractName, "using", conf.LiveCheck.ApiBaseUrl)
		liveUniqueId, err := contract.GetSgxUniqueIDAssert(conf.LiveCheck.ApiBaseUrl, conf.LiveCheck.ContractName)
		if err != nil {
			log.Fatalln("Failed to fetch live contract's SGX Unique ID assertion:", err)
		}

		log.Printf("Fetched SGX Unique ID assertion from %s: %s", conf.LiveCheck.ContractName, liveUniqueId)

		if liveUniqueId != conf.UniqueIdTarget {
			log.Fatalf("Reproducible SGX build of the oracle backend produced a different SGX Unique ID than the live contract.\nLive SGX Unique ID: %s\nReproduced SGX Unique ID: %s\n", liveUniqueId, conf.UniqueIdTarget)
		}

		livePcrValues, err := contract.GetNitroPcrValuesAssert(conf.LiveCheck.ApiBaseUrl, conf.LiveCheck.ContractName)
		if err != nil {
			log.Fatalln("Failed to fetch live contract's Nitro PCR values assertion:", err)
		}

		log.Printf("Fetched Nitro PCR values asserttion from %s: %s", conf.LiveCheck.ContractName, liveUniqueId)

		if !slices.Equal(livePcrValues, conf.PcrValuesTarget) {
			log.Fatalf("Reproducible Nitro build of the oracle backend produced different Nitro PCR values than the live contract.\nLive Nitro PCR values: %s\nReproduced Nitro PCR values: %s\n", strings.Join(livePcrValues, ", "), strings.Join(conf.PcrValuesTarget[:], ", "))
		}
	} else {
		log.Println("WARNING: skipping Aleo live contract SGX Unique ID and Nitro PCR values check")
	}

	log.Println("Expecting Aleo Oracle backend to have SGX Unique ID:", conf.UniqueIdTarget)
	log.Println("Expecting Aleo Oracle backend to have Nitro PCR values:", strings.Join(conf.PcrValuesTarget, ", "))

	err = nitro.Init()
	if err != nil {
		log.Fatalln("Failed to initialize Nitro report verifier:", err)
	}

	aleo, close, err := aleo_utils.NewWrapper()
	if err != nil {
		log.Fatalln("Failed to initialize Aleo wrapper:", err)
	}
	defer close()

	mux := api.CreateApi(aleo, conf)

	bindAddr := fmt.Sprintf(":%d", conf.Port)

	server := &http.Server{
		IdleTimeout:       time.Second * IdleTimeout,
		ReadHeaderTimeout: time.Second * ReadWriteTimeout,
		WriteTimeout:      time.Second * ReadWriteTimeout,
		Addr:              bindAddr,
		Handler:           mux,
	}

	log.Printf("oracle-verification-backend: starting http server on %s\n", bindAddr)
	log.Fatalln(server.ListenAndServe())
	
}
