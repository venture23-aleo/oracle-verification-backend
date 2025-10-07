package api

import (
	"net/http"

	"github.com/venture23-aleo/oracle-verification-backend/api/handlers"
	"github.com/venture23-aleo/oracle-verification-backend/config"

	aleo_wrapper "github.com/venture23-aleo/aleo-utils-go"

	"github.com/rs/cors"
)

func CreateApi(aleoWrapper aleo_wrapper.Wrapper, conf *config.Configuration) http.Handler {
	if conf == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "server configuration missing", http.StatusInternalServerError)
		})
	}
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{http.MethodPost},
	})

	addMiddleware := func(h http.Handler) http.Handler {
		return handlers.LogAndTraceMiddleware(handlers.PanicMiddleware(corsMiddleware.Handler(handlers.HeaderMiddleware(h))))
	}

	mux := http.NewServeMux()

	// Avoid out-of-range panics if fewer than 3 PCR values are configured
	var targetPcrs [3]string
	for i := 0; i < 3 && i < len(conf.PcrValuesTarget); i++ {
		targetPcrs[i] = conf.PcrValuesTarget[i]
	}

	mux.Handle("/info", addMiddleware(handlers.CreateInfoHandler(conf.UniqueIdTarget, targetPcrs, conf.LiveCheck.ContractName)))
	mux.Handle("/verify", addMiddleware(handlers.CreateVerifyHandler(aleoWrapper, conf.UniqueIdTarget, targetPcrs)))
	mux.Handle("/decode", addMiddleware(handlers.CreateDecodeHandler(aleoWrapper)))
	mux.Handle("/decode_quote", addMiddleware(handlers.DecodeQuoteHandler()))

	return mux
}
