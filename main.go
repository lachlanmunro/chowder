package main

import (
	"flag"
	"net/http"
	"os"

	"github.com/julienschmidt/httprouter"
	chowder "github.com/lachlanmunro/chowder/pkg"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	level := flag.String("level", "info", "Log level is one of debug, info, warn, error, fatal, panic")
	bind := flag.String("bind", ":3399", "Binding URL")
	antivirusURL := flag.String("antivirus", "127.0.0.1:3398", "Destination antivirus URL")
	cert := flag.String("cert", "server.crt", "Server TLS certificate")
	key := flag.String("key", "server.key", "Server TLS key")
	pretty := flag.Bool("pretty", true, "Use pretty logging (slower)")
	flag.Parse()
	if *pretty {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
	loglevel, err := zerolog.ParseLevel(*level)
	if err != nil {
		log.Fatal().Str("loglevel", *level).Err(err).Msg("Loglevel must be one of debug, info, warn, error, fatal, panic")
	}
	zerolog.SetGlobalLevel(loglevel)
	zerolog.TimeFieldFormat = ""
	proxy := &chowder.Proxy{AntiVirus: chowder.NewClamAV(*antivirusURL)}
	router := httprouter.New()
	router.POST("/scan", proxy.Scan)
	router.GET("/healthz", proxy.Ok)
	router.GET("/metrics", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) { promhttp.Handler().ServeHTTP(w, r) })
	log.Fatal().Err(http.ListenAndServeTLS(*bind, *cert, *key, chowder.LogRequests(router))).Msg("Closed")
}
