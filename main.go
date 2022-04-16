package main

import (
	"flag"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/julienschmidt/httprouter"
	chowder "github.com/lachlanmunro/chowder/pkg"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"
)

func main() {
	level := flag.String("level", "info", "Log level is one of debug, info, warn, error, fatal, panic")
	bind := flag.String("bind", ":3399", "Binding URL")
	antivirusURL := flag.String("antivirus", "127.0.0.1:3310", "Destination antivirus URL")
	certFile := flag.String("certfile", "server.crt", "Server TLS certificate")
	keyFile := flag.String("keyfile", "server.key", "Server TLS key")
	pretty := flag.Bool("pretty", false, "Use pretty logging (instead of JSON)")
	usersFile := flag.String("usersfile", "users.yml", "Users file containing auth tokens in the format `token: username\\n`, if not supplied or empty authentication will be disabled")
	unixTime := flag.Bool("unixtime", false, "Log unix timestamps instead of RFC3339Nano")
	floatDurations := flag.Bool("floatdur", false, "Log float durations instead of integers")
	flag.Parse()
	// Setup the logger
	if *pretty {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
	if !*unixTime {
		zerolog.TimeFieldFormat = time.RFC3339Nano
	}
	zerolog.DurationFieldUnit = time.Millisecond
	l := log.With().
		Str("loglevel", *level).
		Str("bind", *bind).
		Str("antivirus", *antivirusURL).
		Str("certfile", *certFile).
		Str("keyfile", *keyFile).
		Bool("pretty", *pretty).
		Str("usersfile", *usersFile).
		Bool("unixtime", *unixTime).
		Bool("floatdur", *floatDurations).
		Logger()
	loglevel, err := zerolog.ParseLevel(*level)
	if err != nil {
		l.Fatal().Err(err).Msg("loglevel must be one of debug, info, warn, error, fatal, panic")
	}
	zerolog.SetGlobalLevel(loglevel)
	zerolog.DurationFieldInteger = !*floatDurations
	// Get the auth list
	f, err := ioutil.ReadFile(*usersFile)
	if err != nil && !os.IsNotExist(err) {
		l.Fatal().Err(err).Msg("could not load users file")
	}
	users := make(map[string]string)
	err = yaml.Unmarshal(f, users)
	if err != nil {
		l.Fatal().Err(err).Msg("failed reading user list")
	}
	// Setup the router
	proxy := &chowder.Proxy{AntiVirus: chowder.NewClamAV(*antivirusURL)}
	r := httprouter.New()
	r.POST("/scan", proxy.Scan)
	r.GET("/healthz", proxy.Ok)
	r.GET("/metrics", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) { promhttp.Handler().ServeHTTP(w, r) })
	api := chowder.LogRequests(log.With().Logger(), chowder.HeaderAuth(users, r))
	l.Fatal().Err(listenAndServe(l, *bind, *certFile, *keyFile, api)).Msg("closed")
}

// listenAndServe checks if either cert or keyfile exists, and if either does, serves HTTPS
func listenAndServe(l zerolog.Logger, addr, certFile, keyFile string, handler http.Handler) error {
	_, errCert := os.Stat(certFile)
	_, errKey := os.Stat(keyFile)
	if errCert == nil || errKey == nil {
		l.Info().Msg("starting server")
		return http.ListenAndServeTLS(addr, certFile, keyFile, handler)
	}
	l.Warn().Msg("no tls credentials found, starting server without tls")
	return http.ListenAndServe(addr, handler)
}
