# Chowder
[![Build Status](https://travis-ci.org/lachlanmunro/chowder.svg?branch=master)](https://travis-ci.org/lachlanmunro/chowder)

Chowder is a REST API for ClamAV written in Go.
* HTTPS
* JSON logs
* Prometheus metrics

## Current state
All the API endpoints are hand tested, no unit or integration CI yet. Probably needs a tomb on the response goroutine. Missing a panic handler so you might get some text where you should be getting JSON (from the router). Not benchmarked or optimised further than by eyeball. Beta means beta.

## Key Points
* Needs a backing clamd setup with a tcp socket.
* Auth using an `Authorize` header if you supply a users.yml (a yaml dict of `token: username`).
* HTTPS if either of the supplied `certfile` or `keyfile` resolve to a file.
* POST /scan performs an instream scan using the post body (will correctly chunk for instream, just send your files as straight binary in the body).
* GET /healthz performs a health check and calls ping on the underlying antivirus.
* GET /metrics returns prometheus metrics.
* Quirks of Go mean you need to set false flags like `-pretty=false` (ie if you want JSON logs).
* Should get one line of log entry per request so long as loglevel is info or above.