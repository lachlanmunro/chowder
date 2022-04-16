[![Go Report Card](https://goreportcard.com/badge/github.com/lachlanmunro/chowder)](https://goreportcard.com/report/github.com/lachlanmunro/chowder)
# Chowder

Chowder is a HTTP Proxy for the ClamAV antivirus. It has run providing ClanAV scans for live services in house for years.

It assumes you want to run ClamAV to scan things but you also want (perhaps because you want to loadbalance/provision into a service mesh/K8S):
* POST /scan passing the entire body as a binary stream to the backing ClanAV (transparently converting format).
* GET /metrics Prometheus endpoint with throughput, scan outcome, durations etc.
* GET /healthz endpoints for load balancing.
* HTTPS if either of the supplied `certfile` or `keyfile` resolve to a file.
* Logs (preferably JSON) for all scan requests with the outcomes clearly logged.
* Auth (arbitary token) using an `Authorization` header if you supply a `users.yml` (a yaml dict of `token: username`).
* Minimal overhead in RAM/CPU/Latency.

## Deployment
* Setup a backing `clamd` with a tcp socket (presumably over localhost/pod container neighbour).
* Clone this repository, install go
* Run `go build` at the root of the cloned repository
* Run the chowder binary (with `--help` for config flags)
