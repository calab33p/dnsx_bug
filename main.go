package main

import (
	"os"

	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	retryabledns "github.com/projectdiscovery/retryabledns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type result struct {
	domain string
	cname  string
}

func main() {
	maxRetries := 5
	domains := []string{"timeout.example.com", "example.org", "example.com"}
	var results []result

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	dnsopts := dnsx.DefaultOptions
	dnsopts.QuestionTypes = []uint16{miekgdns.TypeCNAME}
	dnsopts.MaxRetries = maxRetries
	dnsopts.Hostsfile = false
	dnsopts.BaseResolvers = []string{"8.8.8.8", "127.0.0.1"}
	//dnsopts.BaseResolvers = []string{"127.0.0.1"}

	log.Trace().Msgf("Creating CNAME Resolver with options: %v", dnsopts)

	// Create DNS Resolver with specified options
	dnsClient, err := dnsx.New(dnsopts)
	if err != nil {
		log.Fatal().Msgf("Error initializing CNAME resolver: %v\n", err)
	}

	for _, dom := range domains {

		// retry loop in case of i/o timeout
		i := 0
		var resp *retryabledns.DNSData

		for i = 0; i < maxRetries; i++ {
			// DNS CNAME question and returns corresponding canonical names
			r, err := dnsClient.QueryOne(dom)
			if err != nil {
				log.Warn().Err(err).Msg("Error in DNS Query")
			} else {
				resp = r
				break
			}
		}
		if i == maxRetries {
			log.Error().Msg("Max retries exceeded!")
			continue
		}

		if len(resp.CNAME) == 0 {
			log.Trace().Msgf("   Skipping subdomain %s with no CNAME...", dom)
		} else if len(resp.CNAME) == 1 {
			results = append(results, result{domain: dom, cname: resp.CNAME[0]})
		} else {
			log.Error().Msgf("Unexpected CNAME size")
		}
	}

	for _, res := range results {
		log.Info().Str("domain", res.domain).Str("cname", res.cname).Msg("Results")
	}
}
