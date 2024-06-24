// Package hostdiscover provides the data structures and logic necessary for conducting host discovery on a network
package hostdiscover

import (
	"context"
	"fmt"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// HostReport represents a singular instance of a host that was scanned
type HostReport struct {
	Host  string        `json:"host" yaml:"host"`
	IP    string        `json:"ip" yaml:"ip"`
}

// Report represents the final output of a hostdiscover scan, including all hosts that were scanned.
// It includes all of the hosts that were scanned alongside any non-fatal errors that were encountered during the scan.
type Report struct {
	Hosts  []HostReport `json:"hosts" yaml:"hosts"`
	Errors []string     `json:"errors" yaml:"errors"`
}

func getHostDiscover(ctx context.Context, target string, scantype string) ([]HostReport, error) {
	output := result.HostResult{}
	hostReports := []HostReport{}
	hostDiscoverOpts := &runner.Options{
		Silent:            true,
		JSON:              true,
		NoColor:           true,
		Retries: 		   3,
		WarmUpTime: 	   2,
		Rate: 			   1000,
		Threads:           25,
		Timeout:           runner.DefaultPortTimeoutSynScan,
		Host:              goflags.StringSlice{target},
		OnlyHostDiscovery: true,
		OnResult: func(hr *result.HostResult) {
			output = *hr
			hostReports = append(hostReports, parseResult(output))
		},
	}

	switch scantype {
	case "tcpsyn":
		hostDiscoverOpts.TcpSynPingProbes = goflags.StringSlice{"80"}
	case "tcpack":
		hostDiscoverOpts.TcpAckPingProbes = goflags.StringSlice{"80"}
	case "icmpecho":
		hostDiscoverOpts.IcmpEchoRequestProbe = true
	case "icmptimestamp":
		hostDiscoverOpts.IcmpTimestampRequestProbe = true
	case "arp":
		hostDiscoverOpts.ArpPing = true
	case "icmpaddressmask":
		hostDiscoverOpts.IcmpAddressMaskRequestProbe = true
	default:
		fmt.Print("Unrecognized scantype")
	}

	hostdiscover, err := runner.NewRunner(hostDiscoverOpts)
	if err != nil {
		return hostReports, err
	}

	defer hostdiscover.Close()
	err = hostdiscover.RunEnumeration(ctx)
	if err != nil {
		return hostReports, err
	}

	return hostReports, nil

}

func parseResult(result result.HostResult) HostReport {
	return HostReport{
		Host:  result.Host,
		IP:    result.IP,
	}
}

// RunHostDiscover takes a target host (which can be a CIDR) and a scantype and returns a report of all hosts that were discovered
func RunHostDiscover(ctx context.Context, target string, scantype string) (Report, error) {
	errors := []string{}

	hostDiscoverResult, err := getHostDiscover(ctx, target, scantype)
	if err != nil {
		errors = append(errors, err.Error())
	}

	return Report{
		Hosts:  hostDiscoverResult,
		Errors: errors,
	}, nil
}
