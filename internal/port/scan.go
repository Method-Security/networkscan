// Package port provides the data structures and logic necessary for interacting with ports on a network.
package port

import (
	"context"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// Details represents a singular instance of a port that was scanned and found to be open on a target host.
type Details struct {
	Port     int    `json:"port" yaml:"port"`
	Protocol string `json:"protocol" yaml:"protocol"`
}

// Host represents a singular instance of a host that was scanned and found to have open ports.
type Host struct {
	Host  string    `json:"host" yaml:"host"`
	IP    string    `json:"ip" yaml:"ip"`
	Ports []Details `json:"ports" yaml:"ports"`
}

// Report represents the final output of a port scan, including all hosts that were scanned and their open ports.
// It includes all of the hosts that were scanned alongside any non-fatal errors that were encountered during the scan.
type Report struct {
	Hosts  []Host   `json:"hosts" yaml:"hosts"`
	Errors []string `json:"errors" yaml:"errors"`
}

func getPortScan(ctx context.Context, target string, ports string, topports string, scantype string) ([]Host, error) {
	output := result.HostResult{}
	hosts := []Host{}
	// These settings mimic naabu's default settings
	portscanOpts := &runner.Options{
		Silent:            false,
		JSON:              true,
		NoColor:           true,
		Rate:              runner.DefaultRateConnectScan,
		Retries:           runner.DefaultRetriesConnectScan,
		Threads:           25,
		Timeout:           runner.DefaultPortTimeoutConnectScan,
		Host:              goflags.StringSlice{target},
		SkipHostDiscovery: true,
		WarmUpTime:        2,
		InputReadTimeout:  180000000000, // This is their default
		OnResult: func(hr *result.HostResult) {
			output = *hr
			hosts = append(hosts, parseResult(output))
		},
	}

	switch scantype {
	case "syn":
		portscanOpts.ScanType = runner.SynScan
	case "connect":
		portscanOpts.ScanType = runner.ConnectScan
	default:
		portscanOpts.ScanType = ""
	}

	if ports != "" {
		portscanOpts.Ports = ports
	}
	if topports != "" {
		portscanOpts.TopPorts = topports
	}

	portscan, err := runner.NewRunner(portscanOpts)
	if err != nil {
		return hosts, err
	}

	defer portscan.Close()
	err = portscan.RunEnumeration(ctx)
	if err != nil {
		return hosts, err
	}

	return hosts, nil

}

func parseResult(result result.HostResult) Host {
	ports := []Details{}
	for _, port := range result.Ports {
		ports = append(ports, Details{
			Port:     port.Port,
			Protocol: port.Protocol.String(),
		})
	}
	return Host{
		Host:  result.Host,
		IP:    result.IP,
		Ports: ports,
	}
}

// RunPortScan takes a target host and a list of ports to scan and returns a report of all hosts that were scanned and
// their open ports.
func RunPortScan(ctx context.Context, target string, ports string, topport string, scantype string) (Report, error) {
	errors := []string{}

	portscanResult, err := getPortScan(ctx, target, ports, topport, scantype)
	if err != nil {
		errors = append(errors, err.Error())
	}

	return Report{
		Hosts:  portscanResult,
		Errors: errors,
	}, nil
}
