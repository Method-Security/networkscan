package portscan

import (
	"context"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

type PortsReport struct {
	Port     int    `json:"port" yaml:"port"`
	Protocol string `json:"protocol" yaml:"protocol"`
}

type HostReport struct {
	Host  string        `json:"host" yaml:"host"`
	IP    string        `json:"ip" yaml:"ip"`
	Ports []PortsReport `json:"ports" yaml:"ports"`
}

type Report struct {
	Hosts  []HostReport `json:"hosts" yaml:"hosts"`
	Errors []string     `json:"errors" yaml:"errors"`
}

func getPortScan(ctx context.Context, target string, ports string, topports string) ([]HostReport, error) {
	output := result.HostResult{}
	hostReports := []HostReport{}
	portscanOpts := &runner.Options{
		Threads:           10,
		Timeout:           runner.DefaultPortTimeoutSynScan,
		Host:              goflags.StringSlice{target},
		SkipHostDiscovery: true,
		OnResult: func(hr *result.HostResult) {
			output = *hr
			hostReports = append(hostReports, parseResult(output))
		},
	}
	if ports != "" {
		portscanOpts.Ports = ports
	}
	if topports != "" {
		portscanOpts.TopPorts = topports
	}

	portscan, err := runner.NewRunner(portscanOpts)
	if err != nil {
		return hostReports, err
	}

	defer portscan.Close()
	err = portscan.RunEnumeration(ctx)
	if err != nil {
		return hostReports, err
	}

	return hostReports, nil

}

func parseResult(result result.HostResult) HostReport {
	ports := []PortsReport{}
	for _, port := range result.Ports {
		ports = append(ports, PortsReport{
			Port:     port.Port,
			Protocol: port.Protocol.String(),
		})
	}
	return HostReport{
		Host:  result.Host,
		IP:    result.IP,
		Ports: ports,
	}
}

func RunPortscan(ctx context.Context, target string, ports string, topport string) (Report, error) {
	errors := []string{}

	portscanResult, err := getPortScan(ctx, target, ports, topport)
	if err != nil {
		errors = append(errors, err.Error())
	}

	return Report{
		Hosts:  portscanResult,
		Errors: errors,
	}, nil
}
