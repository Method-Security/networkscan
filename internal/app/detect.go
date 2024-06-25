// Package app provides the data structures and logic necessary for interacting with apps and services on a network.
package app

import (
	"context"
	"fmt"

	"github.com/Ullaakut/nmap/v3"
)

// Report represents the final output of a hostdiscover scan, including all hosts that were scanned.
// It includes all of the hosts that were scanned alongside any non-fatal errors that were encountered during the scan.
type Report struct {
	Hosts  []nmap.Host `json:"hosts" yaml:"hosts"`
	Errors []string    `json:"errors" yaml:"errors"`
}

func getAppDetect(ctx context.Context, target string, ports string) ([]nmap.Host, error) {
	hostReports := []nmap.Host{}

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithServiceInfo(),
		nmap.WithFilterPort(func(p nmap.Port) bool {
			return p.State.State == "open"
		}),
	)
	if ports != "" {
		scanner.AddOptions(nmap.WithPorts(ports))
	}

	if err != nil {
		return hostReports, err
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		fmt.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		return hostReports, err
	}

	for _, host := range result.Hosts {
		hostReports = append(hostReports, host)
	}

	return hostReports, nil

}

// RunAppDetect takes a target host and returns a report of all hosts and apps and services that were detected
func RunAppDetect(ctx context.Context, target string, ports string) (Report, error) {
	errors := []string{}

	osDetectResult, err := getAppDetect(ctx, target, ports)
	if err != nil {
		errors = append(errors, err.Error())
	}

	return Report{
		Hosts:  osDetectResult,
		Errors: errors,
	}, nil
}
