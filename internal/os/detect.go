// Package os provides the data structures and logic necessary for interacting with operating systems on a network.
package os

import (
	"context"
	"fmt"

	"github.com/Ullaakut/nmap/v3"
)

// Report represents the final output of a hostdiscover scan, including all hosts that were scanned.
// It includes all of the hosts that were scanned alongside any non-fatal errors that were encountered during the scan.
type Report struct {
	Run    nmap.Run `json:"run" yaml:"run"`
	Errors []string `json:"errors" yaml:"errors"`
}

func getOSDetect(ctx context.Context, target string) (nmap.Run, error) {
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithOSDetection(),
	)
	if err != nil {
		return nmap.Run{}, err
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		fmt.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		return nmap.Run{}, err
	}

	return *result, nil

}

// RunOSDetect takes a target host and returns a report of all hosts and OS that were detected
func RunOSDetect(ctx context.Context, target string) (Report, error) {
	errors := []string{}

	osDetectResult, err := getOSDetect(ctx, target)
	if err != nil {
		errors = append(errors, err.Error())
	}

	return Report{
		Run:    osDetectResult,
		Errors: errors,
	}, nil
}
