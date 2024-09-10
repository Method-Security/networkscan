package host

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
)

// BannerGrabResult represents the result of a banner grab operation
type BannerGrabResult struct {
	Host      string            `json:"host"`
	IP        string            `json:"ip"`
	Port      uint16            `json:"port"`
	Transport string            `json:"transport"`
	Protocol  string            `json:"protocol"`
	Metadata  map[string]string `json:"metadata"`
}

// BannerGrabReport represents the final output of a banner grab scan
type BannerGrabReport struct {
	Results []BannerGrabResult `json:"results"`
	Errors  []string           `json:"errors"`
}

// RunHostBannerGrab performs a banner grab on the specified target
func RunHostBannerGrab(ctx context.Context, target string) (BannerGrabReport, error) {
	report := BannerGrabReport{
		Results: []BannerGrabResult{},
		Errors:  []string{},
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Invalid target format: %v", err))
		return report, nil
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Invalid port number: %v", err))
		return report, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to resolve host: %v", err))
		return report, nil
	}
	if len(ips) == 0 {
		report.Errors = append(report.Errors, "No IP addresses found for host")
		return report, nil
	}
	ip := ips[0]

	fxConfig := scan.Config{
		DefaultTimeout: 2 * time.Second,
		FastMode:       false,
		Verbose:        false,
		UDP:            false,
	}

	ipAddr, err := netip.ParseAddr(ip.String())
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Failed to parse IP address: %v", err))
		return report, nil
	}
	fxTarget := plugins.Target{
		Address: netip.AddrPortFrom(ipAddr, uint16(port)),
		Host:    host,
	}
	targets := []plugins.Target{fxTarget}

	results, err := scan.ScanTargets(targets, fxConfig)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report, nil
	}

	for _, result := range results {
		metadata := make(map[string]string)
		resultMetadata := result.Metadata()

		v := reflect.ValueOf(resultMetadata)
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := t.Field(i)
			value := v.Field(i)
			metadata[field.Name] = fmt.Sprintf("%v", value.Interface())
		}

		bannerResult := BannerGrabResult{
			Host:      result.Host,
			IP:        result.IP,
			Port:      uint16(result.Port),
			Transport: result.Transport,
			Protocol:  result.Protocol,
			Metadata:  metadata,
		}
		report.Results = append(report.Results, bannerResult)
	}

	return report, nil
}
