package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	networkscan "github.com/Method-Security/networkscan/generated/go"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
)

// RunHostBannerGrab performs a banner grab on the specified target
func RunHostBannerGrab(ctx context.Context, timeout int, target string) (*networkscan.BannerGrabReport, error) {
	resources := networkscan.BannerGrabReport{Target: target}
	errs := []string{}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return &resources, err
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return &resources, err
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return &resources, err
	}

	if len(ips) == 0 {
		return &resources, errors.New("no IP addresses found for host")
	}

	ip := ips[0]
	fxConfig := scan.Config{
		FastMode:       false,
		DefaultTimeout: time.Duration(timeout) * time.Second,
		UDP:            false,
		Verbose:        false,
	}
	ipAddr, err := netip.ParseAddr(ip.String())
	if err != nil {
		return &resources, err
	}
	fxTarget := plugins.Target{
		Address: netip.AddrPortFrom(ipAddr, uint16(port)),
		Host:    host,
	}
	targets := []plugins.Target{fxTarget}

	results, err := scan.ScanTargets(targets, fxConfig)
	if err != nil {
		return &resources, err
	}

	var bannerResults []*networkscan.BannerGrab
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

		// Marshal Metadata into variables
		transportTypeEnum, err := networkscan.NewTransportTypeFromString(strings.ToUpper(result.Transport))
		if err != nil {
			transportTypeEnum, _ = networkscan.NewTransportTypeFromString("UNKNOWN")
		}

		serviceTypeEnum, err := networkscan.NewServiceTypeFromString(strings.ToUpper(result.Protocol))
		if err != nil {
			serviceTypeEnum, _ = networkscan.NewServiceTypeFromString("UNKNOWN")
		}

		var statusCode *string
		if val, ok := metadata["StatusCode"]; ok {
			statusCode = &val
		}

		var technogliesList *[]string
		if val, ok := metadata["Technologies"]; ok {
			techs := strings.Split(strings.Trim(val, "[]"), ",")
			technogliesList = &techs
		}

		var connection *string
		var contentType *string
		sameSiteString := ""
		if val, ok := metadata["ResponseHeaders"]; ok {
			responseHeadersMap := unmarshalMapString(val)

			if connectionData, ok := responseHeadersMap["Connection"]; ok {
				connection = &connectionData
			}

			if contentTypeData, ok := responseHeadersMap["Content-Type"]; ok {
				contentType = &contentTypeData
			}

			if cookieData, ok := responseHeadersMap["Set-Cookie"]; ok {
				if strings.Contains(cookieData, "SameSite=") {
					startIndex := strings.Index(cookieData, "SameSite=")
					sameSiteValueSub := cookieData[startIndex+len("SameSite="):]
					sameSiteString = strings.Split(sameSiteValueSub, ";")[0]
				}
			}
		}

		sameSiteTypeEnum, err := networkscan.NewSameSiteTypeFromString(strings.ToUpper(sameSiteString))
		if err != nil {
			sameSiteTypeEnum, _ = networkscan.NewSameSiteTypeFromString("UNKNOWN")
		}

		bannerResult := networkscan.BannerGrab{
			Host:         result.Host,
			Ip:           result.IP,
			Port:         result.Port,
			StatusCode:   statusCode,
			Tls:          result.TLS,
			Transport:    transportTypeEnum,
			Service:      serviceTypeEnum,
			Version:      result.Version,
			Connection:   connection,
			ContentType:  contentType,
			SameSite:     &sameSiteTypeEnum,
			Technologies: *technogliesList,
			Metadata:     metadata,
		}

		bannerResults = append(bannerResults, &bannerResult)
	}

	resources.BannerGrabs = bannerResults
	resources.Errors = errs
	return &resources, nil
}

// Function to unmarshal a string that has the structure of a Map
func unmarshalMapString(headerStr string) map[string]string {
	data := make(map[string]string)

	re := regexp.MustCompile(`(\w[\w-]*):(\[.*?\]|\S+)`)
	matches := re.FindAllStringSubmatch(headerStr, -1)

	for _, match := range matches {
		key := match[1]
		value := strings.Trim(match[2], "[]")
		data[key] = value
	}

	return data
}
