package address

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"time"

	networkscan "github.com/Method-Security/networkscan/generated/go"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
)

// RunBannerGrab performs a banner grab on the specified target
func RunBannerGrab(ctx context.Context, timeout int, target string, port uint16) (*networkscan.BannerGrabReport, error) {
	resources := networkscan.BannerGrabReport{Target: target}
	errors := []string{}

	fxConfig := scan.Config{
		FastMode:       false,
		DefaultTimeout: time.Duration(timeout) * time.Second,
		UDP:            false,
		Verbose:        true,
	}

	ips, err := getIPs(target)
	if err != nil {
		return &resources, err
	}
	fmt.Println(ips)

	var bannerResults []*networkscan.BannerGrab
	for _, ip := range ips {
		ipAddr, err := netip.ParseAddr(ip.String())
		if err != nil {
			return &resources, err
		}

		fxTarget := plugins.Target{
			Address: netip.AddrPortFrom(ipAddr, port),
			Host:    target,
		}
		fmt.Println(fxTarget)

		result, err := fxConfig.SimpleScanTarget(fxTarget)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		metadata := metadataMap(result.Metadata())
		bannerResult := networkscan.BannerGrab{
			Host:        result.Host,
			Ip:          result.IP,
			Port:        result.Port,
			Tls:         result.TLS,
			Version:     result.Version,
			Transport:   getTransportTypeEnum(result.Transport),
			Protocol:    getProtocolTypeEnum(result.Protocol),
			StatusCode:  getStatusCode(metadata),
			Connection:  getConnectionBanner(metadata),
			ContentType: getContentTypeBanner(metadata),
			SameSite:    getSamesiteEnum(metadata),
			Metadata:    metadata,
		}
		bannerResults = append(bannerResults, &bannerResult)
	}

	resources.BannerGrabs = bannerResults
	resources.Errors = errors
	return &resources, nil
}

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

func metadataMap(resultMetadata plugins.Metadata) map[string]string {
	metadata := make(map[string]string)
	v := reflect.ValueOf(resultMetadata)
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)
		metadata[field.Name] = fmt.Sprintf("%v", value.Interface())
	}
	return metadata
}

func getIPs(target string) ([]net.IP, error) {
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no IP addresses found for host")
	}
	return ips, nil
}

func getTransportTypeEnum(transport string) networkscan.TransportType {
	transportTypeEnum, err := networkscan.NewTransportTypeFromString(strings.ToUpper(transport))
	if err != nil {
		transportTypeEnum, _ = networkscan.NewTransportTypeFromString("UNKNOWN")
	}
	return transportTypeEnum
}

func getProtocolTypeEnum(protocol string) networkscan.ProtocolType {
	serviceTypeEnum, err := networkscan.NewProtocolTypeFromString(strings.ToUpper(protocol))
	if err != nil {
		serviceTypeEnum, _ = networkscan.NewProtocolTypeFromString("UNKNOWN")
	}
	return serviceTypeEnum
}

func getStatusCode(metadata map[string]string) *string {
	if val, ok := metadata["StatusCode"]; ok {
		return &val
	}
	return nil
}

func getConnectionBanner(metadata map[string]string) *string {
	if val, ok := metadata["ResponseHeaders"]; ok {
		if connectionData, ok := unmarshalMapString(val)["Connection"]; ok {
			return &connectionData
		}
	}
	return nil
}

func getContentTypeBanner(metadata map[string]string) *string {
	if val, ok := metadata["ResponseHeaders"]; ok {
		if connectionData, ok := unmarshalMapString(val)["Content-Type"]; ok {
			return &connectionData
		}
	}
	return nil
}

func getSamesiteEnum(metadata map[string]string) *networkscan.SameSiteType {
	val, ok := metadata["ResponseHeaders"]
	if !ok {
		return nil
	}

	responseHeadersMap := unmarshalMapString(val)
	cookieData, ok := responseHeadersMap["Set-Cookie"]
	if !ok || !strings.Contains(cookieData, "SameSite=") {
		sameSiteTypeEnum, _ := networkscan.NewSameSiteTypeFromString("UNKNOWN")
		return &sameSiteTypeEnum
	}

	startIndex := strings.Index(cookieData, "SameSite=")
	sameSiteValueSub := cookieData[startIndex+len("SameSite="):]
	sameSiteString := strings.Split(sameSiteValueSub, ";")[0]

	sameSiteTypeEnum, err := networkscan.NewSameSiteTypeFromString(strings.ToUpper(sameSiteString))
	if err != nil {
		sameSiteTypeEnum, _ = networkscan.NewSameSiteTypeFromString("UNKNOWN")
	}

	return &sameSiteTypeEnum
}