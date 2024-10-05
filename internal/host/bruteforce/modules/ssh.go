package host

import (
	"fmt"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/bruteforce"
	"golang.org/x/crypto/ssh"
)

type SSHLibrary struct{}

func (SSHLib *SSHLibrary) StandardPorts() []int {
	return []int{22, 2222}
}

func (SSHLib *SSHLibrary) BruteForce(host string, port int, credPair *bruteforce.CredentialPair, config *bruteforce.BruteForceRunConfig) (*bruteforce.AttemptInfo, []string) {
	attempt := bruteforce.AttemptInfo{}
	errors := []string{}

	username, password := "", ""
	if credPair != nil {
		username, password = credPair.Username, credPair.Password

	}

	sshConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(config.Timeout) * time.Second,
	}

	targetAddr := fmt.Sprintf("%s:%d", host, port)
	requestTimeStamp := time.Now()
	conn, err := ssh.Dial("tcp", targetAddr, sshConfig)
	responseTimeStamp := time.Now()

	var message string
	if err != nil {
		message = err.Error()
	} else {
		if credPair == nil {
			message = fmt.Sprintf("SUCCESSFUL: SSH for %s with no authentication", targetAddr)
		} else {
			message = fmt.Sprintf("SUCCESSFUL: SSH for %s with username: %s and password: %s", targetAddr, username, password)
		}
		err := conn.Close()
		if err != nil {
			errors = append(errors, err.Error())
		}
	}

	request := bruteforce.GeneralRequestInfo{
		Username:  username,
		Password:  password,
		Host:      host,
		Port:      port,
		Timestamp: requestTimeStamp,
	}
	response := bruteforce.GeneralResponseInfo{
		Message:   message,
		Timestamp: responseTimeStamp,
	}
	attempt.Request = &bruteforce.RequestUnion{GeneralRequestInfo: &request}
	attempt.Response = &bruteforce.ResponseUnion{GeneralResponseInfo: &response}
	attempt.Result = SSHLib.AnalyzeResponse(attempt.Response)
	return &attempt, errors
}

func (SSHLib *SSHLibrary) AnalyzeResponse(response *bruteforce.ResponseUnion) *bruteforce.ResultInfo {
	result := bruteforce.ResultInfo{Login: false, Ratelimit: false}
	if strings.Contains(response.GeneralResponseInfo.Message, "SUCCESSFUL") {
		result.Login = true
	}
	// TODO: result.Ratelimit = true
	return &result
}
