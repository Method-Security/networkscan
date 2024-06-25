package cmd

import (
	"os/exec"

	"github.com/Method-Security/networkscan/internal/os"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/spf13/cobra"
)

// InitOSCommand initializes the os command for the networkscan CLI. It also sets up the flags for the port
// command and its subcommands.
func (a *NetworkScan) InitOSCommand() {
	osCmd := &cobra.Command{
		Use:   "os",
		Short: "Scan and interact operating systems on a network host",
		Long:  "Scan and interact operating systems on a network host",
	}

	osDetectCmd := &cobra.Command{
		Use:   "detect",
		Short: "Detect the operating system on a target host",
		Long:  `Detect the operating system on a target host`,
		Run: func(cmd *cobra.Command, args []string) {
			// osdetect can only be run as a sudoer or privileged user
			if !privileges.IsPrivileged {
				errorMessage := "os detect can only be run as a privileged user"
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			// Check if nmap is installed and in the system path
			_, err := exec.LookPath("nmap")
			if err != nil {
				errorMessage := "nmap is not installed or is not in the system path"
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			target, err := cmd.Flags().GetString("target")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			if target == "" {
				errorMessage := "target is required"
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report, err := os.RunOSDetect(cmd.Context(), target)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			a.OutputSignal.Content = report
		},
	}

	osDetectCmd.Flags().String("target", "", "Target IP or FQDN to detect")

	osCmd.AddCommand(osDetectCmd)
	a.RootCmd.AddCommand(osCmd)
}
