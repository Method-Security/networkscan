package cmd

import (
	"errors"
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
				a.OutputSignal.AddError(errors.New("os detect can only be run as a privileged user"))
				return
			}

			// Check if nmap is installed and in the system path
			_, err := exec.LookPath("nmap")
			if err != nil {
				a.OutputSignal.AddError(errors.New("nmap is not installed or is not in the system path"))
				return
			}

			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if target == "" {
				a.OutputSignal.AddError(errors.New("target is required"))
				return
			}
			report, err := os.RunOSDetect(cmd.Context(), target)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	osDetectCmd.Flags().String("target", "", "Target IP or FQDN to detect")
	_ = osDetectCmd.MarkFlagRequired("target")

	osCmd.AddCommand(osDetectCmd)
	a.RootCmd.AddCommand(osCmd)
}
