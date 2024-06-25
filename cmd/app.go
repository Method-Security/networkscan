package cmd

import (
	"os/exec"
	//"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/Method-Security/networkscan/internal/app"
	"github.com/spf13/cobra"
)

// InitAppCommand initializes the app command for the networkscan CLI. It also sets up the flags for the port
// command and its subcommands.
func (a *NetworkScan) InitAppCommand() {
	appCmd := &cobra.Command{
		Use:   "app",
		Short: "Scan and interact apps and services on a network host",
		Long:  "Scan and interact apps and services on a network host",
	}

	appDetectCmd := &cobra.Command{
		Use:   "detect",
		Short: "Detect the apps and services on a target host",
		Long:  `Detect the apps and services on a target host`,
		Run: func(cmd *cobra.Command, args []string) {
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
			ports, err := cmd.Flags().GetString("ports")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report, err := app.RunAppDetect(cmd.Context(), target, ports)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			a.OutputSignal.Content = report
		},
	}

	appDetectCmd.Flags().String("target", "", "Target IP or FQDN to detect apps and services")
	appDetectCmd.Flags().String("ports", "", "Port/Port Range to scan for apps and services")

	appCmd.AddCommand(appDetectCmd)
	a.RootCmd.AddCommand(appCmd)
}
