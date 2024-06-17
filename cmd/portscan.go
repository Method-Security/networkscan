package cmd

import (
	"github.com/Method-Security/networkscan/internal/portscan"
	"github.com/spf13/cobra"
)

// InitPortscanCommand initializes the portscan command for the networkscan CLI. This function sets up the portscan command
// for the CLI. It also sets up the flags for the portscan command, such as the target, ports, and topports.
func (a *NetworkScan) InitPortscanCommand() {
	portscanCmd := &cobra.Command{
		Use:   "portscan",
		Short: "Scan for open ports",
		Long:  `Scan for open ports`,
		Run: func(cmd *cobra.Command, args []string) {
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
			topport, err := cmd.Flags().GetString("topports")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report, err := portscan.RunPortscan(cmd.Context(), target, ports, topport)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			a.OutputSignal.Content = report
		},
	}

	portscanCmd.Flags().String("target", "", "Target IP to scan on")
	portscanCmd.Flags().String("ports", "", "Port/Port Range to scan")
	portscanCmd.Flags().String("topports", "", "Top Ports to scan [full,100,1000]")
	a.RootCmd.AddCommand(portscanCmd)
}
