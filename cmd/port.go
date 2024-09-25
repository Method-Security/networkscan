package cmd

import (
	"errors"

	"github.com/Method-Security/networkscan/internal/port"
	"github.com/spf13/cobra"
)

// InitPortCommand initializes the port command for the networkscan CLI. It also sets up the flags for the port
// command and its subcommands.
func (a *NetworkScan) InitPortCommand() {
	portCmd := &cobra.Command{
		Use:   "port",
		Short: "Scan and interact with ports on a network",
		Long:  "Scan and interact with ports on a network",
	}

	portScanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan for open ports on a target host",
		Long:  `Scan for open ports on a target host`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if target == "" {
				a.OutputSignal.AddError(errors.New("target is required"))
				return
			}
			ports, err := cmd.Flags().GetString("ports")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			topport, err := cmd.Flags().GetString("topports")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			report, err := port.RunPortScan(cmd.Context(), target, ports, topport)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	portScanCmd.Flags().String("target", "", "Target IP or FQDN to scan for ports")
	portScanCmd.Flags().String("ports", "", "Port/Port Range to scan")
	portScanCmd.Flags().String("topports", "", "Top Ports to scan (full | 100 |1000)")
	_ = portScanCmd.MarkFlagRequired("target")

	portCmd.AddCommand(portScanCmd)
	a.RootCmd.AddCommand(portCmd)
}
