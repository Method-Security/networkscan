package cmd

import (
	"github.com/Method-Security/networkscan/internal/hostdiscover"
	"github.com/spf13/cobra"
)

// InitHostDiscoverCommand initializes the hostscan command for the networkscan CLI. This function sets up the hostdiscover command
// for the CLI. It also sets up the flags for the hostdiscover command, such as the target and scantype.
func (a *NetworkScan) InitHostDiscoverCommand() {
	hostDiscoverCmd := &cobra.Command{
		Use:   "hostdiscover",
		Short: "Discover hosts on the network",
		Long:  `Discover hosts on the network`,
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
			scantype, err := cmd.Flags().GetString("scantype")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report, err := hostdiscover.RunHostDiscover(cmd.Context(), target, scantype)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			a.OutputSignal.Content = report
		},
	}

	hostDiscoverCmd.Flags().String("target", "", "Target IP, host, or CIDR to scan for hosts")
	hostDiscoverCmd.Flags().String("scantype", "icmpecho", "Scan type for host discovery (tcpsyn | tcpack | icmpecho | icmptimestamp | arp | icmpaddressmask)")
	a.RootCmd.AddCommand(hostDiscoverCmd)
}
