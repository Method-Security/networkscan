package cmd

import (
	"github.com/Method-Security/networkscan/internal/host"
	"github.com/projectdiscovery/naabu/v2/pkg/privileges"
	"github.com/spf13/cobra"
)

// InitHostCommand initializes the host command for the networkscan CLI. It also sets up the flags for
// the host command and its subcommands.
func (a *NetworkScan) InitHostCommand() {
	hostCmd := &cobra.Command{
		Use:   "host",
		Short: "Discover and interact with hosts on a network",
		Long:  `Discover and interact with hosts on a network`,
	}

	hostDiscoverCmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover hosts on a network",
		Long:  `Discover hosts on a network`,
		Run: func(cmd *cobra.Command, args []string) {
			// hostdiscover can only be run as a sudoer or privileged user
			if !privileges.IsPrivileged {
				errorMessage := "host discover can only be run as a privileged user"
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
			scantype, err := cmd.Flags().GetString("scantype")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report, err := host.RunHostDiscover(cmd.Context(), target, scantype)
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
	hostDiscoverCmd.Flags().String("scantype", "", "Scan type for host discovery (tcpsyn | tcpack | icmpecho | icmptimestamp | arp | icmpaddressmask)")
	_ = hostDiscoverCmd.MarkFlagRequired("target")
	hostCmd.AddCommand(hostDiscoverCmd)
	a.RootCmd.AddCommand(hostCmd)
}
