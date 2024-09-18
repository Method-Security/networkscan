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

	hostCmd.AddCommand(hostDiscoverCmd)
	a.RootCmd.AddCommand(hostCmd)

	hostBannerGrabCmd := &cobra.Command{
		Use:   "bannergrab",
		Short: "Grab banner from a host",
		Long:  `Grab banner from a host using a socket-based address`,
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
			port, err := cmd.Flags().GetUint16("port")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			if port == 0 {
				errorMessage := "port is required"
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report, err := host.RunHostBannerGrab(cmd.Context(), timeout, target, port)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			a.OutputSignal.Content = report
		},
	}

	hostBannerGrabCmd.Flags().String("target", "", "Target address (e.g., 192.168.1.1)")
	hostBannerGrabCmd.Flags().Uint16("port", 0, "Address Port (e.g., 443)")
	hostBannerGrabCmd.Flags().Int("timeout", 30, "Timeout limit in seconds")
	hostCmd.AddCommand(hostBannerGrabCmd)
	a.RootCmd.AddCommand(hostCmd)
}
