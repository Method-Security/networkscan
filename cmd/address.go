package cmd

import (
	"github.com/Method-Security/networkscan/internal/address"
	"github.com/spf13/cobra"
)

// InitAddressCommand initializes the address command for the networkscan CLI. It also sets up the flags for
// the address command and its subcommands.
func (a *NetworkScan) InitAddressCommand() {
	addressCmd := &cobra.Command{
		Use:   "address",
		Short: "Discover and interact with network addresses",
		Long:  `Discover and interact with network addresses`,
	}

	bannerGrabCmd := &cobra.Command{
		Use:   "bannergrab",
		Short: "Grab banner from a network address",
		Long:  `Grab banner from a network address`,
		Run: func(cmd *cobra.Command, args []string) {
			target, err := cmd.Flags().GetString("target")
			if err != nil {
				errorMessage := err.Error()
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
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report, err := address.RunBannerGrab(cmd.Context(), timeout, target, port)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			a.OutputSignal.Content = report
		},
	}

	bannerGrabCmd.Flags().String("target", "", "Target address (e.g., 192.168.1.1 or example.com)")
	bannerGrabCmd.Flags().Uint16("port", 0, "Address Port (e.g., 443)")
	bannerGrabCmd.Flags().Int("timeout", 5, "Timeout limit for each handshake in seconds")
	bannerGrabCmd.MarkFlagRequired("target")
	bannerGrabCmd.MarkFlagRequired("port")

	addressCmd.AddCommand(bannerGrabCmd)
	a.RootCmd.AddCommand(addressCmd)
}
