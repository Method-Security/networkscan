package cmd

import (
	"errors"

	bruteforcefern "github.com/Method-Security/networkscan/generated/go/bruteforce"
	"github.com/Method-Security/networkscan/internal/address"
	bruteforce "github.com/Method-Security/networkscan/internal/address/bruteforce"
	"github.com/Method-Security/networkscan/utils"
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
				a.OutputSignal.AddError(err)
				return
			}
			port, err := cmd.Flags().GetUint16("port")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			report, err := address.RunBannerGrab(cmd.Context(), timeout, target, port)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	bannerGrabCmd.Flags().String("target", "", "Target address (e.g., 192.168.1.1 or example.com)")
	bannerGrabCmd.Flags().Uint16("port", 0, "Address Port (e.g., 443)")
	bannerGrabCmd.Flags().Int("timeout", 5, "Timeout limit for each handshake in seconds")
	_ = bannerGrabCmd.MarkFlagRequired("target")
	_ = bannerGrabCmd.MarkFlagRequired("port")

	addressCmd.AddCommand(bannerGrabCmd)

	bruteForceCmd := &cobra.Command{
		Use:   "bruteforce",
		Short: "Execute a Bruteforce attack against an application",
		Long:  `Execute a Bruteforce attack against an application`,
		Run: func(cmd *cobra.Command, args []string) {

			// Targets
			targets, err := cmd.Flags().GetStringSlice("targets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Module
			module, err := cmd.Flags().GetString("module")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			moduleEnum, err := bruteforcefern.NewModuleTypeFromString(module)
			if err != nil {
				a.OutputSignal.AddError(errors.New("invalid module"))
				return
			}

			// Usernames
			usernames, err := cmd.Flags().GetStringSlice("usernames")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			usernameFiles, err := cmd.Flags().GetStringSlice("usernamelists")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			usernamesFromFiles, err := utils.GetEntriesFromFiles(usernameFiles)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			allUsernames := append(usernames, usernamesFromFiles...)

			// Passwords
			passwords, err := cmd.Flags().GetStringSlice("passwords")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			passwordFiles, err := cmd.Flags().GetStringSlice("passwordlists")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			passwordsFromFiles, err := utils.GetEntriesFromFiles(passwordFiles)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			allPasswords := append(passwords, passwordsFromFiles...)

			// Attack Configurations
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sleep, err := cmd.Flags().GetInt("sleep")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			retries, err := cmd.Flags().GetInt("retries")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			successfulOnly, err := cmd.Flags().GetBool("successfulonly")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			stopFirstSuccess, err := cmd.Flags().GetBool("stopfirstsuccess")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			bruteForceConfig, err := LoadBruteForceConfig(moduleEnum, targets, allUsernames, allPasswords, timeout, sleep, retries, successfulOnly, stopFirstSuccess)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Generate Report
			report, err := bruteforce.BruteForceAttack(cmd.Context(), bruteForceConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	bruteForceCmd.Flags().StringSlice("targets", []string{}, "Address of target")
	bruteForceCmd.Flags().String("module", "", "Module type (ie.SSH)")
	bruteForceCmd.Flags().StringSlice("usernames", []string{}, "Username to use in attack")
	bruteForceCmd.Flags().StringSlice("passwords", []string{}, "Password to use in attack")
	bruteForceCmd.Flags().StringSlice("usernamelists", []string{}, "File paths containing usernames to use in attack")
	bruteForceCmd.Flags().StringSlice("passwordlists", []string{}, "File paths containing passwords to use in attack")
	bruteForceCmd.Flags().Int("timeout", 3000, "Timeout per request (MilliSeconds)")
	bruteForceCmd.Flags().Int("sleep", 3000, "Sleep time between requests (MilliSeconds)")
	bruteForceCmd.Flags().Int("retries", 2, "Number of Attempts per credential pair")
	bruteForceCmd.Flags().Bool("successfulonly", false, "Only show successful attempts")
	bruteForceCmd.Flags().Bool("stopfirstsuccess", false, "Stop on the first successful login")

	_ = bruteForceCmd.MarkFlagRequired("targets")
	_ = bruteForceCmd.MarkFlagRequired("module")

	addressCmd.AddCommand(bruteForceCmd)

	a.RootCmd.AddCommand(addressCmd)
}

func LoadBruteForceConfig(module bruteforcefern.ModuleType, targets []string, usernames []string, passwords []string, timeout int, sleep int, retries int, successfulOnly bool, stopFirstSuccess bool) (*bruteforcefern.BruteForceRunConfig, error) {
	config := &bruteforcefern.BruteForceRunConfig{
		Module:           module,
		Targets:          targets,
		Usernames:        usernames,
		Passwords:        passwords,
		Timeout:          timeout,
		Sleep:            sleep,
		Retries:          retries,
		SuccessfulOnly:   successfulOnly,
		StopFirstSuccess: stopFirstSuccess,
	}
	if config.Timeout < 1 {
		return nil, errors.New("timeout must be greater than 0")
	}
	if config.Sleep < 0 {
		return nil, errors.New("sleep time cannot be negative")
	}
	if config.Retries < 0 {
		return nil, errors.New("retries cannot be negative")
	}
	return config, nil
}
