# networkscan

networkscan provides a number of granular network enumeration capabilities that can be leveraged by security teams to gain better visibility into both on-prem and cloud environments.

## Development

networkscan leverages Palantir's [godel](https://github.com/palantir/godel) build tool to provide streamlined Go build infrastructure. After cloning this repository, you can run `./godelw build` to build the project from source.

### Adding a new Enumeration Capability

#### New Resource Type

If you are adding a new network resource type to networkscan, you should add it as a new top level command that will get nested under the networkscan root command. To do this, you will do the following:

1. Add a file to `cmd/` that corresponds to the sub-command name you'd like to add to the `networkscan` CLI
2. You can use `cmd/ec2.go` as a template
3. Your file needs to be a member function of the `networkscan` struct and should be of the form `Init<cmd>Command`
4. Add a new member to the `networkscan` struct in `cmd/root.go` that corresponds to your command name.
5. Call your `Init` function from `main.go`
6. Add logic to your commands runtime and put it in its own package within `internal` (e.g., `internal/ec2`)

## Testing

### Testing from Source (pre-build)

You can test locally without building by running

```bash
go run main.go <subcommand> <flags>
```

### Testing the CLI (post-build)

You can test locally using the CLI by building it from source. Run, `./godelw clean && ./godelw build` to clean out the `out/` directory and rebuild. You will now have a binary at `out/build/networkscan/<version>/<architecture>/networkscan` that you can run

The majority of networkscan commands will require authentication with an AWS account, so you will need to have the appropriate [AWS Credentials exported as environment variables](https://docs.aws.amazon.com/cli/v1/userguide/cli-configure-envvars.html).
