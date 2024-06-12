# On Hold due to build issues for arm


# Cobra CLI Template

## Bootstrapping a new Template

To use this repo as a template, perform the following steps after cloning.

1. Change the key in the `godel/config/dist-plugin.yml` to be the name of your CLI
2. Change the `CLI_NAME` arg in the `template-docker/Dockerfile` to the name of your CLI and rename `template-docker` to your cli name
3. Within `go.mod` change the top module to be this repo's url
   1. Change it in `main.go` import as well
4. In `root.go` change `gitlab.com/method-security/templates/golang-template/internal/config` to `<this repo url>/internal/config`
5. Within `root.go` change the combra Command to have proper descriptions
6. Within `interna/config/config.go` set the RootFlags struct to the flags you need
7. See below for adding sub-command capability

## Adding a new AWS Enumeration Capability

1. Add a file to `cmd/` that corresponds to the sub-command name you'd like to add to the `awsenumerate` CLI
2. You can use `cmd/ec2.go` as a template
3. Your file needs to be a member function of the `AwsEnumerate` struct and should be of the form `Init<cmd>Command`
4. Add a new member to the `AwsEnumerate` struct in `cmd/root.go` that corresponsds to your command name. Remember, the first letter must be capitalized.
5. Call your `Init` function from `main.go`
6. Add logic to your commands runtime and put it in its own package within `internal` (e.g., `internal/ec2`)

## Testing

### Testing from Source (pre-build)

You can test locally without building by running

```bash
go run main.go <subcommand> <flags>
```

### Testing the CLI (post-build)

You can test locally using the CLI by building it from source. Run, `./godelw clean && ./godelw build` to clean out the `out/` directory and rebuild. You will now have a binary at `out/build/awsenumerate/<version>/darwin-arm64/awsenumerate` that you can run

## Building the Docker Container

I have not yet figured out how to get godel to build docker for us, so at the moment, it's a bit of a pain. The best idea is to follow what the `build-docker` stage in `.gitlab-ci.yml` does
