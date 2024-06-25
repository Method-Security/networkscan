# App

The `networkscan app detect` command provide information about apps and services that are running on a network host. Under the hood it leverages `nmap`.

## Usage

To scan for apps and services on a target host:
```bash
networkscan app detect --target 192.168.1.1
```

## Help

```bash
networkscan app detect -h

Detect the apps and services on a target host

Usage:
  networkscan app detect [flags]

Flags:
  -h, --help            help for detect
      --ports string    Port/Port Range to scan for apps and services
      --target string   Target IP or FQDN to detect apps and services

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
