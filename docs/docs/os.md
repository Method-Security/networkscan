# OS

The `networkscan os detect` command detects OS across network hosts. Under the hood it leverages `nmap`.

## Usage

To scan for ports on a target host (this must be run as a privileged user):
```bash
networkscan os detect --target 192.168.1.1
```

## Help

```bash
networkscan os detect -h

Detect the operating system on a target host

Usage:
  networkscan os detect [flags]

Flags:
  -h, --help            help for detect
      --target string   Target IP or FQDN to detect

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
