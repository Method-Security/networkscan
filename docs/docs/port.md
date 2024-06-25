# Port

The `networkscan port scan` command provide information about ports that are open across networked devices.

## Usage

To scan for ports on a target host:
```bash
networkscan port scan --topports 100 --target scanme.sh
```

## Help

```bash
networkscan port scan -h

Scan for open ports on a target host

Usage:
  networkscan port scan [flags]

Flags:
  -h, --help              help for scan
      --ports string      Port/Port Range to scan
      --target string     Target IP to scan on
      --topports string   Top Ports to scan [full,100,1000]

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
