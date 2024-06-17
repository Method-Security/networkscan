# Portscan

The `networkscan portscan` command provide information about ports that are open across networked devices.

## Usage

```bash
portscan --topports 100 --target scanme.sh
```

## Help Test

```bash
networkscan portscan -h
Scan for open ports

Usage:
  networkscan portscan [flags]

Flags:
  -h, --help              help for portscan
      --ports string      Port/Port Range to scan
      --target string     Target IP to scan on
      --topports string   Top Ports to scan [full,100,1000]

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
