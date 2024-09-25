# Address

The `networkscan address bannergrab` grabs and analyzes the banner on a socket network address.

## Usage

To grab the banner from a network address
```bash
networkscan address bannergrab --target scanme.sh --port 22
```

## Help

```bash
networkscan address bannergrab -h

Grab banner from a network address

Usage:
  networkscan address bannergrab [flags]

Flags:
  -h, --help            help for bannergrab
      --port uint16     Address Port (e.g., 443)
      --target string   Target address (e.g., 192.168.1.1 or example.com)
      --timeout int     Timeout limit for each handshake in seconds (default 5)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
