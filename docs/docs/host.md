# Host

## Discover

The `networkscan host discover` command discovers active network hosts.

### Usage 

To discover active hosts on a network (this must be run as a privileged user):

```bash
networkscan host discover  --target 192.168.0.0/24
```

### Help

```bash
networkscan host discover -h

Discover hosts on a network

Usage:
  networkscan host discover [flags]

Flags:
  -h, --help              help for discover
      --scantype string   Scan type for host discovery (tcpsyn | tcpack | icmpecho | icmptimestamp | arp | icmpaddressmask)
      --target string     Target IP, host, or CIDR to scan for hosts

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```