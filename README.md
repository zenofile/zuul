# rostschutz

A basic utility for managing nftables-based IP blocklists with support for country-based filtering and abuse list integration.

Inspired by [nft-blackhole](https://github.com/tomasz-c/nft-blackhole).

## Features

- **Multi-source IP blocking**: Whitelists, blacklists, abuselists, and country-based filtering
- **Dual-stack support**: IPv4 and IPv6 with independent configuration
- **Concurrent downloads**: Multi-threaded fetching of remote IP lists
- **Template-based rules**: Jinja2 templating for flexible nftables rule generation
- **Multi-interface template**: Supports multiple network interfaces
- **Systemd integration**: Includes service and timer units for automated updates
- **Sandboxing**: Optional landlock based sandboxing (enabled by default)


## Requirements

- Linux kernel (>= 6.12 for landlock) with nftables support
- Rust 2024 edition or later

### When dynamically linked:
- libssl >= 3
- libcurl >= 4

## Building & Installation

```cli
cargo build --release --features=static
cp target/release/rostschutz /usr/local/bin/
mkdir -p /usr/local/etc/rostschutz/
cp config.yaml template.j2 /usr/local/etc/rostschutz/
cp -r systemd/rostschutz-.service.d /etc/systemd/system/
cp systemd/rostschutz-main.service systemd/rostschutz-refresh.{service,timer} /etc/systemd/system/
systemctl daemon-reload
```


## Configuration

Edit `config.yaml` to configure IP versions, block policies, whitelists, blacklists, abuselists, and ISO 3166-1 alpha-2 country codes

## Usage

```log
Usage: rostschutz [OPTIONS] <COMMAND>

Commands:
  start    Start rostschutz and create firewall rules
  stop     Stop rostschutz and remove firewall rules
  restart  Restart rostschutz (stop then start)
  refresh  Update lists
  config   Display current configuration
  help     Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>      Path to configuration file
  -t, --template <TEMPLATE>  Path to template file
  -v, --verbose...           Increase verbosity level (-v, -vv, -vvv, etc.)
  -w, --threads <THREADS>    Number of worker threads [default: 8]
      --timeout <TIMEOUT>    Timeout for requests in seconds [default: 10]
  -s, --enforce-sandbox      Enforce sandboxing
  -n, --dry-run              Perform a dry-run without making actual changes
  -h, --help                 Print help
```

## Systemd Services

Enable automatic updates with the included systemd units:

```cli
systemctl enable --now rostschutz-main.service
systemctl enable --now rostschutz-refresh.timer
```

The timer refreshes abuse and country lists at configured intervals.
