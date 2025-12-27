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

## Example output generated

```nft
table netdev blackhole {
    set blacklist_v4 {
        type ipv4_addr;
        flags interval;
        auto-merge;
        elements = { 224.0.0.0/3 }
    }

    set whitelist_v4 {
        type ipv4_addr;
        flags interval;
        auto-merge;
        elements = {
            10.0.0.0/8,
            217.142.30.0/24
        }
    }

    set whitelist_v6 {
        type ipv6_addr;
        flags interval;
        auto-merge;
        elements = {
            fc00::/7,
            fd00::/8,
            fe80::/10
        }
    }

    set abuselist_v4_1766862325 {
        type ipv4_addr;
        flags interval;
        auto-merge;
        elements = {
            1.2.239.214/32,
            223.247.33.150/32,
            223.247.218.112/32,
            223.254.0.0/16
        }
    }

    set abuselist_v6_1766862325 {
        type ipv6_addr;
        flags interval;
        auto-merge;
        elements = {
            2400:3200::/32,
            2400:3200::/48,
            2a13:1800::/29,
            2a13:8b40::/29
        }
    }

    counter whitelist_v4_cnt {}
    counter blacklist_v4_cnt {}
    counter abuselist_v4_cnt {}
    counter country_v4_cnt {}
    counter whitelist_v6_cnt {}
    counter blacklist_v6_cnt {}
    counter abuselist_v6_cnt {}
    counter country_v6_cnt {}

    chain ingress_enp73s0 {
            type filter hook ingress device "enp73s0" priority -190; policy accept;
            jump validation
        }

        chain validation {
            iifname "lo" accept

            ip saddr @whitelist_v4 counter name whitelist_v4_cnt accept
            ip saddr @blacklist_v4 counter name blacklist_v4_cnt goto log-target
            ip saddr @abuselist_v4_1766862325 counter name abuselist_v4_cnt goto log-target
            ip saddr @country_v4_1766862325 counter name country_v4_cnt goto log-target
            ip6 saddr @whitelist_v6 counter name whitelist_v6_cnt accept
            ip6 saddr @abuselist_v6_1766862325 counter name abuselist_v6_cnt goto log-target
            ip6 saddr @country_v6_1766862325 counter name country_v6_cnt goto log-target
        }

        chain log-target {
            limit rate 10/minute burst 5 packets log level debug
            drop
        }
    }
}
```
