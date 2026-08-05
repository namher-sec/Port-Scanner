# Port Scanner

A fast, asynchronous TCP port scanner written in C++ using Boost.Asio. Scans a range of ports concurrently, detects common services, and grabs banners from open ports.

## Features

- Asynchronous scanning via Boost.Asio — no thread-per-port overhead
- Configurable concurrency, timeout, and port range
- Service name lookup for common ports (SSH, HTTP, MySQL, Redis, etc.)
- Banner grabbing on open ports
- Verbose mode to show closed/filtered ports

## Requirements

- C++17 or later
- [Boost](https://www.boost.org/) (`program_options`, `asio`)
## Usage

```bash
./port_scanner -i <target> -p <port-range> [options]
```

### Options

| Flag | Description | Default |
|---|---|---|
| `-i, --dname` | Domain name or IP address | `127.0.0.1` |
| `-p, --ports` | Port range (`1-1024`) or single port (`80`) | `1-1024` |
| `-t, --threads` | Max concurrent connections | `100` |
| `-e, --expiry_time` | Timeout in seconds per port | `2` |
| `-v, --verbose` | Show closed/filtered ports too | off |
| `-h, --help` | Show help message | |

### Examples

```bash
# Scan common ports on localhost
./port_scanner -i 127.0.0.1 -p 1-1024

# Full TCP port scan with more concurrency
./port_scanner -i 192.168.1.1 -p 1-65535 -t 200

# Scan with a custom timeout
./port_scanner -i example.com -p 80-443 -e 5

# Verbose output
./port_scanner -i 127.0.0.1 -p 1-1024 -v
```

### Sample Output

```
PORT     STATE      SERVICE      BANNER
--------------------------------------------------------
22       OPEN       SSH          SSH-2.0-OpenSSH_9.6
80       OPEN       HTTP         ---
443      OPEN       HTTPS        ---
--------------------------------------------------------
Scan complete.
  Open:     3
  Closed:   1021
  Filtered: 0
```

## ⚠️ Disclaimer

Only scan systems you own or have explicit permission to test. Unauthorized port scanning may violate computer misuse laws in your jurisdiction.
