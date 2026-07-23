# C++ TCP Port Scanner

A simple, multi-threaded TCP port scanner written in modern C++17.

**Educational / authorized-use only.**

## Features

- Resolves hostnames to IPv4
- Multi-threaded scanning (configurable thread count)
- Non-blocking connect with timeout for reasonable speed
- Clean sorted list of open ports at the end
- Lightweight — single source file

## Build

```bash
make
```

Requires a C++17 compiler (g++ / clang++) and POSIX sockets (Linux, macOS, WSL, etc.).

## Usage

```bash
./portscan <host> <start_port> <end_port> [num_threads]
```

| Argument     | Description                          | Default |
|--------------|--------------------------------------|---------|
| host         | IP address or hostname               | —       |
| start_port   | First port to scan (1–65535)         | —       |
| end_port     | Last port to scan (1–65535)          | —       |
| num_threads  | Number of concurrent threads         | 100     |

### Examples

```bash
# Scan common ports on localhost
./portscan 127.0.0.1 1 1024

# Faster scan of a wider range
./portscan scanme.nmap.org 20 1000 200

# Scan a single port
./portscan 192.168.1.1 22 22
```

## Important Legal Notice

**Only scan systems and networks that you own or have explicit written permission to test.**

Unauthorized port scanning can be considered a criminal offense under computer misuse laws in many jurisdictions. This tool is provided strictly for educational purposes, penetration testing under contract, and authorized security assessments.

The author assumes no liability for misuse.

## License

MIT License — see [LICENSE](LICENSE)
