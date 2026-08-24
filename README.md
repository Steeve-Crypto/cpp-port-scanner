# C++ TCP Port Scanner

Fast multi-threaded TCP port scanner written in C++17.

**Educational / authorized-use only.**

## Ethical Guardrails (built-in)

- **Localhost + private RFC1918 ranges** (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are allowed by default.
- **Any public IP** is blocked unless you pass `--i-have-permission` (or `-p`).
- Strong red legal banner printed on every run.
- The tool will refuse to scan public targets without the explicit flag.

This is intentional. The goal is education and authorized testing only.

## Features

- Work-queue based thread pool
- Non-blocking connect with configurable timeout
- Optional service banner grabbing (`-b`)
- Quiet mode (`-q`) and JSON output (`--json`)
- Real-time progress + colored results
- Graceful Ctrl+C handling
- Ports/sec rate reporting
- Permission gate for public targets

## Build

```bash
make
```

Requires g++/clang++ with C++17 and POSIX sockets.

## Usage

```bash
./portscan [options] <host> <start_port> <end_port>
```

| Option / Arg              | Description                                      | Default |
|---------------------------|--------------------------------------------------|---------|
| host                      | IP or hostname                                   | —       |
| start_port / end_port     | Port range (1–65535)                             | —       |
| -t, --threads N           | Number of worker threads                         | 100     |
| -T, --timeout MS          | Connect timeout in milliseconds                  | 400     |
| -b, --banner              | Attempt to grab service banners                  | off     |
| -q, --quiet               | Suppress progress and live output                | off     |
| --json                    | Machine-readable JSON output                     | off     |
| -p, --i-have-permission   | Required for any public (non-private) target     | off     |
| -h, --help                | Show help                                        |         |

### Examples

```bash
# Localhost (always allowed)
./portscan 127.0.0.1 1 1024

# Private network + banner grab
./portscan 192.168.1.10 22 80 -t 50 -b

# Quiet mode (only open ports)
./portscan 127.0.0.1 1 1000 -q

# Public target with permission + JSON
./portscan scanme.nmap.org 20 100 -p -b --json
```

## Legal Notice

**Only scan systems and networks you own or have explicit written permission to test.**

Unauthorized scanning can be illegal. This tool is for education and authorized security work only. The built-in permission gate exists to reduce accidental misuse.

## License

MIT — see [LICENSE](LICENSE)
