# C++ TCP Port Scanner

Fast multi-threaded TCP port scanner written in C++17.

**Educational / authorized-use only.**

## Features

- Work-queue based thread pool (better load balancing)
- Non-blocking connect with configurable timeout
- Real-time progress indicator
- Colored output + common service names
- Graceful Ctrl+C handling
- Ports/sec rate reporting

## Build

```bash
make
```

Requires g++/clang++ with C++17 and POSIX sockets.

## Usage

```bash
./portscan <host> <start_port> <end_port> [threads] [timeout_ms]
```

| Argument    | Description                     | Default |
|-------------|---------------------------------|---------| 
| host        | IP or hostname                  | —       |
| start_port  | First port (1–65535)            | —       |
| end_port    | Last port (1–65535)             | —       |
| threads     | Number of worker threads        | 100     |
| timeout_ms  | Connect timeout in milliseconds | 400     |

### Examples

```bash
./portscan 127.0.0.1 1 1024
./portscan scanme.nmap.org 20 1000 200 300
./portscan 192.168.1.1 22 22 10 500
```

## Legal Notice

**Only scan systems and networks you own or have explicit permission to test.**

Unauthorized scanning can be illegal. This tool is for education and authorized security work only.

## License

MIT — see [LICENSE](LICENSE)
