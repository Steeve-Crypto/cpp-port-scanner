# C++ TCP Port Scanner

Fast multi-threaded TCP port scanner written in C++17.

**Version 1.2.0 — Educational / authorized-use only.**

## Ethical Guardrails (built-in)

- **Localhost + private RFC1918 ranges** allowed by default.
- **Any public IP** blocked unless `--i-have-permission` (`-p`) is passed.
- Strong red legal banner on every interactive run.
- Refuses public targets without the explicit flag.

## Features

- Work-queue thread pool
- Non-blocking connect + configurable timeout
- `--top` curated common-ports list
- Optional banner grabbing (`-b`)
- Quiet mode (`-q`) and JSON (`--json`)
- Write results to file (`-o`)
- Progress + colored output
- Graceful Ctrl+C
- Version flag

## Build

```bash
make          # release
make debug    # -g -O0
make clean
```

## Usage

```bash
./portscan [options] <host> [<start_port> <end_port>]
```

| Option                    | Description                              | Default |
|---------------------------|------------------------------------------|---------|
| host                      | IP or hostname                           | —       |
| start end                 | Inclusive port range                     | —       |
| --top                     | Scan curated common ports instead        | off     |
| -t, --threads N           | Worker threads                           | 100     |
| -T, --timeout MS          | Connect timeout (ms)                     | 400     |
| -b, --banner              | Grab service banners                     | off     |
| -q, --quiet               | Suppress live progress                   | off     |
| --json                    | JSON stdout                              | off     |
| -o, --output FILE         | Also write results to FILE               | —       |
| -p, --i-have-permission   | Allow public targets                     | off     |
| --version                 | Print version                            |         |
| -h, --help                | Help                                     |         |

### Examples

```bash
./portscan 127.0.0.1 1 1024
./portscan 192.168.1.10 --top -b
./portscan 127.0.0.1 --top -q -o open.txt
./portscan scanme.nmap.org --top -p -b --json -o result.json
```

## Legal Notice

Only scan systems you own or have explicit written permission to test. Unauthorized scanning can be illegal. The permission gate exists to reduce accidental misuse.

## License

MIT — see [LICENSE](LICENSE)
