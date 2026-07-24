/*
 * Multi-threaded TCP Port Scanner in C++17
 * Educational / authorized-use only.
 *
 * Build: make
 * Usage: ./portscan <host> <start> <end> [threads] [timeout_ms]
 *
 * WARNING: Only scan systems you own or have explicit permission to test.
 */

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <queue>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <map>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

// ANSI colors
const char* GREEN  = "\033[32m";
const char* YELLOW = "\033[33m";
const char* RESET  = "\033[0m";
const char* BOLD   = "\033[1m";

std::atomic<bool> running{true};
std::atomic<int> scanned{0};
std::atomic<int> open_count{0};
std::mutex results_mutex;
std::vector<int> open_ports;
std::mutex cout_mutex;

// Common service names
std::map<int, std::string> services = {
    {20, "ftp-data"}, {21, "ftp"}, {22, "ssh"}, {23, "telnet"},
    {25, "smtp"}, {53, "dns"}, {80, "http"}, {110, "pop3"},
    {111, "rpcbind"}, {135, "msrpc"}, {139, "netbios-ssn"},
    {143, "imap"}, {443, "https"}, {445, "microsoft-ds"},
    {993, "imaps"}, {995, "pop3s"}, {1433, "mssql"},
    {1521, "oracle"}, {3306, "mysql"}, {3389, "rdp"},
    {5432, "postgresql"}, {5900, "vnc"}, {6379, "redis"},
    {8080, "http-proxy"}, {8443, "https-alt"}, {27017, "mongodb"}
};

void signal_handler(int) {
    running = false;
    std::cerr << "\n" << YELLOW << "[!] Interrupted. Finishing current work..." << RESET << "\n";
}

bool set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return false;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK) != -1;
}

bool check_port(const std::string& ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    if (!set_nonblocking(sock)) {
        close(sock);
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        return false;
    }

    int res = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (res == 0) {
        close(sock);
        return true;
    }

    if (errno != EINPROGRESS) {
        close(sock);
        return false;
    }

    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(sock, &write_fds);

    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    res = select(sock + 1, nullptr, &write_fds, nullptr, &tv);
    if (res <= 0) {
        close(sock);
        return false;
    }

    int so_error = 0;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    close(sock);
    return so_error == 0;
}

// Thread-safe work queue of ports
class PortQueue {
public:
    void push(int port) {
        std::lock_guard<std::mutex> lock(mtx_);
        q_.push(port);
        cv_.notify_one();
    }

    void finish() {
        std::lock_guard<std::mutex> lock(mtx_);
        finished_ = true;
        cv_.notify_all();
    }

    bool pop(int& port) {
        std::unique_lock<std::mutex> lock(mtx_);
        cv_.wait(lock, [this] { return !q_.empty() || finished_ || !running; });
        if (q_.empty()) return false;
        port = q_.front();
        q_.pop();
        return true;
    }

private:
    std::queue<int> q_;
    std::mutex mtx_;
    std::condition_variable cv_;
    bool finished_ = false;
};

void worker(const std::string& ip, PortQueue& queue, int timeout_ms, int total) {
    int port;
    while (running && queue.pop(port)) {
        if (check_port(ip, port, timeout_ms)) {
            {
                std::lock_guard<std::mutex> lock(results_mutex);
                open_ports.push_back(port);
            }
            open_count++;
            std::string svc = services.count(port) ? services[port] : "";
            {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << GREEN << "[+] " << port;
                if (!svc.empty()) std::cout << "/" << svc;
                std::cout << " open" << RESET << "\n";
            }
        }
        int done = ++scanned;
        if (done % 50 == 0 || done == total) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            int pct = (done * 100) / total;
            std::cout << YELLOW << "\r[*] Progress: " << done << "/" << total
                      << " (" << pct << "%)   " << RESET << std::flush;
        }
    }
}

std::string resolve_hostname(const std::string& host) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
        return "";
    }

    char ipstr[INET_ADDRSTRLEN];
    auto* ipv4 = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));
    freeaddrinfo(res);
    return std::string(ipstr);
}

void print_usage(const char* prog) {
    std::cerr << BOLD << "Usage: " << RESET << prog
              << " <host> <start_port> <end_port> [threads] [timeout_ms]\n\n"
              << "  host         IP or hostname\n"
              << "  start_port   First port (1-65535)\n"
              << "  end_port     Last port (1-65535)\n"
              << "  threads      Worker threads (default: 100)\n"
              << "  timeout_ms   Connect timeout in ms (default: 400)\n\n"
              << "Example: " << prog << " scanme.nmap.org 1 1000 150 300\n"
              << YELLOW << "Only scan systems you own or have permission for!\n" << RESET;
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc > 6) {
        print_usage(argv[0]);
        return 1;
    }

    std::string host = argv[1];
    int start_port = std::atoi(argv[2]);
    int end_port   = std::atoi(argv[3]);
    int num_threads = (argc >= 5) ? std::atoi(argv[4]) : 100;
    int timeout_ms  = (argc == 6) ? std::atoi(argv[5]) : 400;

    if (start_port < 1 || end_port > 65535 || start_port > end_port ||
        num_threads < 1 || timeout_ms < 50) {
        std::cerr << "Invalid arguments.\n";
        print_usage(argv[0]);
        return 1;
    }

    std::string ip = resolve_hostname(host);
    if (ip.empty()) {
        std::cerr << "Failed to resolve: " << host << "\n";
        return 1;
    }

    std::signal(SIGINT, signal_handler);

    int total = end_port - start_port + 1;

    std::cout << BOLD << "Target: " << RESET << host << " (" << ip << ")\n"
              << "Ports:  " << start_port << "-" << end_port
              << "  |  Threads: " << num_threads
              << "  |  Timeout: " << timeout_ms << "ms\n\n";

    PortQueue queue;
    for (int p = start_port; p <= end_port; ++p) {
        queue.push(p);
    }

    auto start_time = std::chrono::steady_clock::now();

    std::vector<std::thread> workers;
    for (int i = 0; i < num_threads; ++i) {
        workers.emplace_back(worker, ip, std::ref(queue), timeout_ms, total);
    }

    // All work has been enqueued; signal workers they can exit when queue drains
    queue.finish();

    for (auto& t : workers) {
        t.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

    {
        std::lock_guard<std::mutex> lock(results_mutex);
        std::sort(open_ports.begin(), open_ports.end());
    }

    std::cout << "\n\n" << BOLD << "========== Results ==========" << RESET << "\n";
    std::cout << "Open ports: " << open_count << "\n";
    for (int p : open_ports) {
        std::string svc = services.count(p) ? " (" + services[p] + ")" : "";
        std::cout << GREEN << "  " << p << svc << RESET << "\n";
    }
    std::cout << "Scanned: " << scanned << " ports in " << ms << " ms\n";
    if (ms > 0) {
        std::cout << "Rate:    " << (scanned * 1000 / ms) << " ports/sec\n";
    }
    std::cout << BOLD << "=============================" << RESET << "\n";

    return 0;
}
