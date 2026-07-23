/*
 * Simple multi-threaded TCP Port Scanner in C++
 * Educational / authorized-use only.
 *
 * Build: make
 * Usage: ./portscan <host> <start_port> <end_port> [num_threads]
 *
 * Example: ./portscan 127.0.0.1 1 1024 50
 *
 * WARNING: Only scan hosts and networks you own or have explicit permission to test.
 * Unauthorized port scanning may be illegal.
 */

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

std::mutex cout_mutex;
std::atomic<int> open_ports_count{0};
std::vector<int> open_ports;
std::mutex open_ports_mutex;

bool set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return false;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK) != -1;
}

bool check_port(const std::string& ip, int port, int timeout_ms = 300) {
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
        // Immediate success (rare for non-blocking)
        close(sock);
        return true;
    }

    if (errno != EINPROGRESS) {
        close(sock);
        return false;
    }

    // Wait with select for connection or timeout
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(sock, &write_fds);

    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    res = select(sock + 1, nullptr, &write_fds, nullptr, &tv);
    if (res <= 0) {
        // Timeout or error
        close(sock);
        return false;
    }

    // Check if connection succeeded
    int so_error = 0;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    close(sock);

    return so_error == 0;
}

void scan_range(const std::string& ip, int start, int end) {
    for (int port = start; port <= end; ++port) {
        if (check_port(ip, port)) {
            {
                std::lock_guard<std::mutex> lock(open_ports_mutex);
                open_ports.push_back(port);
            }
            {
                std::lock_guard<std::mutex> lock(cout_mutex);
                std::cout << "[+] Port " << port << " is OPEN\n";
            }
            open_ports_count++;
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
    std::cerr << "Usage: " << prog << " <host> <start_port> <end_port> [num_threads]\n"
              << "  host         : IP or hostname to scan\n"
              << "  start_port   : First port (1-65535)\n"
              << "  end_port     : Last port (1-65535)\n"
              << "  num_threads  : Optional, default 100\n\n"
              << "Example: " << prog << " scanme.nmap.org 20 100 50\n"
              << "Only use on systems you own or have permission to scan!\n";
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc > 5) {
        print_usage(argv[0]);
        return 1;
    }

    std::string host = argv[1];
    int start_port = std::atoi(argv[2]);
    int end_port = std::atoi(argv[3]);
    int num_threads = (argc == 5) ? std::atoi(argv[4]) : 100;

    if (start_port < 1 || end_port > 65535 || start_port > end_port || num_threads < 1) {
        std::cerr << "Invalid port range or thread count.\n";
        print_usage(argv[0]);
        return 1;
    }

    std::string ip = resolve_hostname(host);
    if (ip.empty()) {
        std::cerr << "Failed to resolve host: " << host << "\n";
        return 1;
    }

    std::cout << "Scanning " << host << " (" << ip << ") ports "
              << start_port << "-" << end_port
              << " with " << num_threads << " threads...\n\n";

    auto start_time = std::chrono::steady_clock::now();

    int total_ports = end_port - start_port + 1;
    int ports_per_thread = total_ports / num_threads;
    int remainder = total_ports % num_threads;

    std::vector<std::thread> threads;
    int current = start_port;

    for (int i = 0; i < num_threads; ++i) {
        int count = ports_per_thread + (i < remainder ? 1 : 0);
        if (count <= 0) break;
        int thread_end = current + count - 1;
        threads.emplace_back(scan_range, ip, current, thread_end);
        current = thread_end + 1;
    }

    for (auto& t : threads) {
        t.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

    // Sort open ports for clean output
    {
        std::lock_guard<std::mutex> lock(open_ports_mutex);
        std::sort(open_ports.begin(), open_ports.end());
    }

    std::cout << "\n========== Scan complete ==========\n";
    std::cout << "Open ports (" << open_ports_count << "):\n";
    for (int p : open_ports) {
        std::cout << "  " << p << "\n";
    }
    std::cout << "Time taken: " << duration << " ms\n";
    std::cout << "===================================\n";

    return 0;
}
