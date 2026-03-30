// =============================================================================
// Generic TLS Library (gtls) - Connection pool implementation (v2)
// =============================================================================

#include "gtls/connection_pool.h"
#include "gtls/logger.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace gtls {

using std::chrono::steady_clock;
using std::chrono::seconds;
using std::chrono::milliseconds;
using std::chrono::duration_cast;

// ---------------------------------------------------------------------------
// TunnelKey
// ---------------------------------------------------------------------------

bool TunnelKey::operator==(const TunnelKey& other) const {
    return host == other.host &&
           port == other.port &&
           tls_config_name == other.tls_config_name;
}

std::size_t TunnelKeyHash::operator()(const TunnelKey& key) const {
    std::size_t h = std::hash<std::string>{}(key.host);
    h ^= std::hash<uint16_t>{}(key.port) + 0x9e3779b9 + (h << 6) + (h >> 2);
    h ^= std::hash<std::string>{}(key.tls_config_name) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
}

// ---------------------------------------------------------------------------
// Helper: log with tunnel key, state, and timestamp
// ---------------------------------------------------------------------------
static void log_pool_event(LogLevel level, const TunnelKey& key,
                           const char* event) {
    auto ts = duration_cast<milliseconds>(
        steady_clock::now().time_since_epoch()).count();
    Logger::log(level,
                "ConnectionPool: %s [%s:%u/%s] ts=%lld",
                event, key.host.c_str(), key.port,
                key.tls_config_name.c_str(), (long long)ts);
}

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

ConnectionPool::ConnectionPool(PoolConfig config)
    : config_(config) {}

ConnectionPool::~ConnectionPool() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [key, entry] : tunnels_) {
        for (auto& pc : entry.connections) {
            if (pc.conn) {
                log_pool_event(LogLevel::Info, key, "shutdown state=Disconnected");
                pc.conn->shutdown();
            }
        }
    }
    tunnels_.clear();
}

// ---------------------------------------------------------------------------
// count_state
// ---------------------------------------------------------------------------

size_t ConnectionPool::count_state(const TunnelEntry& entry,
                                    PooledConn::State state) const {
    size_t n = 0;
    for (const auto& pc : entry.connections) {
        if (pc.state == state) ++n;
    }
    return n;
}

// ---------------------------------------------------------------------------
// acquire()
// ---------------------------------------------------------------------------

AcquireResult ConnectionPool::acquire(const TunnelKey& key, TlsContext& ctx) {
    std::unique_lock<std::mutex> lock(mutex_);

    auto deadline = steady_clock::now() + seconds(config_.acquire_timeout_sec);

    while (true) {
        auto& entry = tunnels_[key];

        // Strategy 1: Find an IDLE connection, with health check.
        for (auto& pc : entry.connections) {
            if (pc.state == PooledConn::State::IDLE && pc.conn) {
                // Health check before handing out.
                if (!pc.conn->is_alive()) {
                    log_pool_event(LogLevel::Warning, key,
                                   "health check failed, marking BROKEN");
                    pc.state = PooledConn::State::BROKEN;
                    pc.conn->shutdown();
                    continue;
                }
                pc.state = PooledConn::State::IN_USE;
                pc.last_used = steady_clock::now();
                log_pool_event(LogLevel::Debug, key,
                               "acquire reuse state=IDLE->IN_USE");
                return {pc.conn, TlsError::Ok};
            }
        }

        // Purge BROKEN connections before counting.
        entry.connections.erase(
            std::remove_if(entry.connections.begin(), entry.connections.end(),
                           [](const PooledConn& pc) {
                               return pc.state == PooledConn::State::BROKEN;
                           }),
            entry.connections.end());

        // Strategy 2: Create new if under limit.
        int total = static_cast<int>(entry.connections.size());
        if (total < config_.max_connections_per_target) {
            // Unlock during potentially slow network operation.
            lock.unlock();
            auto conn = create_connection(key, ctx);
            lock.lock();

            if (conn) {
                auto& e = tunnels_[key];  // Re-fetch after re-lock
                PooledConn pc(conn);
                pc.state = PooledConn::State::IN_USE;
                e.connections.push_back(std::move(pc));
                log_pool_event(LogLevel::Info, key,
                               "acquire new state=IN_USE");
                return {conn, TlsError::Ok};
            }
            // Creation failed — fall through to wait or fail.
            log_pool_event(LogLevel::Error, key,
                           "acquire create_connection failed");
        }

        // Strategy 3: Wait for a connection to become IDLE.
        auto now = steady_clock::now();
        if (now >= deadline) {
            log_pool_event(LogLevel::Warning, key,
                           "acquire timeout, pool exhausted");
            return {nullptr, TlsError::PoolExhausted};
        }

        cv_.wait_until(lock, deadline);
    }
}

// ---------------------------------------------------------------------------
// release()
// ---------------------------------------------------------------------------

void ConnectionPool::release(const TunnelKey& key,
                              std::shared_ptr<TlsConnection> conn) {
    {
        std::lock_guard<std::mutex> lock(mutex_);

        auto it = tunnels_.find(key);
        if (it != tunnels_.end()) {
            for (auto& pc : it->second.connections) {
                if (pc.conn == conn) {
                    pc.state = PooledConn::State::IDLE;
                    pc.last_used = steady_clock::now();
                    log_pool_event(LogLevel::Debug, key,
                                   "release state=IN_USE->IDLE");
                    goto notify;
                }
            }
        }

        // Connection not found in pool — add it as new IDLE entry.
        {
            auto& entry = tunnels_[key];
            PooledConn pc(std::move(conn));
            pc.state = PooledConn::State::IDLE;
            entry.connections.push_back(std::move(pc));
            log_pool_event(LogLevel::Debug, key,
                           "release new entry state=IDLE");
        }
    }

notify:
    cv_.notify_one();
}

// ---------------------------------------------------------------------------
// remove()
// ---------------------------------------------------------------------------

void ConnectionPool::remove(const TunnelKey& key,
                             std::shared_ptr<TlsConnection> conn) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnels_.find(key);
    if (it == tunnels_.end()) return;

    auto& conns = it->second.connections;
    for (auto ci = conns.begin(); ci != conns.end(); ++ci) {
        if (ci->conn == conn) {
            log_pool_event(LogLevel::Info, key, "remove state=BROKEN");
            if (ci->conn) ci->conn->shutdown();
            conns.erase(ci);
            break;
        }
    }

    if (conns.empty()) {
        tunnels_.erase(it);
    }
}

// ---------------------------------------------------------------------------
// remove_tunnel()
// ---------------------------------------------------------------------------

void ConnectionPool::remove_tunnel(const TunnelKey& key) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnels_.find(key);
    if (it == tunnels_.end()) return;

    log_pool_event(LogLevel::Info, key, "remove_tunnel");

    for (auto& pc : it->second.connections) {
        if (pc.conn) pc.conn->shutdown();
    }
    tunnels_.erase(it);
}

// ---------------------------------------------------------------------------
// cleanup_idle() — per-connection granularity
// ---------------------------------------------------------------------------

void ConnectionPool::cleanup_idle() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = steady_clock::now();
    auto timeout = seconds(config_.idle_timeout_sec);

    std::vector<TunnelKey> empty_tunnels;

    for (auto& [key, entry] : tunnels_) {
        // Only remove IDLE connections that have exceeded the timeout.
        auto& conns = entry.connections;
        for (auto ci = conns.begin(); ci != conns.end(); ) {
            if (ci->state == PooledConn::State::IDLE &&
                (now - ci->last_used) >= timeout) {
                log_pool_event(LogLevel::Info, key,
                               "cleanup idle connection state=IdleTimeout");
                if (ci->conn) ci->conn->shutdown();
                ci = conns.erase(ci);
            } else {
                ++ci;
            }
        }

        if (conns.empty()) {
            empty_tunnels.push_back(key);
        }
    }

    for (const auto& key : empty_tunnels) {
        tunnels_.erase(key);
    }
}

// ---------------------------------------------------------------------------
// stats()
// ---------------------------------------------------------------------------

PoolStats ConnectionPool::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    PoolStats s{};

    for (const auto& [key, entry] : tunnels_) {
        size_t count = entry.connections.size();
        s.per_target[key] = count;
        s.total_active += count;
        s.total_idle += count_state(entry, PooledConn::State::IDLE);
        s.total_in_use += count_state(entry, PooledConn::State::IN_USE);
        s.total_capacity += static_cast<size_t>(config_.max_connections_per_target);
    }

    return s;
}

// ---------------------------------------------------------------------------
// for_each()
// ---------------------------------------------------------------------------

void ConnectionPool::for_each(
    std::function<void(const TunnelKey&, TlsConnection&)> fn) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& [key, entry] : tunnels_) {
        for (auto& pc : entry.connections) {
            if (pc.conn) fn(key, *pc.conn);
        }
    }
}

// ---------------------------------------------------------------------------
// create_connection()
// ---------------------------------------------------------------------------

std::shared_ptr<TlsConnection> ConnectionPool::create_connection(
    const TunnelKey& key, TlsContext& ctx) {

    struct addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(key.port);
    struct addrinfo* result = nullptr;

    int gai_ret = ::getaddrinfo(key.host.c_str(), port_str.c_str(),
                                &hints, &result);
    if (gai_ret != 0) {
        Logger::log(LogLevel::Error,
                    "ConnectionPool: getaddrinfo failed for %s:%u — %s",
                    key.host.c_str(), key.port, gai_strerror(gai_ret));
        return nullptr;
    }

    int sock = -1;
    for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        sock = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        if (::connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        ::close(sock);
        sock = -1;
    }
    ::freeaddrinfo(result);

    if (sock < 0) {
        Logger::log(LogLevel::Error,
                    "ConnectionPool: TCP connect failed for %s:%u — %s",
                    key.host.c_str(), key.port, std::strerror(errno));
        return nullptr;
    }

    auto conn = std::make_shared<TlsConnection>(ctx, sock);
    if (!conn->connect(config_.connect_timeout_sec, key.host)) {
        Logger::log(LogLevel::Error,
                    "ConnectionPool: TLS handshake failed for %s:%u",
                    key.host.c_str(), key.port);
        return nullptr;
    }

    return conn;
}

} // namespace gtls
