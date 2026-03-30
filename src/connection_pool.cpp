// =============================================================================
// Generic TLS Library (gtls) - Connection pool implementation
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

// ---------------------------------------------------------------------------
// TunnelKey
// ---------------------------------------------------------------------------

bool TunnelKey::operator==(const TunnelKey& other) const {
    return host == other.host &&
           port == other.port &&
           tls_config_name == other.tls_config_name;
}

std::size_t TunnelKeyHash::operator()(const TunnelKey& key) const {
    // Combine hashes of host, port, and tls_config_name using FNV-like mixing.
    std::size_t h = std::hash<std::string>{}(key.host);
    h ^= std::hash<uint16_t>{}(key.port) + 0x9e3779b9 + (h << 6) + (h >> 2);
    h ^= std::hash<std::string>{}(key.tls_config_name) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
}

// ---------------------------------------------------------------------------
// ConnectionPool construction / destruction
// ---------------------------------------------------------------------------

ConnectionPool::ConnectionPool(PoolConfig config)
    : config_(config) {}

ConnectionPool::~ConnectionPool() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [key, entry] : tunnels_) {
        for (auto& conn : entry.connections) {
            if (conn) {
                auto now = steady_clock::now();
                auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()).count();
                Logger::log(LogLevel::Info,
                            "ConnectionPool: shutdown connection [%s:%u/%s] state=Disconnected ts=%lld",
                            key.host.c_str(), key.port,
                            key.tls_config_name.c_str(), (long long)ts);
                conn->shutdown();
            }
        }
        entry.connections.clear();
    }
    tunnels_.clear();
}

// ---------------------------------------------------------------------------
// acquire()
// ---------------------------------------------------------------------------

std::shared_ptr<TlsConnection> ConnectionPool::acquire(const TunnelKey& key,
                                                         TlsContext& ctx) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& entry = tunnels_[key];

    // Strategy 1: Find an existing idle connection (Connected state).
    for (auto& conn : entry.connections) {
        if (conn && conn->state() == ConnState::Connected) {
            entry.last_used = steady_clock::now();

            auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
                entry.last_used.time_since_epoch()).count();
            Logger::log(LogLevel::Debug,
                        "ConnectionPool: reuse connection [%s:%u/%s] state=Connected ts=%lld",
                        key.host.c_str(), key.port,
                        key.tls_config_name.c_str(), (long long)ts);
            return conn;
        }
    }

    // Strategy 2: Create a new connection if under the per-target limit.
    int current_count = static_cast<int>(entry.connections.size());
    if (current_count < config_.max_connections_per_target) {
        // Release the pool lock during connection creation to avoid
        // holding it during potentially slow network operations.
        // We must unlock, create, then re-lock and insert.
        // However, since we use lock_guard, we do the creation inline.
        // For simplicity and correctness, we create under the lock.
        // In production, consider upgrading to a more sophisticated scheme.
        auto conn = create_connection(key, ctx);
        if (conn) {
            entry.connections.push_back(conn);
            entry.last_used = steady_clock::now();

            auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
                entry.last_used.time_since_epoch()).count();
            Logger::log(LogLevel::Info,
                        "ConnectionPool: new connection [%s:%u/%s] state=Connected ts=%lld",
                        key.host.c_str(), key.port,
                        key.tls_config_name.c_str(), (long long)ts);
        }
        return conn;
    }

    // Strategy 3: At limit — reuse the least-recently-used (first) connection.
    if (!entry.connections.empty()) {
        auto& conn = entry.connections.front();
        entry.last_used = steady_clock::now();

        auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
            entry.last_used.time_since_epoch()).count();
        Logger::log(LogLevel::Debug,
                    "ConnectionPool: reuse LRU connection [%s:%u/%s] state=AtLimit ts=%lld",
                    key.host.c_str(), key.port,
                    key.tls_config_name.c_str(), (long long)ts);
        return conn;
    }

    return nullptr;
}

// ---------------------------------------------------------------------------
// release()
// ---------------------------------------------------------------------------

void ConnectionPool::release(const TunnelKey& key,
                              std::shared_ptr<TlsConnection> conn) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnels_.find(key);
    if (it == tunnels_.end()) {
        // Tunnel not found; create a new entry and add the connection.
        TunnelEntry entry;
        entry.connections.push_back(std::move(conn));
        entry.last_used = steady_clock::now();
        tunnels_[key] = std::move(entry);
    } else {
        // Check if connection is already in the pool.
        auto& conns = it->second.connections;
        auto found = std::find(conns.begin(), conns.end(), conn);
        if (found == conns.end()) {
            conns.push_back(std::move(conn));
        }
        it->second.last_used = steady_clock::now();
    }

    auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        steady_clock::now().time_since_epoch()).count();
    Logger::log(LogLevel::Debug,
                "ConnectionPool: release connection [%s:%u/%s] state=Released ts=%lld",
                key.host.c_str(), key.port,
                key.tls_config_name.c_str(), (long long)ts);
}

// ---------------------------------------------------------------------------
// remove()
// ---------------------------------------------------------------------------

void ConnectionPool::remove(const TunnelKey& key,
                             std::shared_ptr<TlsConnection> conn) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnels_.find(key);
    if (it == tunnels_.end()) {
        return;
    }

    auto& conns = it->second.connections;
    auto found = std::find(conns.begin(), conns.end(), conn);
    if (found != conns.end()) {
        auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
            steady_clock::now().time_since_epoch()).count();
        Logger::log(LogLevel::Info,
                    "ConnectionPool: remove connection [%s:%u/%s] state=Removed ts=%lld",
                    key.host.c_str(), key.port,
                    key.tls_config_name.c_str(), (long long)ts);

        // Shutdown the connection before removing.
        if (*found) {
            (*found)->shutdown();
        }
        conns.erase(found);
    }

    // Remove the tunnel entry if no connections remain.
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
    if (it == tunnels_.end()) {
        return;
    }

    auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        steady_clock::now().time_since_epoch()).count();
    Logger::log(LogLevel::Info,
                "ConnectionPool: remove tunnel [%s:%u/%s] connections=%zu state=TunnelRemoved ts=%lld",
                key.host.c_str(), key.port,
                key.tls_config_name.c_str(),
                it->second.connections.size(), (long long)ts);

    // Shutdown all connections in this tunnel.
    for (auto& conn : it->second.connections) {
        if (conn) {
            conn->shutdown();
        }
    }

    tunnels_.erase(it);
}

// ---------------------------------------------------------------------------
// cleanup_idle()
// ---------------------------------------------------------------------------

void ConnectionPool::cleanup_idle() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = steady_clock::now();
    auto timeout = seconds(config_.idle_timeout_sec);

    // Collect tunnel keys to erase after iteration.
    std::vector<TunnelKey> empty_tunnels;

    for (auto& [key, entry] : tunnels_) {
        // Check if the entire tunnel has been idle beyond the timeout.
        if ((now - entry.last_used) >= timeout) {
            auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count();
            Logger::log(LogLevel::Info,
                        "ConnectionPool: cleanup idle tunnel [%s:%u/%s] connections=%zu state=IdleTimeout ts=%lld",
                        key.host.c_str(), key.port,
                        key.tls_config_name.c_str(),
                        entry.connections.size(), (long long)ts);

            for (auto& conn : entry.connections) {
                if (conn) {
                    conn->shutdown();
                }
            }
            entry.connections.clear();
            empty_tunnels.push_back(key);
        }
    }

    // Remove empty tunnel entries.
    for (const auto& key : empty_tunnels) {
        tunnels_.erase(key);
    }
}

// ---------------------------------------------------------------------------
// stats()
// ---------------------------------------------------------------------------

PoolStats ConnectionPool::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    PoolStats s;
    s.total_active = 0;
    s.total_capacity = 0;

    for (const auto& [key, entry] : tunnels_) {
        size_t count = entry.connections.size();
        s.per_target[key] = count;
        s.total_active += count;
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
        for (auto& conn : entry.connections) {
            if (conn) {
                fn(key, *conn);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// create_connection() — private helper
// ---------------------------------------------------------------------------

std::shared_ptr<TlsConnection> ConnectionPool::create_connection(
    const TunnelKey& key, TlsContext& ctx) {

    // Resolve the target host address.
    struct addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;      // Support both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;  // TCP
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

    // Try each resolved address until one succeeds.
    int sock = -1;
    for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        sock = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) {
            continue;
        }

        if (::connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;  // Successfully connected.
        }

        // Connect failed for this address; close and try next.
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

    // Create TLS connection and perform handshake.
    auto conn = std::make_shared<TlsConnection>(ctx, sock);
    if (!conn->connect(config_.connect_timeout_sec, key.host)) {
        Logger::log(LogLevel::Error,
                    "ConnectionPool: TLS handshake failed for %s:%u",
                    key.host.c_str(), key.port);
        // TlsConnection::connect() handles cleanup on failure.
        return nullptr;
    }

    return conn;
}

} // namespace gtls
