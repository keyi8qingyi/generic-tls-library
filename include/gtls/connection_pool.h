// =============================================================================
// Generic TLS Library (gtls) - Connection pool management (v2)
// Manages multiple TLS tunnels indexed by TunnelKey.
// Key improvements over v1:
//   - PooledConn state machine (IDLE / IN_USE / BROKEN) prevents double-dispatch
//   - Per-connection last_used tracking for precise idle cleanup
//   - condition_variable for blocking wait when pool is exhausted
//   - Health check on acquire to detect stale connections
// =============================================================================
#ifndef GTLS_CONNECTION_POOL_H
#define GTLS_CONNECTION_POOL_H

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "gtls/tls_connection.h"
#include "gtls/tls_context.h"
#include "gtls/tls_error.h"

namespace gtls {

// Unique identifier for a TLS tunnel.
struct TunnelKey {
    std::string host;
    uint16_t port;
    std::string tls_config_name;

    bool operator==(const TunnelKey& other) const;
};

struct TunnelKeyHash {
    std::size_t operator()(const TunnelKey& key) const;
};

// Connection pool configuration.
struct PoolConfig {
    int max_connections_per_target = 4;
    int idle_timeout_sec = 600;
    int connect_timeout_sec = 30;
    int acquire_timeout_sec = 5;  // Max time to wait for an idle connection
};

// Per-connection wrapper with state tracking.
struct PooledConn {
    enum class State { IDLE, IN_USE, BROKEN };

    std::shared_ptr<TlsConnection> conn;
    State state = State::IDLE;
    std::chrono::steady_clock::time_point last_used;

    PooledConn() = default;
    explicit PooledConn(std::shared_ptr<TlsConnection> c)
        : conn(std::move(c)),
          state(State::IDLE),
          last_used(std::chrono::steady_clock::now()) {}
};

// Connection pool statistics snapshot.
struct PoolStats {
    size_t total_active;    // All connections (IDLE + IN_USE)
    size_t total_idle;      // IDLE connections only
    size_t total_in_use;    // IN_USE connections only
    std::unordered_map<TunnelKey, size_t, TunnelKeyHash> per_target;
    size_t total_capacity;
};

// Result of an acquire operation.
struct AcquireResult {
    std::shared_ptr<TlsConnection> conn;  // nullptr on failure
    TlsError error = TlsError::Ok;
};

// Thread-safe connection pool with state machine, health checks, and
// blocking wait support.
class ConnectionPool {
public:
    explicit ConnectionPool(PoolConfig config = {});
    ~ConnectionPool();

    ConnectionPool(const ConnectionPool&) = delete;
    ConnectionPool& operator=(const ConnectionPool&) = delete;

    // Acquire a connection. Blocks up to acquire_timeout_sec if pool is full.
    // Performs health check on reused connections.
    AcquireResult acquire(const TunnelKey& key, TlsContext& ctx);

    // Release a connection back to IDLE state.
    // Wakes up one thread waiting in acquire().
    void release(const TunnelKey& key, std::shared_ptr<TlsConnection> conn);

    // Mark a connection as BROKEN and remove it from the pool.
    void remove(const TunnelKey& key, std::shared_ptr<TlsConnection> conn);

    // Remove all connections for a tunnel.
    void remove_tunnel(const TunnelKey& key);

    // Clean up IDLE connections that exceeded idle_timeout_sec.
    // Only removes IDLE connections; IN_USE connections are untouched.
    void cleanup_idle();

    // Get pool statistics.
    PoolStats stats() const;

    // Thread-safe iteration.
    void for_each(std::function<void(const TunnelKey&, TlsConnection&)> fn);

private:
    struct TunnelEntry {
        std::vector<PooledConn> connections;
    };

    std::shared_ptr<TlsConnection> create_connection(
        const TunnelKey& key, TlsContext& ctx);

    // Count connections in a specific state for a tunnel entry.
    size_t count_state(const TunnelEntry& entry, PooledConn::State state) const;

    PoolConfig config_;
    std::unordered_map<TunnelKey, TunnelEntry, TunnelKeyHash> tunnels_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;  // Signaled when a connection becomes IDLE
};

} // namespace gtls

#endif // GTLS_CONNECTION_POOL_H
