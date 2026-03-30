// =============================================================================
// Generic TLS Library (gtls) - Connection pool management
// Manages multiple TLS tunnels indexed by TunnelKey (host + port + config name).
// Supports connection reuse, idle cleanup, and per-target connection limits.
// =============================================================================
#ifndef GTLS_CONNECTION_POOL_H
#define GTLS_CONNECTION_POOL_H

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "gtls/tls_connection.h"
#include "gtls/tls_context.h"

namespace gtls {

// Unique identifier for a TLS tunnel.
// Composed of target host, port, and optional TLS config name.
struct TunnelKey {
    std::string host;             // Target server IP address or hostname
    uint16_t port;                // Target server port
    std::string tls_config_name;  // Optional TLS config name for multi-config scenarios

    bool operator==(const TunnelKey& other) const;
};

// Hash function for TunnelKey, enabling use in std::unordered_map.
struct TunnelKeyHash {
    std::size_t operator()(const TunnelKey& key) const;
};

// Connection pool configuration parameters.
struct PoolConfig {
    int max_connections_per_target = 4;   // Max connections per TunnelKey
    int idle_timeout_sec = 600;           // Idle connection timeout in seconds
    int connect_timeout_sec = 30;         // TCP + TLS handshake timeout in seconds
};

// Connection pool statistics snapshot.
struct PoolStats {
    size_t total_active;          // Total number of active connections across all tunnels
    std::unordered_map<TunnelKey, size_t, TunnelKeyHash> per_target;  // Per-target counts
    size_t total_capacity;        // Sum of max_connections_per_target for all known tunnels
};

// Manages a pool of TLS connections organized by TunnelKey.
// Thread-safe: all public methods are protected by an internal mutex.
//
// Acquire strategy:
//   1. Reuse an existing idle connection for the tunnel
//   2. Create a new connection if under the per-target limit
//   3. Reuse the least-recently-used connection if at the limit
//
// Lock ordering convention (to avoid deadlocks):
//   ConnectionPool::mutex_ -> TlsContext::mutex_ -> TlsConnection::mutex_
class ConnectionPool {
public:
    // Construct a connection pool with the given configuration.
    explicit ConnectionPool(PoolConfig config = {});

    // Destructor. Shuts down and releases all managed connections.
    ~ConnectionPool();

    // Non-copyable, non-movable.
    ConnectionPool(const ConnectionPool&) = delete;
    ConnectionPool& operator=(const ConnectionPool&) = delete;
    ConnectionPool(ConnectionPool&&) = delete;
    ConnectionPool& operator=(ConnectionPool&&) = delete;

    // Acquire a connection for the given tunnel key.
    // Strategy: reuse idle -> create new (if under limit) -> reuse LRU (if at limit).
    // Returns nullptr if connection creation fails.
    // Thread-safe.
    std::shared_ptr<TlsConnection> acquire(const TunnelKey& key, TlsContext& ctx);

    // Release a connection back to the pool for future reuse.
    // Updates the tunnel's last_used timestamp.
    // Thread-safe.
    void release(const TunnelKey& key, std::shared_ptr<TlsConnection> conn);

    // Remove a specific connection from the pool (e.g., on error).
    // Thread-safe.
    void remove(const TunnelKey& key, std::shared_ptr<TlsConnection> conn);

    // Remove all connections for a given tunnel key.
    // Thread-safe.
    void remove_tunnel(const TunnelKey& key);

    // Clean up idle connections that have exceeded idle_timeout_sec.
    // Iterates all tunnels and removes timed-out connections.
    // Thread-safe.
    void cleanup_idle();

    // Get a snapshot of pool statistics.
    // Thread-safe.
    PoolStats stats() const;

    // Thread-safe iteration over all connections.
    // The callback receives each TunnelKey and its associated TlsConnection.
    // The pool mutex is held during iteration; keep callbacks short.
    void for_each(std::function<void(const TunnelKey&, TlsConnection&)> fn);

private:
    // Internal state for each tunnel.
    struct TunnelEntry {
        std::vector<std::shared_ptr<TlsConnection>> connections;
        std::chrono::steady_clock::time_point last_used;
    };

    // Create a new TCP + TLS connection to the target specified by key.
    // Performs DNS resolution, TCP connect, and TLS handshake.
    // Returns nullptr on failure.
    std::shared_ptr<TlsConnection> create_connection(const TunnelKey& key, TlsContext& ctx);

    PoolConfig config_;
    std::unordered_map<TunnelKey, TunnelEntry, TunnelKeyHash> tunnels_;
    mutable std::mutex mutex_;
};

} // namespace gtls

#endif // GTLS_CONNECTION_POOL_H
