// =============================================================================
// Generic TLS Library (gtls) - Protocol adapter interface
// Provides protocol-agnostic message framing, routing, and event callbacks.
// Allows upper-layer protocols (RADIUS, MQTT, HTTPS, gRPC, etc.) to integrate
// with the TLS library through callback registration.
// =============================================================================
#ifndef GTLS_PROTOCOL_ADAPTER_H
#define GTLS_PROTOCOL_ADAPTER_H

#include <functional>
#include <string>

#include "gtls/connection_pool.h"
#include "gtls/tls_connection.h"
#include "gtls/tls_context.h"

namespace gtls {

// Message framing callback: given raw bytes, determine complete message length.
// Returns:
//   >0  Complete message length (bytes) — the message is ready to be consumed
//    0  More data needed — continue reading
//   <0  Framing error — abort the read
using FrameCallback = std::function<int(const unsigned char* data, int len)>;

// Routing callback: given message data, return the target TunnelKey.
// Used by send() to determine which tunnel to route the message through.
using RoutingCallback = std::function<TunnelKey(const unsigned char* data, int len)>;

// Connection event types for event notification callbacks.
enum class ConnEvent {
    Connected,          // TCP + TLS connection established
    Disconnected,       // Connection closed or lost
    HandshakeComplete,  // TLS handshake completed successfully
    RekeyComplete       // TLS 1.3 key update completed
};

// Connection event callback: notified when connection state changes.
using EventCallback = std::function<void(ConnEvent event,
                                         const TunnelKey& key,
                                         TlsConnection& conn)>;

// Target address resolution callback: extract target server info from message data.
using ResolveCallback = std::function<TunnelKey(const unsigned char* data, int len)>;

// Protocol adapter for integrating upper-layer protocols with the TLS library.
// Each adapter instance is independent — modifying callbacks on one adapter
// does not affect other adapter instances.
//
// Usage pattern:
//   1. Create a ProtocolAdapter with a descriptive name
//   2. Register callbacks (frame, routing, event, resolve) as needed
//   3. Use read_message() to read protocol messages from a TLS connection
//   4. Use send() to send data through the appropriate tunnel
class ProtocolAdapter {
public:
    // Construct a protocol adapter with the given name.
    explicit ProtocolAdapter(const std::string& name);

    // Register a message framing callback.
    // When set, read_message() uses this callback to detect message boundaries
    // and returns complete protocol messages.
    void set_frame_callback(FrameCallback cb);

    // Register a routing callback.
    // When set, send() uses this callback to determine the target TunnelKey
    // from message content, then acquires a connection from the pool.
    void set_routing_callback(RoutingCallback cb);

    // Register a connection event callback.
    // Receives notifications for connection lifecycle events.
    void set_event_callback(EventCallback cb);

    // Register a target address resolution callback.
    // Used to extract target server information from message data.
    void set_resolve_callback(ResolveCallback cb);

    // Read a complete protocol message from the given TLS connection.
    //
    // If a frame callback is registered:
    //   Reads data into an internal buffer, calls the frame callback to detect
    //   message boundaries, and returns a complete message. The buffer is
    //   allocated with malloc(); the caller must free it with free().
    //
    // If no frame callback is registered:
    //   Performs a raw read via TlsIO::read() and returns whatever data is
    //   available. The buffer is allocated with malloc(); caller frees with free().
    //
    // Parameters:
    //   conn        - TLS connection to read from
    //   buf         - Output pointer; set to the allocated message buffer on success
    //   timeout_sec - Read timeout in seconds
    //
    // Returns:
    //   >0  Number of bytes in the complete message (or raw read)
    //    0  Timeout (no data available within timeout_sec)
    //   -1  Error or connection closed
    int read_message(TlsConnection& conn, unsigned char** buf,
                     int timeout_sec);

    // Send data through the appropriate TLS tunnel.
    //
    // If a routing callback is registered:
    //   Calls the routing callback to get the TunnelKey, acquires a connection
    //   from the pool, and writes the data via TlsIO::write().
    //
    // If no routing callback is registered:
    //   Uses the explicit_conn parameter to write the data directly.
    //   explicit_conn must not be nullptr in this case.
    //
    // Parameters:
    //   pool         - Connection pool for tunnel management
    //   ctx          - TLS context for creating new connections
    //   data         - Data buffer to send
    //   len          - Number of bytes to send
    //   explicit_conn - Explicit connection to use when no routing callback is set
    //
    // Returns:
    //   >0  Number of bytes written
    //   -1  Error (routing failure, connection acquisition failure, or write error)
    int send(ConnectionPool& pool, TlsContext& ctx,
             const unsigned char* data, int len,
             TlsConnection* explicit_conn = nullptr);

    // Get the adapter name.
    const std::string& name() const;

private:
    std::string name_;
    FrameCallback frame_cb_;
    RoutingCallback routing_cb_;
    EventCallback event_cb_;
    ResolveCallback resolve_cb_;
};

} // namespace gtls

#endif // GTLS_PROTOCOL_ADAPTER_H
