// =============================================================================
// Generic TLS Library (gtls) - Protocol adapter implementation
// =============================================================================

#include "gtls/protocol_adapter.h"
#include "gtls/logger.h"
#include "gtls/tls_io.h"

#include <cstdlib>
#include <cstring>
#include <vector>

namespace gtls {

// Initial read buffer size for framed message reading.
static constexpr int kInitialBufSize = 4096;

// Maximum buffer size to prevent unbounded growth (16 MB).
static constexpr int kMaxBufSize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

ProtocolAdapter::ProtocolAdapter(const std::string& name)
    : name_(name) {}

// ---------------------------------------------------------------------------
// Callback registration
// ---------------------------------------------------------------------------

void ProtocolAdapter::set_frame_callback(FrameCallback cb) {
    frame_cb_ = std::move(cb);
}

void ProtocolAdapter::set_routing_callback(RoutingCallback cb) {
    routing_cb_ = std::move(cb);
}

void ProtocolAdapter::set_event_callback(EventCallback cb) {
    event_cb_ = std::move(cb);
}

void ProtocolAdapter::set_resolve_callback(ResolveCallback cb) {
    resolve_cb_ = std::move(cb);
}

// ---------------------------------------------------------------------------
// read_message()
// ---------------------------------------------------------------------------

int ProtocolAdapter::read_message(TlsConnection& conn, unsigned char** buf,
                                  int timeout_sec) {
    if (!buf) {
        return -1;
    }
    *buf = nullptr;

    SSL* ssl = conn.ssl();
    if (!ssl) {
        Logger::log(LogLevel::Error,
                    "ProtocolAdapter[%s]: read_message called with null SSL",
                    name_.c_str());
        return -1;
    }

    // --- Raw byte stream mode (no frame callback) ---
    if (!frame_cb_) {
        auto* raw_buf = static_cast<unsigned char*>(std::malloc(kInitialBufSize));
        if (!raw_buf) {
            Logger::log(LogLevel::Error,
                        "ProtocolAdapter[%s]: malloc failed for raw read buffer",
                        name_.c_str());
            return -1;
        }

        int n = TlsIO::read(ssl, raw_buf, kInitialBufSize, timeout_sec);
        if (n <= 0) {
            std::free(raw_buf);
            return n;  // 0 = timeout, -1 = error
        }

        *buf = raw_buf;
        return n;
    }

    // --- Framed message mode (frame callback registered) ---
    // Accumulate data until the frame callback reports a complete message.
    std::vector<unsigned char> accum;
    accum.reserve(kInitialBufSize);

    unsigned char tmp[kInitialBufSize];

    while (true) {
        // Check if accumulated data already contains a complete message.
        if (!accum.empty()) {
            int msg_len = frame_cb_(accum.data(),
                                    static_cast<int>(accum.size()));
            if (msg_len < 0) {
                // Framing error reported by callback.
                Logger::log(LogLevel::Error,
                            "ProtocolAdapter[%s]: frame callback returned error %d",
                            name_.c_str(), msg_len);
                return -1;
            }
            if (msg_len > 0) {
                // Complete message found. Allocate output buffer and copy.
                auto* out = static_cast<unsigned char*>(std::malloc(msg_len));
                if (!out) {
                    Logger::log(LogLevel::Error,
                                "ProtocolAdapter[%s]: malloc failed for message buffer",
                                name_.c_str());
                    return -1;
                }
                std::memcpy(out, accum.data(), msg_len);
                *buf = out;
                return msg_len;
            }
            // msg_len == 0: need more data, continue reading.
        }

        // Guard against unbounded buffer growth.
        if (static_cast<int>(accum.size()) >= kMaxBufSize) {
            Logger::log(LogLevel::Error,
                        "ProtocolAdapter[%s]: message buffer exceeded max size %d",
                        name_.c_str(), kMaxBufSize);
            return -1;
        }

        // Read more data from the TLS connection.
        int n = TlsIO::read(ssl, tmp, kInitialBufSize, timeout_sec);
        if (n <= 0) {
            // 0 = timeout, -1 = error/closed. Return as-is.
            return n;
        }

        accum.insert(accum.end(), tmp, tmp + n);
    }
}

// ---------------------------------------------------------------------------
// send()
// ---------------------------------------------------------------------------

int ProtocolAdapter::send(ConnectionPool& pool, TlsContext& ctx,
                          const unsigned char* data, int len,
                          TlsConnection* explicit_conn) {
    if (!data || len <= 0) {
        return -1;
    }

    // --- Routing callback mode ---
    if (routing_cb_) {
        TunnelKey key = routing_cb_(data, len);

        // Acquire a connection from the pool for this tunnel.
        auto conn = pool.acquire(key, ctx);
        if (!conn) {
            Logger::log(LogLevel::Error,
                        "ProtocolAdapter[%s]: failed to acquire connection for [%s:%u/%s]",
                        name_.c_str(), key.host.c_str(), key.port,
                        key.tls_config_name.c_str());
            return -1;
        }

        SSL* ssl = conn->ssl();
        if (!ssl) {
            Logger::log(LogLevel::Error,
                        "ProtocolAdapter[%s]: acquired connection has null SSL for [%s:%u/%s]",
                        name_.c_str(), key.host.c_str(), key.port,
                        key.tls_config_name.c_str());
            return -1;
        }

        return TlsIO::write(ssl, data, len, /*blocking=*/true);
    }

    // --- Explicit connection mode (no routing callback) ---
    if (!explicit_conn) {
        Logger::log(LogLevel::Error,
                    "ProtocolAdapter[%s]: send called without routing callback and no explicit connection",
                    name_.c_str());
        return -1;
    }

    SSL* ssl = explicit_conn->ssl();
    if (!ssl) {
        Logger::log(LogLevel::Error,
                    "ProtocolAdapter[%s]: explicit connection has null SSL",
                    name_.c_str());
        return -1;
    }

    return TlsIO::write(ssl, data, len, /*blocking=*/true);
}

// ---------------------------------------------------------------------------
// name()
// ---------------------------------------------------------------------------

const std::string& ProtocolAdapter::name() const {
    return name_;
}

} // namespace gtls
