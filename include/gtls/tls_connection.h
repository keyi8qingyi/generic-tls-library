// =============================================================================
// Generic TLS Library (gtls) - TLS connection management
// Manages SSL object lifecycle, TLS handshake (client/server), and shutdown.
// Corresponds to radsecproxy's tlsconnect/tlsservernew/cleanup_connection.
// =============================================================================
#ifndef GTLS_TLS_CONNECTION_H
#define GTLS_TLS_CONNECTION_H

#include <chrono>
#include <memory>
#include <mutex>
#include <string>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "gtls/tls_context.h"

namespace gtls {

// Custom deleter for SSL object, enabling RAII via std::unique_ptr.
struct SslDeleter {
    void operator()(SSL* ssl) const {
        if (ssl) {
            SSL_free(ssl);
        }
    }
};

// RAII smart pointer for SSL. Automatically calls SSL_free on destruction.
using SslPtr = std::unique_ptr<SSL, SslDeleter>;

// Connection state machine.
enum class ConnState {
    Disconnected,   // No active SSL session
    Connecting,     // Handshake in progress
    Connected,      // Handshake complete, ready for I/O
    Failing         // Error state, connection should be cleaned up
};

// Manages a single TLS connection (SSL object) bound to a socket.
// Supports both client-side (connect) and server-side (accept) handshakes
// with non-blocking poll-based timeout control.
class TlsConnection {
public:
    // Construct a TlsConnection from the given TlsContext and socket fd.
    // The socket is NOT owned by TlsConnection; the caller manages its lifecycle.
    // However, shutdown() will close the socket as part of cleanup.
    TlsConnection(TlsContext& ctx, int sock);

    // Destructor. Performs shutdown if still connected.
    ~TlsConnection();

    // Non-copyable, non-movable (due to mutex and SSL state).
    TlsConnection(const TlsConnection&) = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;
    TlsConnection(TlsConnection&&) = delete;
    TlsConnection& operator=(TlsConnection&&) = delete;

    // Client-side TLS handshake with timeout (seconds).
    // Optionally sets SNI (Server Name Indication) hostname.
    // Uses non-blocking SSL_connect + poll loop for timeout control.
    // Returns true on successful handshake, false on failure or timeout.
    bool connect(int timeout_sec, const std::string& sni = "");

    // Server-side TLS handshake with timeout (seconds).
    // Uses non-blocking SSL_accept + poll loop for timeout control.
    // Returns true on successful handshake, false on failure or timeout.
    bool accept(int timeout_sec);

    // Get the underlying SSL pointer (for I/O operations).
    // Returns nullptr if no SSL object exists.
    SSL* ssl() const;

    // Get the current connection state.
    ConnState state() const;

    // Graceful shutdown: SSL_shutdown -> close(sock) -> release SSL.
    // After shutdown, state is Disconnected and ssl() returns nullptr.
    void shutdown();

    // Get peer certificate. Caller takes ownership of the returned pointer
    // and must call X509_free() when done. Returns nullptr if unavailable.
    X509* get_peer_certificate() const;

    // Get the timestamp when the connection was established.
    std::chrono::steady_clock::time_point connect_time() const;

    // Get the mutex for thread-safe access to this connection.
    std::mutex& mutex();

    // Check if the TLS connection is still alive and usable.
    // Performs a non-destructive check using SSL_peek with zero timeout.
    // Returns true if the connection appears healthy, false if broken.
    bool is_alive() const;

private:
    // Perform non-blocking SSL handshake with poll-based timeout.
    // handshake_fn is either SSL_connect or SSL_accept.
    // Returns true on success, false on failure or timeout.
    bool do_handshake(int timeout_sec,
                      int (*handshake_fn)(SSL*),
                      const char* op_name);

    // Clean up SSL and socket resources on handshake failure.
    void cleanup_on_failure();

    TlsContext& ctx_;
    SslPtr ssl_;
    int sock_;
    ConnState state_ = ConnState::Disconnected;
    std::chrono::steady_clock::time_point connect_time_;
    mutable std::mutex mutex_;
};

} // namespace gtls

#endif // GTLS_TLS_CONNECTION_H
