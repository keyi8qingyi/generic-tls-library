// =============================================================================
// Generic TLS Library (gtls) - Error classification
// Provides structured error types for TLS operations, replacing raw bool/int
// returns with machine-readable error codes for better diagnostics.
// =============================================================================
#ifndef GTLS_TLS_ERROR_H
#define GTLS_TLS_ERROR_H

#include <string>

namespace gtls {

// Categorized error codes for TLS operations.
enum class TlsError {
    Ok = 0,             // No error
    Timeout,            // Operation timed out
    ConnectionClosed,   // Peer performed orderly shutdown (SSL_ERROR_ZERO_RETURN)
    HandshakeFailed,    // TLS handshake failed
    CertificateError,   // Certificate verification failed
    SocketError,        // Underlying socket error (POLLERR/POLLHUP/POLLNVAL)
    SslError,           // Generic OpenSSL error (check ERR_get_error)
    InvalidArgument,    // Null pointer or invalid parameter
    PoolExhausted,      // Connection pool at capacity, no idle connections
    DnsResolutionFailed,// DNS lookup failed
    TcpConnectFailed,   // TCP connect() failed
    ConnectionBroken,   // Connection health check failed
    InternalError       // Unexpected internal error
};

// Convert TlsError to a human-readable string for logging/debugging.
inline const char* tls_error_to_string(TlsError err) {
    switch (err) {
        case TlsError::Ok:                  return "Ok";
        case TlsError::Timeout:             return "Timeout";
        case TlsError::ConnectionClosed:    return "ConnectionClosed";
        case TlsError::HandshakeFailed:     return "HandshakeFailed";
        case TlsError::CertificateError:    return "CertificateError";
        case TlsError::SocketError:         return "SocketError";
        case TlsError::SslError:            return "SslError";
        case TlsError::InvalidArgument:     return "InvalidArgument";
        case TlsError::PoolExhausted:       return "PoolExhausted";
        case TlsError::DnsResolutionFailed: return "DnsResolutionFailed";
        case TlsError::TcpConnectFailed:    return "TcpConnectFailed";
        case TlsError::ConnectionBroken:    return "ConnectionBroken";
        case TlsError::InternalError:       return "InternalError";
    }
    return "Unknown";
}

} // namespace gtls

#endif // GTLS_TLS_ERROR_H
