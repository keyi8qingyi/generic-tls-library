// =============================================================================
// Generic TLS Library (gtls) - TLS I/O operations
// Provides timeout-aware read/write over SSL connections with poll-based
// non-blocking I/O and optional mutex support for thread-safe access.
// Corresponds to radsecproxy's sslreadtimeout() and sslwrite().
// =============================================================================
#ifndef GTLS_TLS_IO_H
#define GTLS_TLS_IO_H

#include <mutex>

#include <openssl/ssl.h>

namespace gtls {

// Static utility class for TLS I/O operations on an established SSL connection.
// All methods are static — no instance state is maintained.
class TlsIO {
public:
    // Read data from an SSL connection with timeout control.
    //
    // Parameters:
    //   ssl         - Established SSL connection (must not be nullptr)
    //   buf         - Buffer to receive data
    //   num         - Maximum number of bytes to read
    //   timeout_sec - Timeout in seconds; 0 means blocking (wait indefinitely)
    //   lock        - Optional mutex for thread-safe access to the SSL object
    //
    // Returns:
    //   >0  Number of bytes actually read
    //    0  Timeout expired (no data available within timeout_sec)
    //   -1  Error or connection closed (SSL_ERROR_ZERO_RETURN triggers shutdown)
    //
    // Handles SSL_ERROR_WANT_READ/WRITE by retrying with poll().
    // Handles SSL_ERROR_ZERO_RETURN by calling SSL_shutdown().
    static int read(SSL* ssl, unsigned char* buf, int num,
                    int timeout_sec, std::mutex* lock = nullptr);

    // Write data to an SSL connection.
    //
    // Parameters:
    //   ssl      - Established SSL connection (must not be nullptr)
    //   buf      - Data buffer to send
    //   num      - Number of bytes to write
    //   blocking - If true, loop until all bytes are written or error occurs
    //
    // Returns:
    //   >0  Number of bytes written (equals num in blocking mode on success)
    //   -1  Error (socket error detected via poll or SSL_write failure)
    //
    // In blocking mode, loops SSL_write until all data is sent.
    // Checks for socket errors (POLLERR/POLLHUP/POLLNVAL) via poll().
    static int write(SSL* ssl, const void* buf, int num,
                     bool blocking = true);
};

} // namespace gtls

#endif // GTLS_TLS_IO_H
