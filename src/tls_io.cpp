// =============================================================================
// Generic TLS Library (gtls) - TLS I/O implementation
// =============================================================================

#include "gtls/tls_io.h"
#include "gtls/logger.h"

#include <openssl/err.h>

#include <poll.h>

namespace gtls {

// ---------------------------------------------------------------------------
// Helper: get the underlying socket fd from an SSL object.
// ---------------------------------------------------------------------------
static int get_ssl_fd(SSL* ssl) {
    return SSL_get_fd(ssl);
}

// ---------------------------------------------------------------------------
// Helper: check socket for errors using poll with zero timeout.
// Returns true if socket has an error condition.
// ---------------------------------------------------------------------------
static bool check_socket_error(int fd) {
    struct pollfd pfd = {};
    pfd.fd = fd;
    pfd.events = 0;  // Only check for error conditions in revents

    int ret = ::poll(&pfd, 1, 0);
    if (ret > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// TlsIO::read
// ---------------------------------------------------------------------------
int TlsIO::read(SSL* ssl, unsigned char* buf, int num,
                int timeout_sec, std::mutex* lock) {
    if (!ssl || !buf || num <= 0) {
        return -1;
    }

    int fd = get_ssl_fd(ssl);
    if (fd < 0) {
        Logger::log(LogLevel::Error, "TlsIO::read: invalid socket fd");
        return -1;
    }

    // If timeout_sec > 0, wait for data availability with poll first.
    if (timeout_sec > 0) {
        struct pollfd pfd = {};
        pfd.fd = fd;
        pfd.events = POLLIN;

        int poll_ret = ::poll(&pfd, 1, timeout_sec * 1000);

        if (poll_ret == 0) {
            // Timeout — no data available.
            return 0;
        }

        if (poll_ret < 0) {
            Logger::log(LogLevel::Error,
                        "TlsIO::read: poll() failed with errno %d", errno);
            return -1;
        }

        // Check for socket error conditions.
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            Logger::log(LogLevel::Error,
                        "TlsIO::read: socket error detected (revents=0x%x)",
                        pfd.revents);
            return -1;
        }
    }

    // Perform SSL_read, handling WANT_READ/WRITE by retrying with poll.
    while (true) {
        int ret;

        if (lock) {
            std::lock_guard<std::mutex> guard(*lock);
            ret = SSL_read(ssl, buf, num);
        } else {
            ret = SSL_read(ssl, buf, num);
        }

        if (ret > 0) {
            return ret;
        }

        int err = SSL_get_error(ssl, ret);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // SSL needs to retry — wait for socket readiness.
            struct pollfd pfd = {};
            pfd.fd = fd;
            pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;

            // Use the original timeout for the retry poll.
            // timeout_sec == 0 means blocking, so pass -1 to poll (infinite).
            int poll_timeout_ms = (timeout_sec > 0) ? (timeout_sec * 1000) : -1;
            int poll_ret = ::poll(&pfd, 1, poll_timeout_ms);

            if (poll_ret == 0) {
                // Timeout during retry.
                return 0;
            }

            if (poll_ret < 0) {
                Logger::log(LogLevel::Error,
                            "TlsIO::read: poll() failed during retry, errno %d",
                            errno);
                return -1;
            }

            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                Logger::log(LogLevel::Error,
                            "TlsIO::read: socket error during retry (revents=0x%x)",
                            pfd.revents);
                return -1;
            }

            // Socket ready, retry SSL_read.
            continue;
        }

        if (err == SSL_ERROR_ZERO_RETURN) {
            // Peer performed an orderly shutdown.
            Logger::log(LogLevel::Debug,
                        "TlsIO::read: SSL_ERROR_ZERO_RETURN, performing shutdown");
            SSL_shutdown(ssl);
            return -1;
        }

        // Any other error is fatal.
        unsigned long ssl_err = ERR_peek_last_error();
        Logger::log(LogLevel::Error,
                    "TlsIO::read: SSL_read failed, SSL error %d, ERR=%lu (%s)",
                    err, ssl_err,
                    ERR_error_string(ssl_err, nullptr));
        return -1;
    }
}

// ---------------------------------------------------------------------------
// TlsIO::write
// ---------------------------------------------------------------------------
int TlsIO::write(SSL* ssl, const void* buf, int num, bool blocking) {
    if (!ssl || !buf || num <= 0) {
        return -1;
    }

    int fd = get_ssl_fd(ssl);
    if (fd < 0) {
        Logger::log(LogLevel::Error, "TlsIO::write: invalid socket fd");
        return -1;
    }

    const auto* data = static_cast<const unsigned char*>(buf);
    int total_written = 0;

    while (total_written < num) {
        // Check for socket errors before writing.
        if (check_socket_error(fd)) {
            Logger::log(LogLevel::Error,
                        "TlsIO::write: socket error detected before SSL_write");
            return -1;
        }

        int ret = SSL_write(ssl, data + total_written, num - total_written);

        if (ret > 0) {
            total_written += ret;
            if (!blocking) {
                // Non-blocking: return after first successful write.
                return total_written;
            }
            // Blocking: continue until all data is written.
            continue;
        }

        int err = SSL_get_error(ssl, ret);

        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            // SSL needs to retry — wait for socket readiness.
            struct pollfd pfd = {};
            pfd.fd = fd;
            pfd.events = (err == SSL_ERROR_WANT_WRITE) ? POLLOUT : POLLIN;

            int poll_ret = ::poll(&pfd, 1, -1);  // Block until ready.

            if (poll_ret < 0) {
                Logger::log(LogLevel::Error,
                            "TlsIO::write: poll() failed, errno %d", errno);
                return -1;
            }

            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                Logger::log(LogLevel::Error,
                            "TlsIO::write: socket error during poll (revents=0x%x)",
                            pfd.revents);
                return -1;
            }

            // Socket ready, retry SSL_write.
            continue;
        }

        // Fatal SSL error.
        unsigned long ssl_err = ERR_peek_last_error();
        Logger::log(LogLevel::Error,
                    "TlsIO::write: SSL_write failed, SSL error %d, ERR=%lu (%s)",
                    err, ssl_err,
                    ERR_error_string(ssl_err, nullptr));
        return -1;
    }

    return total_written;
}

} // namespace gtls
