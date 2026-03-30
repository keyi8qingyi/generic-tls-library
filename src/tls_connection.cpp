// =============================================================================
// Generic TLS Library (gtls) - TLS connection implementation
// =============================================================================

#include "gtls/tls_connection.h"
#include "gtls/logger.h"

#include <openssl/err.h>

#include <poll.h>
#include <unistd.h>

#include <chrono>

namespace gtls {

using std::chrono::steady_clock;
using std::chrono::seconds;
using std::chrono::milliseconds;
using std::chrono::duration_cast;

// ---------------------------------------------------------------------------
// Construction / Destruction
// ---------------------------------------------------------------------------

TlsConnection::TlsConnection(TlsContext& ctx, int sock)
    : ctx_(ctx), sock_(sock) {}

TlsConnection::~TlsConnection() {
    shutdown();
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

bool TlsConnection::connect(int timeout_sec, const std::string& sni) {
    // Obtain SSL_CTX from the TlsContext.
    SSL_CTX* ssl_ctx = ctx_.get_ctx();
    if (!ssl_ctx) {
        Logger::log(LogLevel::Error,
                    "TlsConnection::connect: failed to get SSL_CTX from TlsContext");
        state_ = ConnState::Failing;
        return false;
    }

    // Create a new SSL object and bind it to the socket.
    ssl_.reset(SSL_new(ssl_ctx));
    if (!ssl_) {
        Logger::log(LogLevel::Error,
                    "TlsConnection::connect: SSL_new() failed");
        state_ = ConnState::Failing;
        return false;
    }

    if (!SSL_set_fd(ssl_.get(), sock_)) {
        Logger::log(LogLevel::Error,
                    "TlsConnection::connect: SSL_set_fd() failed");
        cleanup_on_failure();
        return false;
    }

    // Set SNI hostname if provided.
    if (!sni.empty()) {
        if (!SSL_set_tlsext_host_name(ssl_.get(), sni.c_str())) {
            Logger::log(LogLevel::Error,
                        "TlsConnection::connect: SSL_set_tlsext_host_name() failed for: %s",
                        sni.c_str());
            cleanup_on_failure();
            return false;
        }
    }

    return do_handshake(timeout_sec, SSL_connect, "connect");
}

bool TlsConnection::accept(int timeout_sec) {
    // Obtain SSL_CTX from the TlsContext.
    SSL_CTX* ssl_ctx = ctx_.get_ctx();
    if (!ssl_ctx) {
        Logger::log(LogLevel::Error,
                    "TlsConnection::accept: failed to get SSL_CTX from TlsContext");
        state_ = ConnState::Failing;
        return false;
    }

    // Create a new SSL object and bind it to the socket.
    ssl_.reset(SSL_new(ssl_ctx));
    if (!ssl_) {
        Logger::log(LogLevel::Error,
                    "TlsConnection::accept: SSL_new() failed");
        state_ = ConnState::Failing;
        return false;
    }

    if (!SSL_set_fd(ssl_.get(), sock_)) {
        Logger::log(LogLevel::Error,
                    "TlsConnection::accept: SSL_set_fd() failed");
        cleanup_on_failure();
        return false;
    }

    return do_handshake(timeout_sec, SSL_accept, "accept");
}

SSL* TlsConnection::ssl() const {
    return ssl_.get();
}

ConnState TlsConnection::state() const {
    return state_;
}

void TlsConnection::shutdown() {
    if (ssl_) {
        SSL_shutdown(ssl_.get());
    }
    if (sock_ >= 0) {
        ::close(sock_);
        sock_ = -1;
    }
    ssl_.reset();
    state_ = ConnState::Disconnected;
}

X509* TlsConnection::get_peer_certificate() const {
    if (!ssl_) {
        return nullptr;
    }
    return SSL_get1_peer_certificate(ssl_.get());
}

std::chrono::steady_clock::time_point TlsConnection::connect_time() const {
    return connect_time_;
}

std::mutex& TlsConnection::mutex() {
    return mutex_;
}

bool TlsConnection::is_alive() const {
    if (!ssl_ || state_ != ConnState::Connected) {
        return false;
    }

    // Use poll() with zero timeout to check socket health without blocking.
    int fd = SSL_get_fd(ssl_.get());
    if (fd < 0) {
        return false;
    }

    struct pollfd pfd = {};
    pfd.fd = fd;
    pfd.events = POLLIN;

    int ret = ::poll(&pfd, 1, 0);

    // Socket error conditions mean the connection is broken.
    if (ret > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
        Logger::log(LogLevel::Debug,
                    "TlsConnection::is_alive: socket error detected (revents=0x%x)",
                    pfd.revents);
        return false;
    }

    // If data is available, try SSL_peek to verify TLS layer is healthy.
    if (ret > 0 && (pfd.revents & POLLIN)) {
        unsigned char peek_buf[1];
        int peek_ret = SSL_peek(ssl_.get(), peek_buf, 1);
        if (peek_ret <= 0) {
            int err = SSL_get_error(ssl_.get(), peek_ret);
            // WANT_READ is normal (no data yet), anything else is broken.
            if (err != SSL_ERROR_WANT_READ) {
                Logger::log(LogLevel::Debug,
                            "TlsConnection::is_alive: SSL_peek failed, error=%d", err);
                return false;
            }
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

bool TlsConnection::do_handshake(int timeout_sec,
                                  int (*handshake_fn)(SSL*),
                                  const char* op_name) {
    state_ = ConnState::Connecting;

    auto deadline = steady_clock::now() + seconds(timeout_sec);

    while (true) {
        int ret = handshake_fn(ssl_.get());

        if (ret == 1) {
            // Handshake completed successfully.
            state_ = ConnState::Connected;
            connect_time_ = steady_clock::now();
            Logger::log(LogLevel::Debug,
                        "TlsConnection::%s: handshake completed successfully", op_name);
            return true;
        }

        int err = SSL_get_error(ssl_.get(), ret);

        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // Need to wait for socket readiness.
            auto now = steady_clock::now();
            auto remaining = duration_cast<milliseconds>(deadline - now);

            if (remaining.count() <= 0) {
                Logger::log(LogLevel::Error,
                            "TlsConnection::%s: handshake timed out after %d seconds",
                            op_name, timeout_sec);
                cleanup_on_failure();
                return false;
            }

            struct pollfd pfd = {};
            pfd.fd = sock_;
            pfd.events = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;

            int poll_ret = ::poll(&pfd, 1, static_cast<int>(remaining.count()));

            if (poll_ret < 0) {
                Logger::log(LogLevel::Error,
                            "TlsConnection::%s: poll() failed with errno %d",
                            op_name, errno);
                cleanup_on_failure();
                return false;
            }

            if (poll_ret == 0) {
                // poll timed out
                Logger::log(LogLevel::Error,
                            "TlsConnection::%s: handshake timed out (poll)",
                            op_name);
                cleanup_on_failure();
                return false;
            }

            // Check for socket errors reported by poll.
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                Logger::log(LogLevel::Error,
                            "TlsConnection::%s: socket error during handshake (revents=0x%x)",
                            op_name, pfd.revents);
                cleanup_on_failure();
                return false;
            }

            // Socket is ready, retry handshake.
            continue;
        }

        // Fatal SSL error.
        unsigned long ssl_err = ERR_peek_last_error();
        Logger::log(LogLevel::Error,
                    "TlsConnection::%s: handshake failed with SSL error %d, ERR=%lu (%s)",
                    op_name, err, ssl_err,
                    ERR_error_string(ssl_err, nullptr));
        cleanup_on_failure();
        return false;
    }
}

void TlsConnection::cleanup_on_failure() {
    ssl_.reset();
    if (sock_ >= 0) {
        ::close(sock_);
        sock_ = -1;
    }
    state_ = ConnState::Failing;
}

} // namespace gtls
