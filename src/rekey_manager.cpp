// =============================================================================
// Generic TLS Library (gtls) - Rekey Manager implementation
// =============================================================================

#include "gtls/rekey_manager.h"
#include "gtls/logger.h"

#include <openssl/ssl.h>

#include <chrono>

namespace gtls {

using std::chrono::steady_clock;
using std::chrono::duration_cast;
using std::chrono::seconds;

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

RekeyManager::RekeyManager(int interval_sec)
    : interval_sec_(interval_sec) {}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

bool RekeyManager::check_and_rekey(TlsConnection& conn) {
    SSL* ssl = conn.ssl();
    if (!ssl) {
        Logger::log(LogLevel::Error,
                    "RekeyManager::check_and_rekey: connection has no SSL object");
        return false;
    }

    // Calculate elapsed time since connection was established.
    auto now = steady_clock::now();
    auto elapsed = duration_cast<seconds>(now - conn.connect_time()).count();

    if (elapsed <= interval_sec_) {
        // Not yet time to rekey.
        return false;
    }

    // Elapsed time exceeds interval — trigger key update.
    Logger::log(LogLevel::Debug,
                "RekeyManager::check_and_rekey: triggering key update "
                "(elapsed=%ld sec, interval=%d sec)",
                static_cast<long>(elapsed), interval_sec_);

    int ret = SSL_key_update(ssl, SSL_KEY_UPDATE_REQUESTED);
    if (ret != 1) {
        Logger::log(LogLevel::Warning,
                    "RekeyManager::check_and_rekey: SSL_key_update failed");
        // Return true because the condition was met, even though the
        // actual key update call failed. The caller can decide how to
        // handle the failure.
        return true;
    }

    Logger::log(LogLevel::Debug,
                "RekeyManager::check_and_rekey: key update requested successfully");
    return true;
}

int RekeyManager::interval_sec() const {
    return interval_sec_;
}

} // namespace gtls
