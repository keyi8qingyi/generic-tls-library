// =============================================================================
// Generic TLS Library (gtls) - Rekey Manager
// Manages TLS 1.3 key rotation for long-lived connections.
// Corresponds to radsecproxy's RSP_TLS_REKEY_INTERVAL logic in
// clientradputtls() and tlsserverwr().
// =============================================================================
#ifndef GTLS_REKEY_MANAGER_H
#define GTLS_REKEY_MANAGER_H

#include "gtls/tls_connection.h"

namespace gtls {

// Manages periodic TLS 1.3 key updates for long-lived connections.
// When the connection has been alive longer than the configured interval,
// check_and_rekey() triggers an SSL_key_update request.
class RekeyManager {
public:
    // Construct with a rekey interval in seconds.
    // Default interval is 3600 seconds (1 hour), matching radsecproxy's
    // RSP_TLS_REKEY_INTERVAL.
    explicit RekeyManager(int interval_sec = 3600);

    // Check if the connection needs rekeying and perform it if so.
    // Compares the connection's connect_time with the current time.
    // If elapsed time exceeds interval_sec_, calls SSL_key_update().
    //
    // Returns:
    //   true  - rekey was triggered (elapsed > interval)
    //   false - rekey not needed (elapsed <= interval) or error
    bool check_and_rekey(TlsConnection& conn);

    // Get the configured rekey interval in seconds.
    int interval_sec() const;

private:
    int interval_sec_;
};

} // namespace gtls

#endif // GTLS_REKEY_MANAGER_H
