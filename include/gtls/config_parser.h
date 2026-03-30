// =============================================================================
// Generic TLS Library (gtls) - Configuration parser
// Parses key-value text format into TlsConfig objects.
// Format: "key = value\n" per line, supports comments (#) and blank lines.
// =============================================================================
#ifndef GTLS_CONFIG_PARSER_H
#define GTLS_CONFIG_PARSER_H

#include <string>
#include "gtls/tls_config.h"

namespace gtls {

// Result type for parse operations (C++17 alternative to std::expected)
struct ParseResult {
    TlsConfig config;   // Parsed configuration (valid when error is empty)
    std::string error;   // Error message (empty on success)

    // Convenience check for success
    bool ok() const { return error.empty(); }
};

// Parses key-value text into TlsConfig.
// Supported keys: ca_cert_file, ca_cert_path, cert_file, cert_key_file,
//   cert_key_password, crl_check, policy_oids, cipher_list, cipher_suites,
//   tls_min_version, tls_max_version, dh_param_file, cache_expiry
class ConfigParser {
public:
    // Parse key-value text into TlsConfig.
    // Returns ParseResult with config on success, or error message on failure.
    static ParseResult parse(const std::string& text);
};

} // namespace gtls

#endif // GTLS_CONFIG_PARSER_H
