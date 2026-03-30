// =============================================================================
// Generic TLS Library (gtls) - TLS configuration data structure
// Manages TLS parameters including certificates, keys, cipher suites,
// protocol versions, and provides validation for configuration consistency.
// =============================================================================
#ifndef GTLS_TLS_CONFIG_H
#define GTLS_TLS_CONFIG_H

#include <string>
#include <vector>

namespace gtls {

// TLS configuration structure holding all parameters needed to create
// an SSL context. Corresponds to radsecproxy's struct tls config fields.
struct TlsConfig {
    // CA and certificate paths
    std::string ca_cert_file;       // CACertificateFile (required for mTLS)
    std::string ca_cert_path;       // CACertificatePath (alternative to ca_cert_file)
    std::string cert_file;          // CertificateFile (required for mTLS)
    std::string cert_key_file;      // CertificateKeyFile (required for mTLS)
    std::string cert_key_password;  // CertificateKeyPassword (optional)

    // Verification options (optional)
    bool crl_check = false;                    // CRLCheck
    std::vector<std::string> policy_oids;      // PolicyOID

    // Cipher configuration (optional, defaults to OpenSSL defaults)
    std::string cipher_list;        // CipherList (TLS 1.2)
    std::string cipher_suites;      // CipherSuites (TLS 1.3)

    // Protocol version range (optional, -1 means use OpenSSL default)
    int tls_min_version = -1;       // TlsVersion min
    int tls_max_version = -1;       // TlsVersion max

    // DH parameters (optional, server-side DHE only)
    std::string dh_param_file;      // DhFile

    // Cache expiry in seconds, -1 means no caching
    int cache_expiry = -1;          // CacheExpiry

    // Validate configuration consistency.
    // Returns empty string on success, error message on failure.
    // Checks:
    //   - cert_file and cert_key_file must both be set (Req 1.4)
    //   - If cert_file is set, cert_key_file must also be set (Req 1.2)
    //   - If cert_file is set, at least one of ca_cert_file or ca_cert_path
    //     must be set (Req 1.3)
    std::string validate() const;

    // Equality comparison for round-trip serialization testing.
    // Compares ALL fields to ensure complete fidelity.
    bool operator==(const TlsConfig& other) const;
    bool operator!=(const TlsConfig& other) const;
};

} // namespace gtls

#endif // GTLS_TLS_CONFIG_H
