// =============================================================================
// Generic TLS Library (gtls) - TLS configuration implementation
// =============================================================================

#include "gtls/tls_config.h"

namespace gtls {

std::string TlsConfig::validate() const {
    // Req 1.4: Both cert_file and cert_key_file must be provided.
    // Certificate authentication is mandatory.
    if (cert_file.empty() && cert_key_file.empty()) {
        return "cert_file and cert_key_file are both required "
               "(certificate authentication is mandatory)";
    }

    // Req 1.2: If cert_file is set, cert_key_file must also be set.
    if (!cert_file.empty() && cert_key_file.empty()) {
        return "cert_key_file is required when cert_file is specified";
    }

    // Also check the reverse: key without cert makes no sense.
    if (cert_file.empty() && !cert_key_file.empty()) {
        return "cert_file is required when cert_key_file is specified";
    }

    // Req 1.3: If cert_file is set, at least one CA source must be provided.
    if (!cert_file.empty() &&
        ca_cert_file.empty() && ca_cert_path.empty()) {
        return "ca_cert_file or ca_cert_path is required "
               "when cert_file is specified";
    }

    return "";
}

bool TlsConfig::operator==(const TlsConfig& other) const {
    return ca_cert_file == other.ca_cert_file &&
           ca_cert_path == other.ca_cert_path &&
           cert_file == other.cert_file &&
           cert_key_file == other.cert_key_file &&
           cert_key_password == other.cert_key_password &&
           crl_check == other.crl_check &&
           policy_oids == other.policy_oids &&
           cipher_list == other.cipher_list &&
           cipher_suites == other.cipher_suites &&
           tls_min_version == other.tls_min_version &&
           tls_max_version == other.tls_max_version &&
           dh_param_file == other.dh_param_file &&
           cache_expiry == other.cache_expiry;
}

bool TlsConfig::operator!=(const TlsConfig& other) const {
    return !(*this == other);
}

} // namespace gtls
