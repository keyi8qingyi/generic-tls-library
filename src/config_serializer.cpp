// =============================================================================
// Generic TLS Library (gtls) - Configuration serializer implementation
// =============================================================================

#include "gtls/config_serializer.h"

#include <sstream>

namespace gtls {

std::string ConfigSerializer::serialize(const TlsConfig& config) {
    std::ostringstream out;

    // Serialize string fields (only if non-empty)
    if (!config.ca_cert_file.empty()) {
        out << "ca_cert_file = " << config.ca_cert_file << "\n";
    }
    if (!config.ca_cert_path.empty()) {
        out << "ca_cert_path = " << config.ca_cert_path << "\n";
    }
    if (!config.cert_file.empty()) {
        out << "cert_file = " << config.cert_file << "\n";
    }
    if (!config.cert_key_file.empty()) {
        out << "cert_key_file = " << config.cert_key_file << "\n";
    }
    if (!config.cert_key_password.empty()) {
        out << "cert_key_password = " << config.cert_key_password << "\n";
    }

    // Serialize boolean (only if non-default, i.e. true)
    if (config.crl_check) {
        out << "crl_check = true\n";
    }

    // Serialize policy_oids (only if non-empty)
    if (!config.policy_oids.empty()) {
        out << "policy_oids = ";
        for (std::size_t i = 0; i < config.policy_oids.size(); ++i) {
            if (i > 0) out << ",";
            out << config.policy_oids[i];
        }
        out << "\n";
    }

    // Serialize cipher configuration (only if non-empty)
    if (!config.cipher_list.empty()) {
        out << "cipher_list = " << config.cipher_list << "\n";
    }
    if (!config.cipher_suites.empty()) {
        out << "cipher_suites = " << config.cipher_suites << "\n";
    }

    // Serialize version range (only if non-default, i.e. not -1)
    if (config.tls_min_version != -1) {
        out << "tls_min_version = " << config.tls_min_version << "\n";
    }
    if (config.tls_max_version != -1) {
        out << "tls_max_version = " << config.tls_max_version << "\n";
    }

    // Serialize DH param file (only if non-empty)
    if (!config.dh_param_file.empty()) {
        out << "dh_param_file = " << config.dh_param_file << "\n";
    }

    // Serialize cache expiry (only if non-default, i.e. not -1)
    if (config.cache_expiry != -1) {
        out << "cache_expiry = " << config.cache_expiry << "\n";
    }

    return out.str();
}

} // namespace gtls
