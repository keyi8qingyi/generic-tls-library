// =============================================================================
// Generic TLS Library (gtls) - Configuration parser implementation
// =============================================================================

#include "gtls/config_parser.h"

#include <algorithm>
#include <sstream>

namespace gtls {
namespace {

// Trim leading and trailing whitespace from a string
std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r");
    return s.substr(start, end - start + 1);
}

// Split a string by delimiter, trimming each element
std::vector<std::string> split_and_trim(const std::string& s, char delim) {
    std::vector<std::string> result;
    std::istringstream stream(s);
    std::string item;
    while (std::getline(stream, item, delim)) {
        auto trimmed = trim(item);
        if (!trimmed.empty()) {
            result.push_back(trimmed);
        }
    }
    return result;
}

// Parse a boolean value from string ("true"/"1" -> true, "false"/"0" -> false)
// Returns -1 on invalid input, 0 for false, 1 for true
int parse_bool(const std::string& value) {
    if (value == "true" || value == "1") return 1;
    if (value == "false" || value == "0") return 0;
    return -1;
}

// Parse an integer value from string, returns false on failure
bool parse_int(const std::string& value, int& out) {
    try {
        std::size_t pos = 0;
        out = std::stoi(value, &pos);
        return pos == value.size();
    } catch (...) {
        return false;
    }
}

} // anonymous namespace

ParseResult ConfigParser::parse(const std::string& text) {
    ParseResult result;
    std::istringstream stream(text);
    std::string line;
    int line_num = 0;

    while (std::getline(stream, line)) {
        line_num++;
        auto trimmed = trim(line);

        // Skip empty lines and comments
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }

        // Find the '=' separator
        auto eq_pos = trimmed.find('=');
        if (eq_pos == std::string::npos) {
            result.error = "line " + std::to_string(line_num) +
                           ": missing '=' separator";
            return result;
        }

        auto key = trim(trimmed.substr(0, eq_pos));
        auto value = trim(trimmed.substr(eq_pos + 1));

        if (key.empty()) {
            result.error = "line " + std::to_string(line_num) +
                           ": empty key";
            return result;
        }

        // Map key to TlsConfig field
        if (key == "ca_cert_file") {
            result.config.ca_cert_file = value;
        } else if (key == "ca_cert_path") {
            result.config.ca_cert_path = value;
        } else if (key == "cert_file") {
            result.config.cert_file = value;
        } else if (key == "cert_key_file") {
            result.config.cert_key_file = value;
        } else if (key == "cert_key_password") {
            result.config.cert_key_password = value;
        } else if (key == "crl_check") {
            int b = parse_bool(value);
            if (b < 0) {
                result.error = "line " + std::to_string(line_num) +
                               ": invalid boolean value '" + value + "'";
                return result;
            }
            result.config.crl_check = (b == 1);
        } else if (key == "policy_oids") {
            result.config.policy_oids = split_and_trim(value, ',');
        } else if (key == "cipher_list") {
            result.config.cipher_list = value;
        } else if (key == "cipher_suites") {
            result.config.cipher_suites = value;
        } else if (key == "tls_min_version") {
            int v;
            if (!parse_int(value, v)) {
                result.error = "line " + std::to_string(line_num) +
                               ": invalid integer value '" + value + "'";
                return result;
            }
            result.config.tls_min_version = v;
        } else if (key == "tls_max_version") {
            int v;
            if (!parse_int(value, v)) {
                result.error = "line " + std::to_string(line_num) +
                               ": invalid integer value '" + value + "'";
                return result;
            }
            result.config.tls_max_version = v;
        } else if (key == "dh_param_file") {
            result.config.dh_param_file = value;
        } else if (key == "cache_expiry") {
            int v;
            if (!parse_int(value, v)) {
                result.error = "line " + std::to_string(line_num) +
                               ": invalid integer value '" + value + "'";
                return result;
            }
            result.config.cache_expiry = v;
        } else {
            result.error = "line " + std::to_string(line_num) +
                           ": unknown key '" + key + "'";
            return result;
        }
    }

    return result;
}

} // namespace gtls
