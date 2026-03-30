// =============================================================================
// Generic TLS Library (gtls) - Configuration serializer
// Serializes TlsConfig objects into deterministic key-value text format.
// Only non-default fields are included in the output.
// =============================================================================
#ifndef GTLS_CONFIG_SERIALIZER_H
#define GTLS_CONFIG_SERIALIZER_H

#include <string>
#include "gtls/tls_config.h"

namespace gtls {

// Serializes TlsConfig to key-value text.
// Output format: "key = value\n" per line.
// Fields with default values are omitted for clean output.
class ConfigSerializer {
public:
    // Serialize TlsConfig to key-value text.
    // Deterministic output order for round-trip consistency.
    static std::string serialize(const TlsConfig& config);
};

} // namespace gtls

#endif // GTLS_CONFIG_SERIALIZER_H
