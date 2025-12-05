# Getting Started with Network Intrusion Detection System

## Prerequisites

### System Requirements
- CPU: Multi-core processor (recommended 4+ cores)
- RAM: Minimum 8GB (16GB+ recommended)
- Storage: 100GB+ for log storage
- Network: 1Gbps network interface

### Software Requirements
- C++ Compiler (GCC 9+ or MSVC 2019+)
- CMake 3.15+
- Boost Libraries 1.70+
- OpenSSL 1.1.1+
- Python 3.8+ (for ML components)

## Installation

### Building from Source
```bash
# Clone the repository
git clone https://github.com/your-org/NetIntrusionSys.git

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build the project
cmake --build .
```

### Configuration
1. Copy the example configuration:
   ```bash
   cp config/nids_config.example.json config/nids_config.json
   ```
2. Edit the configuration file to match your environment
3. Verify configuration:
   ```bash
   ./nids --verify-config
   ```

## Quick Start

### Basic Usage
1. Start the system:
   ```bash
   ./nids --config config/nids_config.json
   ```
2. Access the web interface at `http://localhost:8080`
3. Configure network interfaces for monitoring

### Initial Setup
1. Configure detection rules
2. Set up threat intelligence feeds
3. Configure alert notifications
4. Test the system with sample traffic

## Basic Configuration

### Network Interfaces
```json
{
  "interfaces": [
    {
      "name": "eth0",
      "promiscuous": true,
      "capture_filter": "not port 22"
    }
  ]
}
```

### Detection Rules
```json
{
  "rules": {
    "enabled": true,
    "ruleset_path": "/etc/nids/rules",
    "custom_rules": "custom.rules"
  }
}
```

## Verification

### System Health Check
```bash
./nids --health-check
```

### Testing Detection
1. Use provided test scripts:
   ```bash
   ./tests/run_detection_tests.sh
   ```
2. Review test results in `logs/test_results.log`

## Next Steps

- Review the [Configuration Guide](../configuration/README.md)
- Set up [Threat Intelligence](../components/threat-intelligence/README.md)
- Configure [Alert Notifications](../components/incident-response/README.md)
- Explore [Advanced Features](../advanced/README.md)

## Troubleshooting

### Common Issues
1. Insufficient permissions
2. Network interface not found
3. Configuration file errors

For detailed troubleshooting, see the [Troubleshooting Guide](../support/troubleshooting.md).

## Support

- [Documentation](../README.md)
- [FAQ](../support/faq.md)
- [GitHub Issues](https://github.com/your-org/NetIntrusionSys/issues)
- [Community Forum](https://forum.your-org.com)
