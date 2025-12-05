# Configuration Guide

## Configuration File Structure

### Main Configuration File
The system uses a JSON-based configuration file located at `config/nids_config.json`.

## Core Components Configuration

### Packet Capture Settings
```json
{
  "packet_capture": {
    "interfaces": [
      {
        "name": "eth0",
        "promiscuous": true,
        "buffer_size": 262144,
        "snaplen": 65535,
        "timeout_ms": 1000
      }
    ],
    "pcap_file": {
      "enabled": true,
      "directory": "/var/log/nids/pcap",
      "max_size_mb": 1024,
      "rotation_interval": "1h"
    }
  }
}
```

### Detection Engine Configuration
```json
{
  "detection_engine": {
    "rules_path": "/etc/nids/rules",
    "custom_rules": "custom.rules",
    "performance": {
      "pattern_matcher": "hyperscan",
      "max_pattern_length": 8192,
      "thread_count": 4
    },
    "thresholds": {
      "alert_suppression_period": 300,
      "max_alerts_per_hour": 1000
    }
  }
}
```

### Threat Intelligence Settings
```json
{
  "threat_intelligence": {
    "feeds": [
      {
        "name": "emerging_threats",
        "url": "https://rules.emergingthreats.net/open/",
        "update_interval": "24h",
        "enabled": true
      }
    ],
    "local_database": {
      "path": "/var/lib/nids/threat_intel",
      "max_size_gb": 10
    }
  }
}
```

## Advanced Configuration

### Machine Learning Components
```json
{
  "machine_learning": {
    "models": {
      "anomaly_detection": {
        "enabled": true,
        "model_path": "/etc/nids/models/anomaly.pkl",
        "threshold": 0.95,
        "training_interval": "7d"
      }
    },
    "features": [
      "packet_size",
      "protocol",
      "port_distribution",
      "connection_duration"
    ]
  }
}
```

### Logging Configuration
```json
{
  "logging": {
    "level": "info",
    "file": "/var/log/nids/system.log",
    "max_size_mb": 100,
    "rotation_count": 5,
    "syslog": {
      "enabled": true,
      "facility": "local0"
    }
  }
}
```

### Performance Tuning
```json
{
  "performance": {
    "packet_threads": 4,
    "analysis_threads": 8,
    "queue_size": 10000,
    "batch_size": 1000,
    "memory_limit_mb": 4096
  }
}
```

## Integration Settings

### SIEM Integration
```json
{
  "siem_integration": {
    "type": "syslog",
    "format": "cef",
    "server": "siem.example.com",
    "port": 514,
    "protocol": "tcp",
    "facility": "local0",
    "severity_mapping": {
      "high": "emergency",
      "medium": "warning",
      "low": "info"
    }
  }
}
```

### API Configuration
```json
{
  "api": {
    "enabled": true,
    "listen_address": "0.0.0.0",
    "port": 8080,
    "ssl": {
      "enabled": true,
      "cert_file": "/etc/nids/ssl/server.crt",
      "key_file": "/etc/nids/ssl/server.key"
    },
    "authentication": {
      "type": "jwt",
      "secret_key": "your-secret-key",
      "token_expiration": "24h"
    }
  }
}
```

## Environment-Specific Configuration

### Development Environment
```json
{
  "environment": "development",
  "debug": true,
  "mock_data": true,
  "profiling": true
}
```

### Production Environment
```json
{
  "environment": "production",
  "debug": false,
  "mock_data": false,
  "profiling": false,
  "security": {
    "strict_mode": true,
    "ip_whitelist": ["10.0.0.0/8", "172.16.0.0/12"]
  }
}
```

## Configuration Best Practices

1. Always use secure communication protocols
2. Implement proper access controls
3. Regular configuration backups
4. Version control for configuration files
5. Environment-specific configurations
6. Regular security audits
7. Performance monitoring and tuning

## Configuration Validation

### Validation Script
```bash
./nids --verify-config --config /path/to/config.json
```

### Common Configuration Issues
1. Invalid JSON syntax
2. Missing required fields
3. Invalid file paths
4. Insufficient permissions
5. Resource allocation conflicts

## Configuration Management

### Version Control
Store configuration files in version control:
```bash
git add config/nids_config.json
git commit -m "Update system configuration"
```

### Configuration Backup
Regularly backup configurations:
```bash
cp config/nids_config.json config/nids_config.backup.json
```

## Next Steps

- Review [Security Hardening](../advanced/security/README.md)
- Configure [Alert Notifications](../components/incident-response/README.md)
- Set up [High Availability](../advanced/deployment/README.md)
