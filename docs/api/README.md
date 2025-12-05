# API Reference

## Overview
The Network Intrusion Detection System provides a comprehensive REST API for integration and automation.

## Authentication

### JWT Authentication
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your-password"
}
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 86400
}
```

## API Endpoints

### System Status

#### Get System Health
```http
GET /api/v1/system/health
Authorization: Bearer <token>
```

Response:
```json
{
  "status": "healthy",
  "components": {
    "packet_capture": "running",
    "detection_engine": "running",
    "threat_intelligence": "running"
  },
  "resources": {
    "cpu_usage": 45.2,
    "memory_usage": 6144,
    "disk_space": 82.5
  }
}
```

### Alert Management

#### List Alerts
```http
GET /api/v1/alerts
Authorization: Bearer <token>
```

Parameters:
- `start_time` (optional): ISO8601 timestamp
- `end_time` (optional): ISO8601 timestamp
- `severity` (optional): high, medium, low
- `limit` (optional): Number of results (default: 100)
- `offset` (optional): Pagination offset

Response:
```json
{
  "total": 1250,
  "alerts": [
    {
      "id": "alert-123",
      "timestamp": "2024-01-20T15:30:00Z",
      "severity": "high",
      "source_ip": "192.168.1.100",
      "destination_ip": "10.0.0.5",
      "protocol": "TCP",
      "description": "Potential SQL injection attempt"
    }
  ]
}
```

### Threat Intelligence

#### Query IOC
```http
GET /api/v1/threat-intel/ioc/{indicator}
Authorization: Bearer <token>
```

Response:
```json
{
  "indicator": "1.2.3.4",
  "type": "ip",
  "risk_score": 85,
  "first_seen": "2024-01-15T10:00:00Z",
  "last_seen": "2024-01-20T14:30:00Z",
  "tags": ["malware", "c2"],
  "sources": ["emerging_threats", "abuse.ch"]
}
```

### Configuration Management

#### Update System Configuration
```http
PUT /api/v1/config
Authorization: Bearer <token>
Content-Type: application/json

{
  "detection_engine": {
    "rules_path": "/etc/nids/rules",
    "performance": {
      "thread_count": 8
    }
  }
}
```

Response:
```json
{
  "status": "success",
  "message": "Configuration updated successfully",
  "restart_required": true
}
```

## WebSocket API

### Real-time Alert Stream
```javascript
ws://your-server/api/v1/ws/alerts
```

Message Format:
```json
{
  "type": "alert",
  "data": {
    "id": "alert-124",
    "timestamp": "2024-01-20T15:31:00Z",
    "severity": "medium",
    "details": {
      "source_ip": "192.168.1.101",
      "destination_ip": "10.0.0.6",
      "protocol": "HTTP",
      "description": "Suspicious outbound connection"
    }
  }
}
```

## Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "AUTH_FAILED",
    "message": "Invalid authentication credentials",
    "details": {
      "reason": "Token expired"
    }
  }
}
```

### Common Error Codes
- `AUTH_FAILED`: Authentication failure
- `INVALID_REQUEST`: Invalid request parameters
- `NOT_FOUND`: Resource not found
- `INTERNAL_ERROR`: Internal server error

## Rate Limiting

API requests are limited to:
- 1000 requests per hour per IP
- 100 requests per minute per token

Rate limit headers:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 985
X-RateLimit-Reset: 1705766400
```

## Best Practices

1. Always use HTTPS for API requests
2. Implement proper error handling
3. Use pagination for large result sets
4. Cache responses when appropriate
5. Handle rate limiting gracefully
6. Keep authentication tokens secure

## SDK Examples

### Python
```python
import requests

class NIDSClient:
    def __init__(self, base_url, api_token):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json'
        }
    
    def get_alerts(self, start_time=None, end_time=None):
        params = {
            'start_time': start_time,
            'end_time': end_time
        }
        response = requests.get(
            f'{self.base_url}/api/v1/alerts',
            headers=self.headers,
            params=params
        )
        return response.json()
```

### JavaScript
```javascript
class NIDSClient {
  constructor(baseUrl, apiToken) {
    this.baseUrl = baseUrl;
    this.headers = {
      'Authorization': `Bearer ${apiToken}`,
      'Content-Type': 'application/json'
    };
  }

  async getAlerts(startTime, endTime) {
    const params = new URLSearchParams({
      start_time: startTime,
      end_time: endTime
    });
    
    const response = await fetch(
      `${this.baseUrl}/api/v1/alerts?${params}`,
      { headers: this.headers }
    );
    
    return response.json();
  }
}
```

## API Versioning

API versioning is handled through the URL path:
- Current version: `/api/v1/`
- Legacy version: `/api/v0/` (deprecated)

Version changelog available at [Release Notes](../support/release-notes.md).

## Support

- [API Status Dashboard](https://status.your-org.com)
- [Developer Forum](https://forum.your-org.com/developers)
- [API Issues](https://github.com/your-org/NetIntrusionSys/issues)
- Email: api-support@your-org.com