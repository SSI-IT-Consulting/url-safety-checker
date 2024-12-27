# URL Safety Checker

## Overview

The URL Safety Checker is a server-side application that uses Google Safe Browsing API v4 to check the safety of URLs. It allows clients to send full URL hashes for validation against known unsafe entries, leveraging a local cache (Redis) and database (PostgreSQL) to optimize performance.

## Features

- Fetch and store prefix hashes from Google Safe Browsing API.
- Check the safety of URLs using prefix and full hash matching.
- Support for bulk URL hash submissions.
- Caching with Redis for quick access to hash entries.
- Automatic updates from Google to keep the local database synchronized.
- Scalable architecture ready for deployment.

### **Check URL Safety**

- **Endpoint:** `POST /check-url`
- **Request Body:**

```json
{
  "urls": [
    "0OGWoMJdNd0KhFk8uuDzgzOqWFKZNkROomRT6rKN/IY=",
    "WwuJdQx48jP+4lxr4y2Sj82AWoxUVcIRDSk1PC9Rf+4"
  ]
}
```

- **Response:**

```json
[
  {
    "url": "WwuJdQx48jP+4lxr4y2Sj82AWoxUVcIRDSk1PC9Rf+4=",
    "status": "unsafe",
    "message": "The provided URL is considered unsafe. Please avoid visiting this site.",
    "threat_type": "MALWARE"
  },
  {
    "url": "0OGWoMJdNd0KhFk8uuDzgzOqWFKZNkROomRT6rKN/IY=",
    "status": "safe",
    "message": "The URL is not listed in any threat database."
  }
]
```

### Background Processes

- The server fetches prefix hashes on startup and updates them periodically using a background process.

## Caching Strategy

1. **Redis**:
   - Prefix hashes are stored as Redis sets.
   - Checked first to optimize performance.
2. **PostgreSQL**:
   - Serves as the primary storage for prefix hashes and client states.
