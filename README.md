# SimpleSocks5Proxy

A high-performance SOCKS5 proxy server implementation written in C# using .NET 9.

## Overview

SimpleSocks5Proxy is a lightweight, efficient SOCKS5 proxy server that implements the SOCKS5 protocol as specified in RFC 1928. The server is designed for high performance with support for concurrent connections, asynchronous I/O operations, and structured logging.

## Features

- **SOCKS5 Protocol Compliance**: Full implementation of RFC 1928 SOCKS5 protocol
- **TCP CONNECT Support**: Handles TCP streaming connections
- **Multi-Address Support**: IPv4, IPv6, and domain name resolution
- **High Performance**: Asynchronous I/O operations for scalability
- **Concurrent Connections**: Efficient handling of multiple simultaneous connections
- **Configurable**: JSON-based configuration with command-line overrides
- **Structured Logging**: Comprehensive logging using Serilog
- **Graceful Shutdown**: Proper handling of shutdown signals (Ctrl+C)
- **Cross-Platform**: Built on .NET 9 for cross-platform compatibility

## Requirements

- .NET 9 Runtime
- Windows, Linux, or macOS

## Configuration

The proxy server can be configured using JSON configuration files.

### Default Configuration

The server looks for configuration in the following order:
1. Command-line specified configuration file
2. `proxy.json` in the application directory
3. `appsettings.json` for logging configuration

### Proxy Configuration (`proxy.json`)

```json
{
  "ListenIPAddress": "127.0.0.1",
  "ListenPort": 1080
}
```

**Configuration Options:**
- `ListenIPAddress`: IP address to bind the proxy server (default: 127.0.0.1)
- `ListenPort`: Port number to listen on (default: 1080)

### Logging Configuration (`appsettings.json`)

```json
{
  "Serilog": {
    "MinimumLevel": {
      "Default": "Information",
      "Override": {
        "Microsoft.AspNetCore": "Warning"
      }
    },
    "WriteTo": [
      {
        "Name": "Console",
        "Args": {
          "outputTemplate": "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}"
        }
      }
    ]
  }
}
```

## Usage

### Basic Usage

Start the proxy server with default configuration:
```bash
dotnet run --project Socks5Proxy
```

### Custom Configuration

Start with a custom configuration file:
```bash
dotnet run --project Socks5Proxy -- --config /path/to/custom-config.json
```

### Command Line Arguments

- `--config <path>`: Specify custom configuration file path

### Client Configuration

Configure your applications to use the SOCKS5 proxy:
- **Proxy Host**: 127.0.0.1 (or configured listen address)
- **Proxy Port**: 1080 (or configured listen port)
- **Proxy Type**: SOCKS5
- **Authentication**: None

## Architecture

The application consists of several key components:

- **Program.cs**: Main entry point and application lifecycle management
- **Server.cs**: Core SOCKS5 server implementation
- **ConnectionHandler.cs**: Handles individual client connections
- **Socks5Protocol.cs**: SOCKS5 protocol implementation and message parsing
- **UdpRelay.cs**: UDP relay functionality (future enhancement)
- **ProxyConfiguration.cs**: Configuration management

## Protocol Support

### Supported Features
- SOCKS5 protocol (RFC 1928)
- TCP CONNECT command
- IPv4 addresses
- IPv6 addresses
- Domain name resolution
- No authentication method (0x00)

### Currently Not Supported
- SOCKS4/SOCKS4a protocols
- UDP ASSOCIATE command
- BIND command
- Username/password authentication
- GSSAPI authentication

## Performance

The server is optimized for high performance:
- Asynchronous I/O operations using `async`/`await`
- Efficient memory management
- Low-latency connection handling
- Scalable concurrent connection support

### Project Structure

```
SimpleSocks5Proxy/
├── Documents/           # Project documentation
├── Socks5Proxy/        # Main application source code
│   ├── Program.cs      # Application entry point
│   ├── Server.cs       # SOCKS5 server implementation
│   ├── ConnectionHandler.cs
│   ├── Socks5Protocol.cs
│   ├── UdpRelay.cs
│   ├── ProxyConfiguration.cs
│   ├── appsettings.json
│   └── proxy.json
├── LICENSE             # License file
└── Socks5Proxy.sln    # Solution file
```

## Friendly name logging

Optionally map specific IP addresses to human-friendly labels for clearer logs. When a mapping exists, logs append a suffix like ` (FriendlyName)` after the IP or endpoint.

Example config (in `proxy.json`):

```json
{
  "ListenIPAddress": "0.0.0.0",
  "ListenPort": 1080,
  "IPAddressMappings": [
    { "IPAddress": "192.168.1.10", "FriendlyName": "Laptop" },
    { "IPAddress": "10.0.0.5", "FriendlyName": "NAS" }
  ]
}
```

Log output:
- Before: `New client connection from 192.168.1.10:51324`
- After:  `New client connection from 192.168.1.10:51324 (Laptop)`

If no mapping exists, the original value is logged unchanged. Domains (e.g., `example.org:80`) aren’t mapped.

## License

This project is licensed under the terms specified in the LICENSE file.
