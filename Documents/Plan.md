# SOCKS5 Proxy Server Implementation Plan

This document outlines the plan for implementing the SOCKS5 proxy server.

1.  **Project Setup:**
    *   Create a new C# console application project targeting .NET 9.
    *   The project will be named `Socks5Proxy`.

2.  **Core Server Logic (`Server.cs`):**
    *   Implement a `Server` class to encapsulate the proxy server's functionality.
    *   The `Server` class will have a `StartAsync(CancellationToken cancellationToken)` method that:
        *   Initializes a `TcpListener` to listen on a configured IP address and port.
        *   Enters a loop to accept incoming `TcpClient` connections. The loop will be terminated when the `cancellationToken` is triggered.
        *   For each new client, it will start a new task to handle the connection.

3.  **Client Connection Handling (`ConnectionHandler.cs`):**
    *   Create a `ConnectionHandler` class to manage each client connection.
    *   This class will contain the logic for:
        *   **SOCKS5 Handshake:**
            *   Reading the client's method selection message.
            *   Validating that the client supports the "No Authentication Required" method (0x00).
            *   Sending a response selecting the "No Authentication Required" method.
        *   **SOCKS5 Request/Response:**
            *   Reading the client's connection request.
            *   Parsing the command type (CONNECT or UDP ASSOCIATE).
            *   Parsing the address type (IPv4, IPv6, Domain Name) and destination address/port.
            *   For CONNECT command: Establishing a TCP connection to the destination server.
            *   For UDP ASSOCIATE command: Setting up UDP relay functionality.
            *   Sending the appropriate SOCKS5 reply to the client with proper error codes.
            *   Comprehensive error handling for network failures, DNS resolution errors, connection timeouts, and invalid requests.
        *   **Data Forwarding:**
            *   For TCP (CONNECT): Using `System.IO.Pipelines` for high-performance data transfer between the client and the destination.
            *   For UDP (UDP ASSOCIATE): Implementing UDP packet relay between client and destination.
            *   Two pipelines will be created to manage bidirectional data flow, minimizing memory allocations and context switching.
            *   Ensuring that if one side of the connection is closed, the other is also gracefully terminated.
            *   Proper exception handling and logging for all network operations.

4.  **Proxy Configuration (`proxy.json`):**
    *   A JSON file (`proxy.json`) will be used to store the proxy-specific settings.
    *   It will contain settings for the listening IP address and port.
    *   The application can be launched with a command-line argument specifying the path to this file. If not provided, it will look for `proxy.json` in the application's directory.
    *   Configuration validation will be implemented to ensure:
        *   Valid IP addresses (IPv4/IPv6 or "0.0.0.0" for all interfaces).
        *   Valid port ranges (1-65535).
        *   Required fields are present.
    *   Example `proxy.json`:
        ```json
        {
          "ListenIPAddress": "127.0.0.1",
          "ListenPort": 1080
        }
        ```

5.  **Application Configuration (`appsettings.json`):**
    *   A separate `appsettings.json` file will be used for application-level configurations, such as logging.
    *   This file will contain the Serilog configuration with comprehensive logging levels.
    *   Error handling and logging will be implemented for:
        *   Network connection failures and timeouts.
        *   Invalid SOCKS5 protocol messages.
        *   DNS resolution errors.
        *   Configuration validation errors.
        *   Unexpected exceptions during data forwarding.
    *   Example `appsettings.json`:
        ```json
        {
          "Serilog": {
            "MinimumLevel": {
              "Default": "Information",
              "Override": {
                "Microsoft.AspNetCore": "Warning"
              }
            }
          }
        }
        ```

6.  **Main Program (`Program.cs`):**
    *   The `Main` method will be the entry point of the application.
    *   It will be responsible for:
        *   Building a configuration object from `appsettings.json` and `proxy.json` using `Microsoft.Extensions.Configuration`.
        *   It will check for a command-line argument specifying the proxy configuration file path.
        *   Configuring a structured logger using `Serilog` based on the settings in `appsettings.json`.
        *   Setting up a `CancellationTokenSource` to handle graceful shutdown.
        *   Subscribing to the `Console.CancelKeyPress` event to trigger the cancellation token when `Ctrl+C` is pressed.
        *   Creating an instance of the `Server` class, passing in the proxy configuration.
        *   Starting the server with the cancellation token and waiting for it to stop.

7.  **Dependencies:**
    *   `Microsoft.Extensions.Configuration.Json` for loading configuration from JSON files.
    *   `Microsoft.Extensions.Configuration.Binder` to bind configuration to objects.
    *   `Microsoft.Extensions.Configuration.CommandLine` to handle command-line arguments.
    *   `Serilog` for structured logging.
    *   `Serilog.Sinks.Console` for writing logs to the console.
    *   `Serilog.Settings.Configuration` to configure Serilog from `appsettings.json`.
    *   `System.ComponentModel.DataAnnotations` for configuration validation attributes.

8.  **Additional Classes:**
    *   **ProxyConfiguration.cs**: A model class to represent proxy settings with validation attributes.
    *   **UdpRelay.cs**: A class to handle UDP ASSOCIATE command and UDP packet forwarding.
    *   **Socks5Protocol.cs**: Constants and enums for SOCKS5 protocol values (commands, address types, reply codes).

9.  **Project Structure:**
    ```
    Socks5Proxy/
    ├── Socks5Proxy.csproj
    ├── Program.cs
    ├── Server.cs
    ├── ConnectionHandler.cs
    ├── UdpRelay.cs
    ├── ProxyConfiguration.cs
    ├── Socks5Protocol.cs
    ├── proxy.json
    ├── appsettings.json
    ├── Requirements.md
    └── Plan.md
    ```
