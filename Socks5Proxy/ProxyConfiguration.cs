using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Collections.Generic;

namespace Socks5Proxy;

/// <summary>
/// Configuration model for the SOCKS5 proxy server with validation attributes.
/// </summary>
public class ProxyConfiguration
{
    /// <summary>
    /// The IP address to listen on. Can be IPv4, IPv6, or "0.0.0.0" for all interfaces.
    /// </summary>
    [Required(ErrorMessage = "ListenIPAddress is required")]
    public string ListenIPAddress { get; set; } = string.Empty;

    /// <summary>
    /// The port to listen on. Must be between 1 and 65535.
    /// </summary>
    [Range(1, 65535, ErrorMessage = "ListenPort must be between 1 and 65535")]
    public int ListenPort { get; set; }

    /// <summary>
    /// Optional mappings of IP addresses to friendly names for log output.
    /// </summary>
    public List<IPAddressMapping> IPAddressMappings { get; set; } = new();

    /// <summary>
    /// Maximum number of concurrent connections. 0 means unlimited. Default: 1000.
    /// </summary>
    [Range(0, int.MaxValue, ErrorMessage = "MaxConnections must be 0 (unlimited) or a positive number")]
    public int MaxConnections { get; set; } = 1000;

    /// <summary>
    /// Validates that the IP address is valid.
    /// </summary>
    /// <returns>True if the configuration is valid, otherwise false.</returns>
    public bool IsValid(out string errorMessage)
    {
        errorMessage = string.Empty;

        // Validate IP address
        if (string.IsNullOrWhiteSpace(ListenIPAddress))
        {
            errorMessage = "ListenIPAddress cannot be null or empty";
            return false;
        }

        if (!IPAddress.TryParse(ListenIPAddress, out _))
        {
            errorMessage = $"Invalid IP address: {ListenIPAddress}";
            return false;
        }

        // Validate port range
        if (ListenPort < 1 || ListenPort > 65535)
        {
            errorMessage = $"Invalid port: {ListenPort}. Port must be between 1 and 65535";
            return false;
        }

        return true;
    }
}

/// <summary>
/// A single mapping from literal IP address to a friendly name for logging.
/// </summary>
public class IPAddressMapping
{
    public string IPAddress { get; set; } = string.Empty;
    public string FriendlyName { get; set; } = string.Empty;
}
