using System.ComponentModel.DataAnnotations;
using System.Net;

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
