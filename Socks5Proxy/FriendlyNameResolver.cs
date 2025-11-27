using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using Serilog;

namespace Socks5Proxy;

/// <summary>
/// Resolves literal IP addresses to friendly names for log output.
/// Safe-by-default: if anything fails, falls back to original formatting.
/// </summary>
public sealed class FriendlyNameResolver
{
    private readonly ILogger _logger;
    private readonly ImmutableDictionary<string, string> _map; // key: normalized IP string, value: FriendlyName

    public FriendlyNameResolver(IEnumerable<IPAddressMapping>? mappings, ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        var builder = ImmutableDictionary.CreateBuilder<string, string>(StringComparer.OrdinalIgnoreCase);

        if (mappings == null)
        {
            _map = builder.ToImmutable();
            return;
        }

        var invalidEntries = new List<string>();
        var duplicates = new List<string>();

        foreach (var m in mappings)
        {
            var ipStr = (m?.IPAddress ?? string.Empty).Trim();
            var name = (m?.FriendlyName ?? string.Empty).Trim();
            if (ipStr.Length == 0 || name.Length == 0)
            {
                invalidEntries.Add($"(ip:'{m?.IPAddress}', name:'{m?.FriendlyName}')");
                continue;
            }

            if (!IPAddress.TryParse(ipStr, out var ip))
            {
                invalidEntries.Add($"(ip:'{ipStr}', name:'{name}')");
                continue;
            }

            var key = ip.ToString(); // normalized canonical
            if (builder.ContainsKey(key))
            {
                duplicates.Add(key);
            }
            builder[key] = name; // last one wins
        }

        _map = builder.ToImmutable();

        if (invalidEntries.Count > 0)
        {
            _logger.Warning("Some IPAddressMappings are invalid and were ignored: {Invalid}", string.Join(", ", invalidEntries));
        }
        if (duplicates.Count > 0)
        {
            // list distinct duplicates
            var distinct = string.Join(", ", duplicates.Distinct());
            _logger.Warning("Duplicate IPAddressMappings detected (last wins) for: {Duplicates}", distinct);
        }
        _logger.Information("Loaded {Count} IP address mappings for friendly log names", _map.Count);
    }

    // Removed Format* methods; suffix-only API retained per request.

    // Suffix helpers to append only the friendly name in parentheses when available
    public string FriendlySuffix(IPAddress ip)
    {
        if (ip == null) return string.Empty;
        var key = ip.ToString();
        return _map.TryGetValue(key, out var name) ? $" ({name})" : string.Empty;
    }

    public string FriendlySuffix(IPEndPoint endPoint)
    {
        if (endPoint == null) return string.Empty;
        return FriendlySuffix(endPoint.Address);
    }

    public string FriendlySuffix(EndPoint? endPoint)
    {
        if (endPoint is IPEndPoint ipEp)
        {
            return FriendlySuffix(ipEp);
        }
        return string.Empty;
    }

    public string FriendlySuffixForAddressString(string address)
    {
        if (IPAddress.TryParse(address, out var ip))
        {
            return FriendlySuffix(ip);
        }
        return string.Empty;
    }
}
