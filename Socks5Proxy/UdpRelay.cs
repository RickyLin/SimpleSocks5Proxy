using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Serilog;

namespace Socks5Proxy;

/// <summary>
/// UDP relay handler for SOCKS5 UDP ASSOCIATE command.
/// </summary>
public class UdpRelay : IDisposable, IAsyncDisposable
{
    private readonly ILogger _logger;
    private readonly UdpClient _udpClient;
    private readonly IPEndPoint _clientTcpEndPoint;
    private IPEndPoint? _actualClientUdpEndPoint; // Track actual client UDP source
    private readonly FriendlyNameResolver _resolver;
    private readonly CancellationTokenSource _cancellationTokenSource;
    private readonly Task _relayTask;
    private readonly ConcurrentDictionary<string, (IPAddress[] Addresses, DateTime Expiry)> _dnsCache;
    private static readonly TimeSpan DnsCacheTtl = TimeSpan.FromMinutes(5);
    private static readonly int DnsCacheMaxSize = 100;
    private int _disposed;

    /// <summary>
    /// Gets the local endpoint where the UDP relay is listening.
    /// </summary>
    public IPEndPoint LocalEndPoint { get; }

    /// <summary>
    /// Initializes a new instance of the UdpRelay class.
    /// </summary>
    /// <param name="clientEndPoint">The client endpoint that will send UDP packets.</param>
    /// <param name="logger">The logger instance.</param>
    /// <param name="resolver">Friendly name resolver for log formatting.</param>
    public UdpRelay(IPEndPoint clientEndPoint, ILogger logger, FriendlyNameResolver resolver)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _clientTcpEndPoint = clientEndPoint ?? throw new ArgumentNullException(nameof(clientEndPoint));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _cancellationTokenSource = new CancellationTokenSource();
        _dnsCache = new ConcurrentDictionary<string, (IPAddress[] Addresses, DateTime Expiry)>(StringComparer.OrdinalIgnoreCase);

        // Create UDP client and bind to any available port
        _udpClient = new UdpClient(0);
        LocalEndPoint = (IPEndPoint)_udpClient.Client.LocalEndPoint!;

        _logger.Information(
            "UDP relay started on {LocalEndPoint}{FriendlyLocal} for client {ClientEndPoint}{FriendlyClient}",
            LocalEndPoint,
            _resolver.FriendlySuffix(LocalEndPoint),
            _clientTcpEndPoint,
            _resolver.FriendlySuffix(_clientTcpEndPoint));

        // Start the relay task
        _relayTask = RelayPacketsAsync(_cancellationTokenSource.Token);
    }

    /// <summary>
    /// Relays UDP packets between client and destination servers.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token to stop the relay.</param>
    private async Task RelayPacketsAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // Use ReceiveAsync overload with CancellationToken (available in .NET 5+)
                    var result = await _udpClient.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                    
                    // Check if the packet is from our client
                    // Track the actual client UDP source on first packet (client may use different ephemeral port)
                    // Validate by IP address only, as client may use different port than TCP connection
                    if (_actualClientUdpEndPoint == null && result.RemoteEndPoint.Address.Equals(_clientTcpEndPoint.Address))
                    {
                        _actualClientUdpEndPoint = result.RemoteEndPoint;
                        _logger.Debug("Tracked actual client UDP endpoint: {ActualEndPoint}", _actualClientUdpEndPoint);
                    }

                    if (_actualClientUdpEndPoint != null && result.RemoteEndPoint.Equals(_actualClientUdpEndPoint))
                    {
                        // Parse SOCKS5 UDP header and forward to destination
                        await HandleClientPacketAsync(result.Buffer, cancellationToken).ConfigureAwait(false);
                    }
                    else if (result.RemoteEndPoint.Address.Equals(_clientTcpEndPoint.Address))
                    {
                        // Packet from client IP but different port than tracked - could be legitimate
                        await HandleClientPacketAsync(result.Buffer, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        // Forward response back to client with SOCKS5 UDP header
                        await HandleServerResponseAsync(result.Buffer, result.RemoteEndPoint, cancellationToken).ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException)
                {
                    // Cancellation requested, exit gracefully
                    break;
                }
                catch (ObjectDisposedException)
                {
                    // UDP client has been disposed, exit gracefully
                    break;
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.OperationAborted)
                {
                    // Operation was cancelled, exit gracefully
                    break;
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Error in UDP relay for client {ClientEndPoint}{FriendlyClient}", _clientTcpEndPoint, _resolver.FriendlySuffix(_clientTcpEndPoint));
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Fatal error in UDP relay for client {ClientEndPoint}{FriendlyClient}", _clientTcpEndPoint, _resolver.FriendlySuffix(_clientTcpEndPoint));
        }
        finally
        {
            _logger.Information("UDP relay stopped for client {ClientEndPoint}{FriendlyClient}", _clientTcpEndPoint, _resolver.FriendlySuffix(_clientTcpEndPoint));
        }
    }

    /// <summary>
    /// Handles UDP packet from client, parses SOCKS5 UDP header and forwards to destination.
    /// </summary>
    /// <param name="buffer">The packet buffer from client.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task HandleClientPacketAsync(byte[] buffer, CancellationToken cancellationToken)
    {
        try
        {
            // Parse SOCKS5 UDP header
            // Format: RSV (2 bytes) | FRAG (1 byte) | ATYP (1 byte) | DST.ADDR | DST.PORT | DATA
            if (buffer.Length < 10) // Minimum header size
            {
                _logger.Warning("Received UDP packet too small from client {ClientEndPoint}{FriendlyClient}", _clientTcpEndPoint, _resolver.FriendlySuffix(_clientTcpEndPoint));
                return;
            }

            int offset = 0;
            
            // Skip RSV (2 bytes)
            offset += 2;
            
            // Validate FRAG field - fragmented packets are not supported
            byte frag = buffer[offset++];
            if (frag != 0)
            {
                _logger.Warning(
                    "Received fragmented UDP packet (FRAG={Frag}) from client {ClientEndPoint}{FriendlyClient}, fragmentation not supported",
                    frag,
                    _clientTcpEndPoint,
                    _resolver.FriendlySuffix(_clientTcpEndPoint));
                return;
            }
            
            byte addressType = buffer[offset++];
            IPEndPoint? destinationEndPoint = null;

            switch (addressType)
            {
                case Socks5Protocol.AddressType.IPv4:
                    if (buffer.Length < offset + 6) return; // 4 bytes IP + 2 bytes port
                    var ipv4Address = new IPAddress(buffer.AsSpan(offset, 4));
                    offset += 4;
                    var port = (buffer[offset] << 8) | buffer[offset + 1];
                    offset += 2;
                    destinationEndPoint = new IPEndPoint(ipv4Address, port);
                    break;

                case Socks5Protocol.AddressType.IPv6:
                    if (buffer.Length < offset + 18) return; // 16 bytes IP + 2 bytes port
                    var ipv6Address = new IPAddress(buffer.AsSpan(offset, 16));
                    offset += 16;
                    port = (buffer[offset] << 8) | buffer[offset + 1];
                    offset += 2;
                    destinationEndPoint = new IPEndPoint(ipv6Address, port);
                    break;

                case Socks5Protocol.AddressType.DomainName:
                    if (buffer.Length < offset + 1) return;
                    byte domainLength = buffer[offset++];
                    if (buffer.Length < offset + domainLength + 2) return;
                    var domain = System.Text.Encoding.ASCII.GetString(buffer, offset, domainLength);
                    offset += domainLength;
                    port = (buffer[offset] << 8) | buffer[offset + 1];
                    offset += 2;
                    
                    // Resolve domain name with caching and cancellation support
                    try
                    {
                        var addresses = await ResolveDnsWithCacheAsync(domain, cancellationToken).ConfigureAwait(false);
                        IPAddress? targetAddress = null;
                        foreach (var candidate in addresses)
                        {
                            if (candidate.AddressFamily == AddressFamily.InterNetwork)
                            {
                                targetAddress = candidate;
                                break;
                            }

                            targetAddress ??= candidate;
                        }

                        if (targetAddress != null)
                        {
                            destinationEndPoint = new IPEndPoint(targetAddress, port);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                    catch (Exception ex)
                    {
                        _logger.Warning(
                            ex,
                            "Failed to resolve domain {Domain} for UDP relay for client {ClientEndPoint}{FriendlyClient}",
                            domain,
                            _clientTcpEndPoint,
                            _resolver.FriendlySuffix(_clientTcpEndPoint));
                        return;
                    }
                    break;

                default:
                    _logger.Warning(
                        "Unsupported address type {AddressType} in UDP packet from client {ClientEndPoint}{FriendlyClient}",
                        addressType,
                        _clientTcpEndPoint,
                        _resolver.FriendlySuffix(_clientTcpEndPoint));
                    return;
            }

            if (destinationEndPoint == null)
            {
                _logger.Warning(
                    "Could not determine destination endpoint from UDP packet from client {ClientEndPoint}{FriendlyClient}",
                    _clientTcpEndPoint,
                    _resolver.FriendlySuffix(_clientTcpEndPoint));
                return;
            }

            // Send payload directly using Memory<byte> to avoid array copy
            var payloadLength = buffer.Length - offset;
            await _udpClient.SendAsync(buffer.AsMemory(offset, payloadLength), destinationEndPoint, cancellationToken).ConfigureAwait(false);
            
            _logger.Debug(
                "Forwarded UDP packet from client {ClientEndPoint}{FriendlyClient} to {DestinationEndPoint}{FriendlyDest}, size: {Size}",
                _clientTcpEndPoint,
                _resolver.FriendlySuffix(_clientTcpEndPoint),
                destinationEndPoint,
                _resolver.FriendlySuffix(destinationEndPoint),
                payloadLength);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling client UDP packet from {ClientEndPoint}{FriendlyClient}", _clientTcpEndPoint, _resolver.FriendlySuffix(_clientTcpEndPoint));
        }
    }

    /// <summary>
    /// Resolves DNS with caching to avoid repeated lookups.
    /// </summary>
    private async Task<IPAddress[]> ResolveDnsWithCacheAsync(string domain, CancellationToken cancellationToken)
    {
        // Check cache first
        if (_dnsCache.TryGetValue(domain, out var cached) && cached.Expiry > DateTime.UtcNow)
        {
            return cached.Addresses;
        }

        // Resolve and cache
        var addresses = await Dns.GetHostAddressesAsync(domain, cancellationToken).ConfigureAwait(false);
        _dnsCache[domain] = (addresses, DateTime.UtcNow.Add(DnsCacheTtl));

        // Evict expired entries if cache exceeds threshold
        if (_dnsCache.Count > DnsCacheMaxSize)
        {
            var now = DateTime.UtcNow;
            foreach (var key in _dnsCache.Keys)
            {
                if (_dnsCache.TryGetValue(key, out var entry) && entry.Expiry < now)
                {
                    _dnsCache.TryRemove(key, out _);
                }
            }
        }

        return addresses;
    }

    /// <summary>
    /// Handles response from destination server and forwards back to client with SOCKS5 UDP header.
    /// </summary>
    /// <param name="buffer">The response buffer from destination.</param>
    /// <param name="sourceEndPoint">The source endpoint of the response.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task HandleServerResponseAsync(byte[] buffer, IPEndPoint sourceEndPoint, CancellationToken cancellationToken)
    {
        // Determine actual client endpoint to send response to
        var clientTarget = _actualClientUdpEndPoint ?? _clientTcpEndPoint;
        
        // Calculate header length: RSV(2) + FRAG(1) + ATYP(1) + ADDR(4 or 16) + PORT(2)
        var headerLength = sourceEndPoint.AddressFamily == AddressFamily.InterNetwork ? 10 : 22;
        var responseBuffer = ArrayPool<byte>.Shared.Rent(headerLength + buffer.Length);
        
        try
        {
            int offset = 0;

            // RSV (2 bytes)
            responseBuffer[offset++] = 0x00;
            responseBuffer[offset++] = 0x00;
            
            // FRAG (1 byte)
            responseBuffer[offset++] = 0x00;

            // ATYP (1 byte) and address
            if (sourceEndPoint.AddressFamily == AddressFamily.InterNetwork)
            {
                responseBuffer[offset++] = Socks5Protocol.AddressType.IPv4;
                sourceEndPoint.Address.TryWriteBytes(responseBuffer.AsSpan(offset, 4), out var bytesWritten);
                offset += bytesWritten;
            }
            else if (sourceEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                responseBuffer[offset++] = Socks5Protocol.AddressType.IPv6;
                sourceEndPoint.Address.TryWriteBytes(responseBuffer.AsSpan(offset, 16), out var bytesWritten);
                offset += bytesWritten;
            }

            // Port (2 bytes)
            responseBuffer[offset++] = (byte)(sourceEndPoint.Port >> 8);
            responseBuffer[offset++] = (byte)(sourceEndPoint.Port & 0xFF);

            // Payload
            buffer.AsSpan().CopyTo(responseBuffer.AsSpan(offset));
            var totalLength = offset + buffer.Length;

            // Send back to client using Memory<byte>
            await _udpClient.SendAsync(responseBuffer.AsMemory(0, totalLength), clientTarget, cancellationToken).ConfigureAwait(false);
            
            _logger.Debug(
                "Forwarded UDP response from {SourceEndPoint}{FriendlySource} to client {ClientEndPoint}{FriendlyClient}, size: {Size}",
                sourceEndPoint,
                _resolver.FriendlySuffix(sourceEndPoint),
                clientTarget,
                _resolver.FriendlySuffix(clientTarget),
                buffer.Length);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling server UDP response from {SourceEndPoint}{FriendlySource}", sourceEndPoint, _resolver.FriendlySuffix(sourceEndPoint));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(responseBuffer);
        }
    }

    /// <summary>
    /// Stops the UDP relay.
    /// </summary>
    public async Task StopAsync()
    {
        if (Volatile.Read(ref _disposed) != 0) return;

        _cancellationTokenSource.Cancel();
        
        // Dispose UDP client to unblock any pending ReceiveAsync
        try
        {
            _udpClient?.Dispose();
        }
        catch (Exception ex)
        {
            _logger.Debug(ex, "Error disposing UDP client during stop");
        }
        
        // Wait for relay task to complete
        try
        {
            await _relayTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Expected when cancellation is requested
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error stopping UDP relay for client {ClientEndPoint}", _clientTcpEndPoint);
        }
    }

    /// <summary>
    /// Asynchronously disposes the UDP relay resources.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;
        
        await StopAsync().ConfigureAwait(false);
        _cancellationTokenSource.Dispose();
        
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes the UDP relay resources.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;
        _cancellationTokenSource.Cancel();
        
        // Dispose UDP client first to unblock ReceiveAsync
        try
        {
            _udpClient?.Dispose();
        }
        catch
        {
            // Ignore disposal errors
        }
        
        // Wait for relay task with timeout
        try
        {
            if (!_relayTask.Wait(TimeSpan.FromSeconds(2)))
            {
                _logger.Warning("Relay task did not complete within timeout during disposal");
            }
        }
        catch
        {
            // Ignore task completion errors during disposal
        }
        
        _cancellationTokenSource.Dispose();
        
        GC.SuppressFinalize(this);
    }
}
