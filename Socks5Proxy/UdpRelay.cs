using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Serilog;

namespace Socks5Proxy;

/// <summary>
/// UDP relay handler for SOCKS5 UDP ASSOCIATE command.
/// </summary>
public class UdpRelay : IDisposable
{
    private readonly ILogger _logger;
    private readonly UdpClient _udpClient;
    private readonly IPEndPoint _clientEndPoint;
    private readonly CancellationTokenSource _cancellationTokenSource;
    private readonly Task _relayTask;
    private bool _disposed;

    /// <summary>
    /// Gets the local endpoint where the UDP relay is listening.
    /// </summary>
    public IPEndPoint LocalEndPoint { get; }

    /// <summary>
    /// Initializes a new instance of the UdpRelay class.
    /// </summary>
    /// <param name="clientEndPoint">The client endpoint that will send UDP packets.</param>
    /// <param name="logger">The logger instance.</param>
    public UdpRelay(IPEndPoint clientEndPoint, ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _clientEndPoint = clientEndPoint ?? throw new ArgumentNullException(nameof(clientEndPoint));
        _cancellationTokenSource = new CancellationTokenSource();

        // Create UDP client and bind to any available port
        _udpClient = new UdpClient(0);
        LocalEndPoint = (IPEndPoint)_udpClient.Client.LocalEndPoint!;

        _logger.Information("UDP relay started on {LocalEndPoint} for client {ClientEndPoint}",
            LocalEndPoint, _clientEndPoint);

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
                    var result = await _udpClient.ReceiveAsync().ConfigureAwait(false);
                    
                    // Check if the packet is from our client
                    if (result.RemoteEndPoint.Equals(_clientEndPoint))
                    {
                        // Parse SOCKS5 UDP header and forward to destination
                        await HandleClientPacketAsync(result.Buffer, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        // Forward response back to client with SOCKS5 UDP header
                        await HandleServerResponseAsync(result.Buffer, result.RemoteEndPoint, cancellationToken).ConfigureAwait(false);
                    }
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
                    _logger.Error(ex, "Error in UDP relay for client {ClientEndPoint}", _clientEndPoint);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Fatal error in UDP relay for client {ClientEndPoint}", _clientEndPoint);
        }
        finally
        {
            _logger.Information("UDP relay stopped for client {ClientEndPoint}", _clientEndPoint);
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
                _logger.Warning("Received UDP packet too small from client {ClientEndPoint}", _clientEndPoint);
                return;
            }

            int offset = 0;
            
            // Skip RSV (2 bytes) and FRAG (1 byte)
            offset += 3;
            
            byte addressType = buffer[offset++];
            IPEndPoint? destinationEndPoint = null;

            switch (addressType)
            {
                case Socks5Protocol.AddressType.IPv4:
                    if (buffer.Length < offset + 6) return; // 4 bytes IP + 2 bytes port
                    var ipv4Bytes = new byte[4];
                    Array.Copy(buffer, offset, ipv4Bytes, 0, 4);
                    offset += 4;
                    var ipv4Address = new IPAddress(ipv4Bytes);
                    var port = (buffer[offset] << 8) | buffer[offset + 1];
                    offset += 2;
                    destinationEndPoint = new IPEndPoint(ipv4Address, port);
                    break;

                case Socks5Protocol.AddressType.IPv6:
                    if (buffer.Length < offset + 18) return; // 16 bytes IP + 2 bytes port
                    var ipv6Bytes = new byte[16];
                    Array.Copy(buffer, offset, ipv6Bytes, 0, 16);
                    offset += 16;
                    var ipv6Address = new IPAddress(ipv6Bytes);
                    port = (buffer[offset] << 8) | buffer[offset + 1];
                    offset += 2;
                    destinationEndPoint = new IPEndPoint(ipv6Address, port);
                    break;

                case Socks5Protocol.AddressType.DomainName:
                    if (buffer.Length < offset + 1) return;
                    byte domainLength = buffer[offset++];
                    if (buffer.Length < offset + domainLength + 2) return;
                    var domainBytes = new byte[domainLength];
                    Array.Copy(buffer, offset, domainBytes, 0, domainLength);
                    offset += domainLength;
                    var domain = System.Text.Encoding.ASCII.GetString(domainBytes);
                    port = (buffer[offset] << 8) | buffer[offset + 1];
                    offset += 2;
                    
                    // Resolve domain name
                    try
                    {
                        var addresses = await Dns.GetHostAddressesAsync(domain).ConfigureAwait(false);
                        var targetAddress = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) 
                                          ?? addresses.FirstOrDefault();
                        if (targetAddress != null)
                        {
                            destinationEndPoint = new IPEndPoint(targetAddress, port);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.Warning(ex, "Failed to resolve domain {Domain} for UDP relay", domain);
                        return;
                    }
                    break;

                default:
                    _logger.Warning("Unsupported address type {AddressType} in UDP packet from client {ClientEndPoint}", 
                        addressType, _clientEndPoint);
                    return;
            }

            if (destinationEndPoint == null)
            {
                _logger.Warning("Could not determine destination endpoint from UDP packet");
                return;
            }

            // Extract payload data
            var payloadLength = buffer.Length - offset;
            var payload = new byte[payloadLength];
            Array.Copy(buffer, offset, payload, 0, payloadLength);

            // Forward to destination
            await _udpClient.SendAsync(payload, destinationEndPoint).ConfigureAwait(false);
            
            _logger.Debug("Forwarded UDP packet from client {ClientEndPoint} to {DestinationEndPoint}, size: {Size}",
                _clientEndPoint, destinationEndPoint, payloadLength);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling client UDP packet from {ClientEndPoint}", _clientEndPoint);
        }
    }

    /// <summary>
    /// Handles response from destination server and forwards back to client with SOCKS5 UDP header.
    /// </summary>
    /// <param name="buffer">The response buffer from destination.</param>
    /// <param name="sourceEndPoint">The source endpoint of the response.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task HandleServerResponseAsync(byte[] buffer, IPEndPoint sourceEndPoint, CancellationToken cancellationToken)
    {
        try
        {
            // Create SOCKS5 UDP header
            var headerLength = sourceEndPoint.AddressFamily == AddressFamily.InterNetwork ? 10 : 22; // IPv4: 10, IPv6: 22
            var responseBuffer = new byte[headerLength + buffer.Length];
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
                var addressBytes = sourceEndPoint.Address.GetAddressBytes();
                Array.Copy(addressBytes, 0, responseBuffer, offset, 4);
                offset += 4;
            }
            else if (sourceEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                responseBuffer[offset++] = Socks5Protocol.AddressType.IPv6;
                var addressBytes = sourceEndPoint.Address.GetAddressBytes();
                Array.Copy(addressBytes, 0, responseBuffer, offset, 16);
                offset += 16;
            }

            // Port (2 bytes)
            responseBuffer[offset++] = (byte)(sourceEndPoint.Port >> 8);
            responseBuffer[offset++] = (byte)(sourceEndPoint.Port & 0xFF);

            // Payload
            Array.Copy(buffer, 0, responseBuffer, offset, buffer.Length);

            // Send back to client
            await _udpClient.SendAsync(responseBuffer, _clientEndPoint).ConfigureAwait(false);
            
            _logger.Debug("Forwarded UDP response from {SourceEndPoint} to client {ClientEndPoint}, size: {Size}",
                sourceEndPoint, _clientEndPoint, buffer.Length);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling server UDP response from {SourceEndPoint}", sourceEndPoint);
        }
    }

    /// <summary>
    /// Stops the UDP relay.
    /// </summary>
    public async Task StopAsync()
    {
        if (_disposed) return;

        _cancellationTokenSource.Cancel();
        
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
            _logger.Error(ex, "Error stopping UDP relay for client {ClientEndPoint}", _clientEndPoint);
        }
    }

    /// <summary>
    /// Disposes the UDP relay resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        
        _disposed = true;
        _cancellationTokenSource.Cancel();
        _udpClient?.Dispose();
        _cancellationTokenSource?.Dispose();
        
        GC.SuppressFinalize(this);
    }
}
