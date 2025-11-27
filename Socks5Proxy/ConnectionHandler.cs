using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Serilog;

namespace Socks5Proxy;

/// <summary>
/// Handles individual client connections for the SOCKS5 proxy server.
/// </summary>
public class ConnectionHandler : IDisposable, IAsyncDisposable
{
    private readonly TcpClient _client;
    private readonly ILogger _logger;
    private readonly NetworkStream _clientStream;
    private readonly FriendlyNameResolver _resolver;
    private TcpClient? _destinationClient;
    private NetworkStream? _destinationStream;
    private UdpRelay? _udpRelay;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the ConnectionHandler class.
    /// </summary>
    /// <param name="client">The connected TCP client.</param>
    /// <param name="logger">The logger instance.</param>
    /// <param name="resolver">Friendly name resolver for log formatting.</param>
    public ConnectionHandler(TcpClient client, ILogger logger, FriendlyNameResolver resolver)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _clientStream = _client.GetStream();
    }

    /// <summary>
    /// Handles the complete SOCKS5 connection flow.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token to stop processing.</param>
    public async Task HandleConnectionAsync(CancellationToken cancellationToken)
    {
        var clientEpObj = _client.Client.RemoteEndPoint;
        var clientEndPoint = clientEpObj?.ToString() ?? "Unknown";
    var friendlyClientSuffix = _resolver.FriendlySuffix(clientEpObj);
        
        try
        {
            _logger.Information("New client connection from {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);

            // Step 1: SOCKS5 handshake
            if (!await PerformHandshakeAsync(cancellationToken).ConfigureAwait(false))
            {
                _logger.Warning("Handshake failed for client {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);
                return;
            }

            // Step 2: Handle SOCKS5 request
            if (!await HandleSocks5RequestAsync(cancellationToken).ConfigureAwait(false))
            {
                _logger.Warning("SOCKS5 request handling failed for client {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);
                return;
            }

            // Step 3: Data forwarding (only for CONNECT command)
            if (_destinationClient != null && _destinationStream != null)
            {
                await ForwardDataAsync(cancellationToken).ConfigureAwait(false);
            }
            else if (_udpRelay != null)
            {
                // For UDP ASSOCIATE, keep the TCP connection alive until client disconnects
                await WaitForClientDisconnectionAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling connection from {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);
        }
        finally
        {
            _logger.Information("Connection closed for client {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);
        }
    }

    /// <summary>
    /// Performs the SOCKS5 handshake with the client.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if handshake was successful, otherwise false.</returns>
    private async Task<bool> PerformHandshakeAsync(CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(255);
        try
        {
            // Read client's method selection message - need at least 2 bytes for version and method count
            var totalRead = 0;
            while (totalRead < 2)
            {
                var bytesRead = await _clientStream.ReadAsync(buffer, totalRead, 2 - totalRead, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    _logger.Warning("Connection closed during handshake");
                    return false;
                }
                totalRead += bytesRead;
            }

            // Validate SOCKS version
            if (buffer[0] != Socks5Protocol.Version)
            {
                _logger.Warning("Unsupported SOCKS version: {Version}", buffer[0]);
                return false;
            }

            byte methodCount = buffer[1];
            if (methodCount == 0)
            {
                _logger.Warning("No authentication methods provided");
                return false;
            }

            // Read remaining method bytes
            while (totalRead < 2 + methodCount)
            {
                var bytesRead = await _clientStream.ReadAsync(buffer, totalRead, 2 + methodCount - totalRead, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    _logger.Warning("Connection closed during handshake while reading methods");
                    return false;
                }
                totalRead += bytesRead;
            }

            // Check if "No Authentication Required" method is supported
            bool noAuthSupported = false;
            for (int i = 0; i < methodCount; i++)
            {
                if (buffer[2 + i] == Socks5Protocol.AuthMethod.NoAuth)
                {
                    noAuthSupported = true;
                    break;
                }
            }

            // Send method selection response
            var response = new byte[2];
            response[0] = Socks5Protocol.Version;
            response[1] = noAuthSupported ? Socks5Protocol.AuthMethod.NoAuth : Socks5Protocol.AuthMethod.NoAcceptableMethods;

            await _clientStream.WriteAsync(response, 0, response.Length, cancellationToken).ConfigureAwait(false);

            if (!noAuthSupported)
            {
                _logger.Warning("Client does not support 'No Authentication Required' method");
                return false;
            }

            _logger.Debug("Handshake completed successfully");
            return true;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error during handshake");
            return false;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Handles the SOCKS5 connection request from the client.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if request was handled successfully, otherwise false.</returns>
    private async Task<bool> HandleSocks5RequestAsync(CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(4);
        try
        {
            // Read SOCKS5 request header (4 bytes) with proper short-read handling
            var totalRead = 0;
            while (totalRead < 4)
            {
                var bytesRead = await _clientStream.ReadAsync(buffer, totalRead, 4 - totalRead, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                {
                    await SendReplyAsync(Socks5Protocol.ReplyCode.GeneralFailure, null, cancellationToken).ConfigureAwait(false);
                    return false;
                }
                totalRead += bytesRead;
            }

            // Validate request format
            if (buffer[0] != Socks5Protocol.Version || buffer[2] != Socks5Protocol.Reserved)
            {
                await SendReplyAsync(Socks5Protocol.ReplyCode.GeneralFailure, null, cancellationToken).ConfigureAwait(false);
                return false;
            }

            byte command = buffer[1];
            byte addressType = buffer[3];

            // Return buffer early since we don't need it anymore
            ArrayPool<byte>.Shared.Return(buffer);
            buffer = null!;

            // Parse destination address and port
            var (address, port, parseResult) = await ParseDestinationAsync(addressType, cancellationToken).ConfigureAwait(false);
            
            if (parseResult != Socks5Protocol.ReplyCode.Succeeded)
            {
                await SendReplyAsync(parseResult, null, cancellationToken).ConfigureAwait(false);
                return false;
            }

            // Handle different commands
            return command switch
            {
                Socks5Protocol.Command.Connect => await HandleConnectCommandAsync(address!, port, cancellationToken).ConfigureAwait(false),
                Socks5Protocol.Command.UdpAssociate => await HandleUdpAssociateCommandAsync(cancellationToken).ConfigureAwait(false),
                Socks5Protocol.Command.Bind => await HandleUnsupportedCommandAsync(Socks5Protocol.ReplyCode.CommandNotSupported, cancellationToken).ConfigureAwait(false),
                _ => await HandleUnsupportedCommandAsync(Socks5Protocol.ReplyCode.CommandNotSupported, cancellationToken).ConfigureAwait(false)
            };
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling SOCKS5 request");
            await SendReplyAsync(Socks5Protocol.ReplyCode.GeneralFailure, null, cancellationToken).ConfigureAwait(false);
            return false;
        }
        finally
        {
            if (buffer != null)
                ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Reads exact number of bytes from stream, handling short reads.
    /// </summary>
    private async Task<bool> ReadExactAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        var totalRead = 0;
        while (totalRead < count)
        {
            var bytesRead = await _clientStream.ReadAsync(buffer, offset + totalRead, count - totalRead, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
                return false;
            totalRead += bytesRead;
        }
        return true;
    }

    /// <summary>
    /// Parses the destination address from the SOCKS5 request.
    /// </summary>
    /// <param name="addressType">The address type.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Tuple containing the address, port, and result code.</returns>
    private async Task<(string? address, int port, byte resultCode)> ParseDestinationAsync(byte addressType, CancellationToken cancellationToken)
    {
        byte[]? buffer = null;
        try
        {
            switch (addressType)
            {
                case Socks5Protocol.AddressType.IPv4:
                    {
                        buffer = ArrayPool<byte>.Shared.Rent(6); // 4 bytes IP + 2 bytes port
                        if (!await ReadExactAsync(buffer, 0, 6, cancellationToken).ConfigureAwait(false))
                            return (null, 0, Socks5Protocol.ReplyCode.GeneralFailure);

                        var ipBytes = new byte[4];
                        Array.Copy(buffer, 0, ipBytes, 0, 4);
                        var ipAddress = new IPAddress(ipBytes);
                        var port = (buffer[4] << 8) | buffer[5];
                        
                        return (ipAddress.ToString(), port, Socks5Protocol.ReplyCode.Succeeded);
                    }

                case Socks5Protocol.AddressType.IPv6:
                    {
                        buffer = ArrayPool<byte>.Shared.Rent(18); // 16 bytes IP + 2 bytes port
                        if (!await ReadExactAsync(buffer, 0, 18, cancellationToken).ConfigureAwait(false))
                            return (null, 0, Socks5Protocol.ReplyCode.GeneralFailure);

                        var ipBytes = new byte[16];
                        Array.Copy(buffer, 0, ipBytes, 0, 16);
                        var ipAddress = new IPAddress(ipBytes);
                        var port = (buffer[16] << 8) | buffer[17];
                        
                        return (ipAddress.ToString(), port, Socks5Protocol.ReplyCode.Succeeded);
                    }

                case Socks5Protocol.AddressType.DomainName:
                    {
                        buffer = ArrayPool<byte>.Shared.Rent(1);
                        if (!await ReadExactAsync(buffer, 0, 1, cancellationToken).ConfigureAwait(false))
                            return (null, 0, Socks5Protocol.ReplyCode.GeneralFailure);

                        byte domainLength = buffer[0];
                        ArrayPool<byte>.Shared.Return(buffer);
                        
                        buffer = ArrayPool<byte>.Shared.Rent(domainLength + 2); // domain + 2 bytes port
                        if (!await ReadExactAsync(buffer, 0, domainLength + 2, cancellationToken).ConfigureAwait(false))
                            return (null, 0, Socks5Protocol.ReplyCode.GeneralFailure);

                        var domain = Encoding.ASCII.GetString(buffer, 0, domainLength);
                        var port = (buffer[domainLength] << 8) | buffer[domainLength + 1];
                        
                        return (domain, port, Socks5Protocol.ReplyCode.Succeeded);
                    }

                default:
                    return (null, 0, Socks5Protocol.ReplyCode.AddressTypeNotSupported);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error parsing destination address");
            return (null, 0, Socks5Protocol.ReplyCode.GeneralFailure);
        }
        finally
        {
            if (buffer != null)
                ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Handles the CONNECT command by establishing a connection to the destination.
    /// </summary>
    /// <param name="address">The destination address.</param>
    /// <param name="port">The destination port.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if successful, otherwise false.</returns>
    private async Task<bool> HandleConnectCommandAsync(string address, int port, CancellationToken cancellationToken)
    {
        try
        {
            var clientEpObjForConnect = _client.Client.RemoteEndPoint;
            var clientEndPointForConnect = clientEpObjForConnect?.ToString() ?? "Unknown";
            var friendlyClientSuffixForConnect = _resolver.FriendlySuffix(clientEpObjForConnect);

            _logger.Information(
                "Connecting to {Address}{Friendly} for client {ClientEndPoint}{FriendlyClient}",
                $"{address}:{port}",
                _resolver.FriendlySuffixForAddressString(address),
                clientEndPointForConnect,
                friendlyClientSuffixForConnect);

            _destinationClient = new TcpClient();
            
            try
            {
                await _destinationClient.ConnectAsync(address, port, cancellationToken).ConfigureAwait(false);
                _destinationStream = _destinationClient.GetStream();
            }
            catch (SocketException ex)
            {
                _logger.Warning(
                    ex,
                    "Failed to connect to {Address}{Friendly} for client {ClientEndPoint}{FriendlyClient}",
                    $"{address}:{port}",
                    _resolver.FriendlySuffixForAddressString(address),
                    clientEndPointForConnect,
                    friendlyClientSuffixForConnect);
                
                var replyCode = ex.SocketErrorCode switch
                {
                    SocketError.HostUnreachable => Socks5Protocol.ReplyCode.HostUnreachable,
                    SocketError.NetworkUnreachable => Socks5Protocol.ReplyCode.NetworkUnreachable,
                    SocketError.ConnectionRefused => Socks5Protocol.ReplyCode.ConnectionRefused,
                    SocketError.TimedOut => Socks5Protocol.ReplyCode.TtlExpired,
                    _ => Socks5Protocol.ReplyCode.GeneralFailure
                };

                await SendReplyAsync(replyCode, null, cancellationToken).ConfigureAwait(false);
                return false;
            }

            // Send success reply - add null check for LocalEndPoint
            var localEndPointObj = _destinationClient.Client.LocalEndPoint;
            if (localEndPointObj is not IPEndPoint localEndPoint)
            {
                _logger.Warning("LocalEndPoint is null or not IPEndPoint after successful connection");
                await SendReplyAsync(Socks5Protocol.ReplyCode.GeneralFailure, null, cancellationToken).ConfigureAwait(false);
                return false;
            }
            await SendReplyAsync(Socks5Protocol.ReplyCode.Succeeded, localEndPoint, cancellationToken).ConfigureAwait(false);
            
            _logger.Information(
                "Successfully connected to {Address}{Friendly} for client {ClientEndPoint}{FriendlyClient}",
                $"{address}:{port}",
                _resolver.FriendlySuffixForAddressString(address),
                clientEndPointForConnect,
                friendlyClientSuffixForConnect);
            return true;
        }
        catch (Exception ex)
        {
            // Recompute client endpoint defensively in catch
            var clientEpObjForConnect = _client.Client.RemoteEndPoint;
            var clientEndPointForConnect = clientEpObjForConnect?.ToString() ?? "Unknown";
            var friendlyClientSuffixForConnect = _resolver.FriendlySuffix(clientEpObjForConnect);

            _logger.Error(
                ex,
                "Error handling CONNECT command to {Address}{Friendly} for client {ClientEndPoint}{FriendlyClient}",
                $"{address}:{port}",
                _resolver.FriendlySuffixForAddressString(address),
                clientEndPointForConnect,
                friendlyClientSuffixForConnect);
            await SendReplyAsync(Socks5Protocol.ReplyCode.GeneralFailure, null, cancellationToken).ConfigureAwait(false);
            return false;
        }
    }

    /// <summary>
    /// Handles the UDP ASSOCIATE command by setting up UDP relay.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if successful, otherwise false.</returns>
    private async Task<bool> HandleUdpAssociateCommandAsync(CancellationToken cancellationToken)
    {
        try
        {
            _logger.Information("Setting up UDP ASSOCIATE");

            var clientEndPoint = (IPEndPoint)_client.Client.RemoteEndPoint!;
            _udpRelay = new UdpRelay(clientEndPoint, _logger, _resolver);

            // Send success reply with UDP relay endpoint
            await SendReplyAsync(Socks5Protocol.ReplyCode.Succeeded, _udpRelay.LocalEndPoint, cancellationToken).ConfigureAwait(false);
            
            _logger.Information("UDP ASSOCIATE setup completed, relay listening on {UdpEndPoint}{Friendly}",
                _udpRelay.LocalEndPoint,
                _resolver.FriendlySuffix(_udpRelay.LocalEndPoint));
            return true;
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling UDP ASSOCIATE command");
            await SendReplyAsync(Socks5Protocol.ReplyCode.GeneralFailure, null, cancellationToken).ConfigureAwait(false);
            return false;
        }
    }

    /// <summary>
    /// Handles unsupported commands.
    /// </summary>
    /// <param name="replyCode">The reply code to send.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>False since the command is not supported.</returns>
    private async Task<bool> HandleUnsupportedCommandAsync(byte replyCode, CancellationToken cancellationToken)
    {
        await SendReplyAsync(replyCode, null, cancellationToken).ConfigureAwait(false);
        return false;
    }

    /// <summary>
    /// Sends a SOCKS5 reply to the client.
    /// </summary>
    /// <param name="replyCode">The reply code.</param>
    /// <param name="boundEndPoint">The bound endpoint (optional).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task SendReplyAsync(byte replyCode, IPEndPoint? boundEndPoint = null, CancellationToken cancellationToken = default)
    {
        // Max response size: 1 (ver) + 1 (rep) + 1 (rsv) + 1 (atyp) + 16 (IPv6) + 2 (port) = 22 bytes
        var buffer = ArrayPool<byte>.Shared.Rent(22);
        try
        {
            int offset = 0;
            buffer[offset++] = Socks5Protocol.Version;
            buffer[offset++] = replyCode;
            buffer[offset++] = Socks5Protocol.Reserved;

            if (boundEndPoint == null)
            {
                // Use IPv4 zero address if no bound endpoint provided
                buffer[offset++] = Socks5Protocol.AddressType.IPv4;
                buffer[offset++] = 0; // 0.0.0.0
                buffer[offset++] = 0;
                buffer[offset++] = 0;
                buffer[offset++] = 0;
                buffer[offset++] = 0; // Port 0
                buffer[offset++] = 0;
            }
            else
            {
                if (boundEndPoint.AddressFamily == AddressFamily.InterNetwork)
                {
                    buffer[offset++] = Socks5Protocol.AddressType.IPv4;
                    var addressBytes = boundEndPoint.Address.GetAddressBytes();
                    Array.Copy(addressBytes, 0, buffer, offset, 4);
                    offset += 4;
                }
                else if (boundEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    buffer[offset++] = Socks5Protocol.AddressType.IPv6;
                    var addressBytes = boundEndPoint.Address.GetAddressBytes();
                    Array.Copy(addressBytes, 0, buffer, offset, 16);
                    offset += 16;
                }

                buffer[offset++] = (byte)(boundEndPoint.Port >> 8);
                buffer[offset++] = (byte)(boundEndPoint.Port & 0xFF);
            }

            await _clientStream.WriteAsync(buffer, 0, offset, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error sending SOCKS5 reply");
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Forwards data between client and destination using high-performance pipelines.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task ForwardDataAsync(CancellationToken cancellationToken)
    {
        if (_destinationStream == null)
            return;

        // Create a linked cancellation token to coordinate shutdown when one direction fails
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var linkedToken = linkedCts.Token;

        try
        {
            _logger.Debug("Starting data forwarding");

            // Configure pipe options for better network I/O performance
            var pipeOptions = new PipeOptions(
                pool: MemoryPool<byte>.Shared,
                minimumSegmentSize: 4096,
                pauseWriterThreshold: 64 * 1024,
                resumeWriterThreshold: 32 * 1024);

            // Create pipes for bidirectional data flow
            var clientToDestinationPipe = new Pipe(pipeOptions);
            var destinationToClientPipe = new Pipe(pipeOptions);

            // Start forwarding tasks
            var tasks = new[]
            {
                ForwardStreamToPipeAsync(_clientStream, clientToDestinationPipe.Writer, "Client->Destination", linkedToken),
                ForwardPipeToStreamAsync(clientToDestinationPipe.Reader, _destinationStream, "Client->Destination", linkedToken),
                ForwardStreamToPipeAsync(_destinationStream, destinationToClientPipe.Writer, "Destination->Client", linkedToken),
                ForwardPipeToStreamAsync(destinationToClientPipe.Reader, _clientStream, "Destination->Client", linkedToken)
            };

            // Wait for any task to complete (indicating one side closed)
            await Task.WhenAny(tasks).ConfigureAwait(false);
            
            // Cancel remaining tasks to ensure clean shutdown
            linkedCts.Cancel();

            // Wait for all tasks to complete with a timeout to ensure proper cleanup
            try
            {
                await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected when tasks are cancelled
            }
            catch (TimeoutException)
            {
                _logger.Warning("Timeout waiting for forwarding tasks to complete");
            }
            
            _logger.Debug("Data forwarding completed");
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error during data forwarding");
        }
    }

    /// <summary>
    /// Forwards data from a stream to a pipe writer.
    /// </summary>
    /// <param name="stream">The source stream.</param>
    /// <param name="writer">The destination pipe writer.</param>
    /// <param name="direction">Direction description for logging.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task ForwardStreamToPipeAsync(Stream stream, PipeWriter writer, string direction, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var memory = writer.GetMemory(4096);
                var bytesRead = await stream.ReadAsync(memory, cancellationToken).ConfigureAwait(false);
                
                if (bytesRead == 0)
                    break;

                writer.Advance(bytesRead);
                var result = await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                
                if (result.IsCompleted)
                    break;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Debug(ex, "Stream to pipe forwarding ended ({Direction})", direction);
        }
        finally
        {
            await writer.CompleteAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Forwards data from a pipe reader to a stream.
    /// </summary>
    /// <param name="reader">The source pipe reader.</param>
    /// <param name="stream">The destination stream.</param>
    /// <param name="direction">Direction description for logging.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task ForwardPipeToStreamAsync(PipeReader reader, Stream stream, string direction, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var result = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                var buffer = result.Buffer;

                if (buffer.IsEmpty && result.IsCompleted)
                    break;

                foreach (var segment in buffer)
                {
                    await stream.WriteAsync(segment, cancellationToken).ConfigureAwait(false);
                }

                reader.AdvanceTo(buffer.End);

                if (result.IsCompleted)
                    break;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Debug(ex, "Pipe to stream forwarding ended ({Direction})", direction);
        }
        finally
        {
            await reader.CompleteAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Waits for client disconnection (used for UDP ASSOCIATE).
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task WaitForClientDisconnectionAsync(CancellationToken cancellationToken)
    {
        try
        {
            var buffer = new byte[1];
            while (!cancellationToken.IsCancellationRequested && _client.Connected)
            {
                var bytesRead = await _clientStream.ReadAsync(buffer, 0, 1, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                    break; // Client disconnected
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Debug(ex, "Client disconnection detected");
        }
    }

    /// <summary>
    /// Asynchronously disposes the connection handler and all associated resources.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;

        _disposed = true;

        try
        {
            if (_udpRelay != null)
            {
                await _udpRelay.StopAsync().ConfigureAwait(false);
                _udpRelay.Dispose();
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error stopping UDP relay during async disposal");
        }

        try
        {
            _destinationStream?.Dispose();
            _destinationClient?.Close();
            // Note: _clientStream is owned by _client, disposing _client will dispose the stream
            _client?.Close();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error disposing connection resources during async disposal");
        }

        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes the connection handler and all associated resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        try
        {
            // Use GetAwaiter().GetResult() for cleaner exception handling
            _udpRelay?.StopAsync().GetAwaiter().GetResult();
            _udpRelay?.Dispose();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error stopping UDP relay during disposal");
        }

        try
        {
            _destinationStream?.Dispose();
            _destinationClient?.Close();
            // Note: _clientStream is owned by _client, disposing _client will dispose the stream
            _client?.Close();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error disposing connection resources");
        }

        GC.SuppressFinalize(this);
    }
}
