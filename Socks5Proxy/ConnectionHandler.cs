using System;
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
public class ConnectionHandler : IDisposable
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
        try
        {
            // Read client's method selection message
            var buffer = new byte[255];
            var bytesRead = await _clientStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
            
            if (bytesRead < 3)
            {
                _logger.Warning("Invalid handshake message length: {Length}", bytesRead);
                return false;
            }

            // Validate SOCKS version
            if (buffer[0] != Socks5Protocol.Version)
            {
                _logger.Warning("Unsupported SOCKS version: {Version}", buffer[0]);
                return false;
            }

            byte methodCount = buffer[1];
            if (bytesRead < 2 + methodCount)
            {
                _logger.Warning("Incomplete handshake message");
                return false;
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
    }

    /// <summary>
    /// Handles the SOCKS5 connection request from the client.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if request was handled successfully, otherwise false.</returns>
    private async Task<bool> HandleSocks5RequestAsync(CancellationToken cancellationToken)
    {
        try
        {
            // Read SOCKS5 request
            var buffer = new byte[262]; // Max domain name length + header
            var bytesRead = await _clientStream.ReadAsync(buffer, 0, 4, cancellationToken).ConfigureAwait(false);
            
            if (bytesRead != 4)
            {
                await SendReplyAsync(Socks5Protocol.ReplyCode.GeneralFailure, null, cancellationToken).ConfigureAwait(false);
                return false;
            }

            // Validate request format
            if (buffer[0] != Socks5Protocol.Version || buffer[2] != Socks5Protocol.Reserved)
            {
                await SendReplyAsync(Socks5Protocol.ReplyCode.GeneralFailure, null, cancellationToken).ConfigureAwait(false);
                return false;
            }

            byte command = buffer[1];
            byte addressType = buffer[3];

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
    }

    /// <summary>
    /// Parses the destination address from the SOCKS5 request.
    /// </summary>
    /// <param name="addressType">The address type.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Tuple containing the address, port, and result code.</returns>
    private async Task<(string? address, int port, byte resultCode)> ParseDestinationAsync(byte addressType, CancellationToken cancellationToken)
    {
        try
        {
            switch (addressType)
            {
                case Socks5Protocol.AddressType.IPv4:
                    {
                        var buffer = new byte[6]; // 4 bytes IP + 2 bytes port
                        var bytesRead = await _clientStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                        if (bytesRead != 6)
                            return (null, 0, Socks5Protocol.ReplyCode.GeneralFailure);

                        var ipBytes = new byte[4];
                        Array.Copy(buffer, 0, ipBytes, 0, 4);
                        var ipAddress = new IPAddress(ipBytes);
                        var port = (buffer[4] << 8) | buffer[5];
                        
                        return (ipAddress.ToString(), port, Socks5Protocol.ReplyCode.Succeeded);
                    }

                case Socks5Protocol.AddressType.IPv6:
                    {
                        var buffer = new byte[18]; // 16 bytes IP + 2 bytes port
                        var bytesRead = await _clientStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                        if (bytesRead != 18)
                            return (null, 0, Socks5Protocol.ReplyCode.GeneralFailure);

                        var ipBytes = new byte[16];
                        Array.Copy(buffer, 0, ipBytes, 0, 16);
                        var ipAddress = new IPAddress(ipBytes);
                        var port = (buffer[16] << 8) | buffer[17];
                        
                        return (ipAddress.ToString(), port, Socks5Protocol.ReplyCode.Succeeded);
                    }

                case Socks5Protocol.AddressType.DomainName:
                    {
                        var lengthBuffer = new byte[1];
                        var bytesRead = await _clientStream.ReadAsync(lengthBuffer, 0, 1, cancellationToken).ConfigureAwait(false);
                        if (bytesRead != 1)
                            return (null, 0, Socks5Protocol.ReplyCode.GeneralFailure);

                        byte domainLength = lengthBuffer[0];
                        var buffer = new byte[domainLength + 2]; // domain + 2 bytes port
                        bytesRead = await _clientStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                        if (bytesRead != buffer.Length)
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

            // Send success reply
            var localEndPoint = (IPEndPoint)_destinationClient.Client.LocalEndPoint!;
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
        try
        {
            var response = new List<byte>
            {
                Socks5Protocol.Version,
                replyCode,
                Socks5Protocol.Reserved
            };

            if (boundEndPoint == null)
            {
                // Use IPv4 zero address if no bound endpoint provided
                response.Add(Socks5Protocol.AddressType.IPv4);
                response.AddRange(new byte[] { 0, 0, 0, 0 }); // 0.0.0.0
                response.AddRange(new byte[] { 0, 0 }); // Port 0
            }
            else
            {
                if (boundEndPoint.AddressFamily == AddressFamily.InterNetwork)
                {
                    response.Add(Socks5Protocol.AddressType.IPv4);
                    response.AddRange(boundEndPoint.Address.GetAddressBytes());
                }
                else if (boundEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    response.Add(Socks5Protocol.AddressType.IPv6);
                    response.AddRange(boundEndPoint.Address.GetAddressBytes());
                }

                response.Add((byte)(boundEndPoint.Port >> 8));
                response.Add((byte)(boundEndPoint.Port & 0xFF));
            }

            await _clientStream.WriteAsync(response.ToArray(), 0, response.Count, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error sending SOCKS5 reply");
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

        try
        {
            _logger.Debug("Starting data forwarding");

            // Create pipes for bidirectional data flow
            var clientToDestinationPipe = new Pipe();
            var destinationToClientPipe = new Pipe();

            // Start forwarding tasks
            var tasks = new[]
            {
                ForwardStreamToPipeAsync(_clientStream, clientToDestinationPipe.Writer, "Client->Destination", cancellationToken),
                ForwardPipeToStreamAsync(clientToDestinationPipe.Reader, _destinationStream, "Client->Destination", cancellationToken),
                ForwardStreamToPipeAsync(_destinationStream, destinationToClientPipe.Writer, "Destination->Client", cancellationToken),
                ForwardPipeToStreamAsync(destinationToClientPipe.Reader, _clientStream, "Destination->Client", cancellationToken)
            };

            // Wait for any task to complete (indicating one side closed)
            await Task.WhenAny(tasks).ConfigureAwait(false);
            
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
    /// Disposes the connection handler and all associated resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        try
        {
            _udpRelay?.StopAsync().Wait(TimeSpan.FromSeconds(5));
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
            _clientStream?.Dispose();
            _client?.Close();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error disposing connection resources");
        }

        GC.SuppressFinalize(this);
    }
}
