using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Serilog;

namespace Socks5Proxy;

/// <summary>
/// SOCKS5 proxy server that handles incoming client connections.
/// </summary>
public class Server : IDisposable, IAsyncDisposable
{
    private readonly ProxyConfiguration _config;
    private readonly ILogger _logger;
    private readonly FriendlyNameResolver _resolver;
    private readonly SemaphoreSlim? _connectionSlots;
    private readonly CancellationTokenSource _shutdownTokenSource;
    private TcpListener? _listener;
    private readonly ConcurrentDictionary<int, ConnectionHandler> _activeConnections;
    private readonly ConcurrentDictionary<int, Task> _connectionTasks;
    private int _connectionIdCounter;
    private int _stopped;
    private int _disposed;

    /// <summary>
    /// Initializes a new instance of the Server class.
    /// </summary>
    /// <param name="config">The proxy configuration.</param>
    /// <param name="logger">The logger instance.</param>
    /// <param name="resolver">The friendly name resolver.</param>
    public Server(ProxyConfiguration config, ILogger logger, FriendlyNameResolver resolver)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
        _connectionSlots = _config.MaxConnections > 0
            ? new SemaphoreSlim(_config.MaxConnections, _config.MaxConnections)
            : null;
        _shutdownTokenSource = new CancellationTokenSource();
        _activeConnections = new ConcurrentDictionary<int, ConnectionHandler>();
        _connectionTasks = new ConcurrentDictionary<int, Task>();

        // Validate configuration
        if (!_config.IsValid(out string errorMessage))
        {
            throw new ArgumentException($"Invalid proxy configuration: {errorMessage}", nameof(config));
        }
    }

    /// <summary>
    /// Backward compatible constructor that creates a no-op resolver.
    /// </summary>
    public Server(ProxyConfiguration config, ILogger logger)
        : this(config, logger, new FriendlyNameResolver(null, logger))
    {
    }

    /// <summary>
    /// Starts the SOCKS5 proxy server.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token to stop the server.</param>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var linkedCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdownTokenSource.Token);
            var serverCancellationToken = linkedCancellationTokenSource.Token;

            if (!IPAddress.TryParse(_config.ListenIPAddress, out var listenAddress))
            {
                throw new InvalidOperationException($"Invalid IP address: {_config.ListenIPAddress}");
            }

            _listener = new TcpListener(listenAddress, _config.ListenPort);
            _listener.Start();

            var localEndPoint = _listener.LocalEndpoint;
            _logger.Information(
                "SOCKS5 proxy server started on {LocalEndPoint}{Friendly}",
                localEndPoint,
                _resolver.FriendlySuffix(localEndPoint));

            // Register cancellation callback to stop the listener
            using var registration = serverCancellationToken.Register(() =>
            {
                try
                {
                    _listener?.Stop();
                }
                catch (Exception ex)
                {
                    _logger.Warning(ex, "Error stopping listener during cancellation");
                }
            });

            // Accept connections loop
            while (!serverCancellationToken.IsCancellationRequested)
            {
                var slotReserved = false;

                try
                {
                    if (_connectionSlots != null)
                    {
                        await _connectionSlots.WaitAsync(serverCancellationToken).ConfigureAwait(false);
                        slotReserved = true;
                    }

                    var tcpClient = await _listener.AcceptTcpClientAsync(serverCancellationToken).ConfigureAwait(false);

                    // Handle client connection in background task
                    var connectionId = Interlocked.Increment(ref _connectionIdCounter);
                    var task = Task.Run(async () => await HandleClientConnectionAsync(tcpClient, connectionId, serverCancellationToken).ConfigureAwait(false),
                                       CancellationToken.None);
                    _connectionTasks[connectionId] = task;
                    slotReserved = false;
                }
                catch (OperationCanceledException)
                {
                    if (slotReserved)
                    {
                        ReleaseConnectionSlot();
                    }

                    // Cancellation requested, exit gracefully
                    break;
                }
                catch (ObjectDisposedException)
                {
                    if (slotReserved)
                    {
                        ReleaseConnectionSlot();
                    }

                    // Listener has been disposed, exit gracefully
                    break;
                }
                catch (InvalidOperationException)
                {
                    if (slotReserved)
                    {
                        ReleaseConnectionSlot();
                    }

                    // Listener is not started or has been stopped
                    break;
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.Interrupted)
                {
                    if (slotReserved)
                    {
                        ReleaseConnectionSlot();
                    }

                    // Server was stopped, exit gracefully
                    break;
                }
                catch (Exception ex)
                {
                    if (slotReserved)
                    {
                        ReleaseConnectionSlot();
                    }

                    _logger.Error(ex, "Error accepting client connection");
                    
                    // Brief delay to prevent tight loop on persistent errors
                    try
                    {
                        await Task.Delay(1000, serverCancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Fatal error in SOCKS5 proxy server");
            throw;
        }
        finally
        {
            await StopAsync().ConfigureAwait(false);
            _logger.Information("SOCKS5 proxy server stopped");
        }
    }

    /// <summary>
    /// Handles an individual client connection.
    /// </summary>
    /// <param name="tcpClient">The connected TCP client.</param>
    /// <param name="connectionId">The unique connection identifier.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task HandleClientConnectionAsync(TcpClient tcpClient, int connectionId, CancellationToken cancellationToken)
    {
        var clientEndPointObj = tcpClient.Client.RemoteEndPoint;
        var clientEndPoint = clientEndPointObj?.ToString() ?? "Unknown";
        var friendlyClientSuffix = _resolver.FriendlySuffix(clientEndPointObj);
        ConnectionHandler? handler = null;

        try
        {
            // Configure client socket
            tcpClient.ReceiveTimeout = 30000; // 30 seconds
            tcpClient.SendTimeout = 30000;    // 30 seconds
            tcpClient.NoDelay = true;         // Disable Nagle's algorithm for better latency

            handler = new ConnectionHandler(tcpClient, _logger, _resolver);

            // Add to active connections using ConcurrentDictionary
            _activeConnections.TryAdd(connectionId, handler);

            _logger.Debug(
                "Added connection handler for client {ClientEndPoint}{Friendly}, total active: {ActiveCount}",
                clientEndPoint,
                friendlyClientSuffix,
                _activeConnections.Count);

            // Handle the connection
            await handler.HandleConnectionAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling client connection from {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);
        }
        finally
        {
            // Remove from active connections and dispose
            if (handler != null)
            {
                _activeConnections.TryRemove(connectionId, out _);

                try
                {
                    handler.Dispose();
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Error disposing connection handler for {ClientEndPoint}", clientEndPoint);
                }

                _logger.Debug(
                    "Removed connection handler for client {ClientEndPoint}{Friendly}, total active: {ActiveCount}",
                    clientEndPoint,
                    friendlyClientSuffix,
                    _activeConnections.Count);
            }

            if (_connectionSlots != null)
            {
                ReleaseConnectionSlot();
            }

            // Remove task tracking entry
            _connectionTasks.TryRemove(connectionId, out _);

            // Ensure client is properly closed
            try
            {
                tcpClient.Close();
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Error closing TCP client for {ClientEndPoint}{Friendly}", clientEndPoint, friendlyClientSuffix);
            }
        }
    }

    /// <summary>
    /// Stops the SOCKS5 proxy server and closes all active connections.
    /// </summary>
    public async Task StopAsync()
    {
        if (Interlocked.CompareExchange(ref _stopped, 1, 0) != 0)
            return;

        try
        {
            _shutdownTokenSource.Cancel();

            // Stop accepting new connections
            _listener?.Stop();

            // Wait for active connection tasks to complete (they clean up after themselves)
            var tasks = _connectionTasks.Values.ToArray();
            _logger.Information("Waiting for {Count} active connections to finish", tasks.Length);

            try
            {
                await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                _logger.Warning("Some connections did not close gracefully within timeout");
            }
            catch (Exception ex)
            {
                _logger.Warning(ex, "Error while waiting for connections to close");
            }
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error during server shutdown");
        }
    }

    /// <summary>
    /// Gets the current number of active connections.
    /// </summary>
    public int ActiveConnectionCount => _activeConnections.Count;

    private void ReleaseConnectionSlot()
    {
        try
        {
            _connectionSlots?.Release();
        }
        catch (ObjectDisposedException)
        {
            // Late connection cleanup can race with server disposal.
        }
    }

    /// <summary>
    /// Asynchronously disposes the server and all its resources.
    /// </summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
            return;

        try
        {
            await StopAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error during async disposal");
        }
        finally
        {
            _connectionSlots?.Dispose();
            _shutdownTokenSource.Dispose();
        }

        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Disposes the server and all its resources.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
            return;

        try
        {
            // Use GetAwaiter().GetResult() instead of Wait() to avoid wrapping exceptions
            StopAsync().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error during disposal");
        }
        finally
        {
            _connectionSlots?.Dispose();
            _shutdownTokenSource.Dispose();
        }

        GC.SuppressFinalize(this);
    }
}
