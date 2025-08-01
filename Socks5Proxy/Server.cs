using System;
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
public class Server : IDisposable
{
    private readonly ProxyConfiguration _config;
    private readonly ILogger _logger;
    private TcpListener? _listener;
    private readonly List<ConnectionHandler> _activeConnections;
    private readonly object _connectionLock = new();
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the Server class.
    /// </summary>
    /// <param name="config">The proxy configuration.</param>
    /// <param name="logger">The logger instance.</param>
    public Server(ProxyConfiguration config, ILogger logger)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _activeConnections = new List<ConnectionHandler>();

        // Validate configuration
        if (!_config.IsValid(out string errorMessage))
        {
            throw new ArgumentException($"Invalid proxy configuration: {errorMessage}", nameof(config));
        }
    }

    /// <summary>
    /// Starts the SOCKS5 proxy server.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token to stop the server.</param>
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (!IPAddress.TryParse(_config.ListenIPAddress, out var listenAddress))
            {
                throw new InvalidOperationException($"Invalid IP address: {_config.ListenIPAddress}");
            }

            _listener = new TcpListener(listenAddress, _config.ListenPort);
            _listener.Start();

            var localEndPoint = _listener.LocalEndpoint;
            _logger.Information("SOCKS5 proxy server started on {LocalEndPoint}", localEndPoint);

            // Register cancellation callback to stop the listener
            using var registration = cancellationToken.Register(() =>
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
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    var tcpClient = await AcceptClientAsync(_listener, cancellationToken).ConfigureAwait(false);
                    
                    if (tcpClient != null)
                    {
                        // Handle client connection in background task
                        _ = Task.Run(async () => await HandleClientConnectionAsync(tcpClient, cancellationToken).ConfigureAwait(false), 
                                   cancellationToken);
                    }
                    else
                    {
                        // AcceptClientAsync returned null, likely due to cancellation
                        break;
                    }
                }
                catch (ObjectDisposedException)
                {
                    // Listener has been disposed, exit gracefully
                    break;
                }
                catch (InvalidOperationException)
                {
                    // Listener is not started or has been stopped
                    break;
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.Interrupted)
                {
                    // Server was stopped, exit gracefully
                    break;
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Error accepting client connection");
                    
                    // Brief delay to prevent tight loop on persistent errors
                    try
                    {
                        await Task.Delay(1000, cancellationToken).ConfigureAwait(false);
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
    /// Accepts a client connection with cancellation support.
    /// </summary>
    /// <param name="listener">The TCP listener.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The accepted TCP client or null if cancelled.</returns>
    private static async Task<TcpClient?> AcceptClientAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        try
        {
            // Create a task completion source that will be completed when cancellation is requested
            var tcs = new TaskCompletionSource<TcpClient>();
            
            // Register cancellation callback to cancel the task completion source
            using var registration = cancellationToken.Register(() => tcs.TrySetCanceled());
            
            // Start accepting the connection
            var acceptTask = listener.AcceptTcpClientAsync();
            
            // Wait for either the accept task to complete or cancellation
            var completedTask = await Task.WhenAny(acceptTask, tcs.Task).ConfigureAwait(false);
            
            if (completedTask == acceptTask)
            {
                return await acceptTask.ConfigureAwait(false);
            }
            else
            {
                // Cancellation was requested
                return null;
            }
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (ObjectDisposedException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>
    /// Handles an individual client connection.
    /// </summary>
    /// <param name="tcpClient">The connected TCP client.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task HandleClientConnectionAsync(TcpClient tcpClient, CancellationToken cancellationToken)
    {
        var clientEndPoint = tcpClient.Client.RemoteEndPoint?.ToString() ?? "Unknown";
        ConnectionHandler? handler = null;

        try
        {
            // Configure client socket
            tcpClient.ReceiveTimeout = 30000; // 30 seconds
            tcpClient.SendTimeout = 30000;    // 30 seconds
            tcpClient.NoDelay = true;         // Disable Nagle's algorithm for better latency

            handler = new ConnectionHandler(tcpClient, _logger);

            // Add to active connections
            lock (_connectionLock)
            {
                _activeConnections.Add(handler);
            }

            _logger.Debug("Added connection handler for client {ClientEndPoint}, total active: {ActiveCount}", 
                clientEndPoint, _activeConnections.Count);

            // Handle the connection
            await handler.HandleConnectionAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error handling client connection from {ClientEndPoint}", clientEndPoint);
        }
        finally
        {
            // Remove from active connections and dispose
            if (handler != null)
            {
                lock (_connectionLock)
                {
                    _activeConnections.Remove(handler);
                }

                try
                {
                    handler.Dispose();
                }
                catch (Exception ex)
                {
                    _logger.Error(ex, "Error disposing connection handler for {ClientEndPoint}", clientEndPoint);
                }

                _logger.Debug("Removed connection handler for client {ClientEndPoint}, total active: {ActiveCount}", 
                    clientEndPoint, _activeConnections.Count);
            }

            // Ensure client is properly closed
            try
            {
                tcpClient.Close();
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Error closing TCP client for {ClientEndPoint}", clientEndPoint);
            }
        }
    }

    /// <summary>
    /// Stops the SOCKS5 proxy server and closes all active connections.
    /// </summary>
    public async Task StopAsync()
    {
        if (_disposed)
            return;

        try
        {
            // Stop accepting new connections
            _listener?.Stop();

            // Close all active connections
            List<ConnectionHandler> connectionsToClose;
            lock (_connectionLock)
            {
                connectionsToClose = new List<ConnectionHandler>(_activeConnections);
                _activeConnections.Clear();
            }

            _logger.Information("Closing {Count} active connections", connectionsToClose.Count);

            // Dispose all connection handlers
            var disposeTasks = connectionsToClose.Select(handler =>
                Task.Run(() =>
                {
                    try
                    {
                        handler.Dispose();
                    }
                    catch (Exception ex)
                    {
                        _logger.Error(ex, "Error disposing connection handler during server shutdown");
                    }
                }));

            // Wait for all connections to close with timeout
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(10));
            var disposeTask = Task.WhenAll(disposeTasks);
            
            await Task.WhenAny(disposeTask, timeoutTask).ConfigureAwait(false);

            if (!disposeTask.IsCompleted)
            {
                _logger.Warning("Some connections did not close gracefully within timeout");
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
    public int ActiveConnectionCount
    {
        get
        {
            lock (_connectionLock)
            {
                return _activeConnections.Count;
            }
        }
    }

    /// <summary>
    /// Disposes the server and all its resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        try
        {
            StopAsync().Wait(TimeSpan.FromSeconds(15));
        }
        catch (Exception ex)
        {
            _logger.Error(ex, "Error during disposal");
        }

        GC.SuppressFinalize(this);
    }
}
