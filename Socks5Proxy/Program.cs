using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Serilog;

namespace Socks5Proxy;

/// <summary>
/// Main program entry point for the SOCKS5 proxy server.
/// </summary>
public class Program
{
    /// <summary>
    /// Main entry point of the application.
    /// </summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>Exit code (0 for success, non-zero for error).</returns>
    public static async Task<int> Main(string[] args)
    {
        ILogger? logger = null;
        Server? server = null;

        try
        {
            // Build configuration
            var configuration = BuildConfiguration(args);

            // Configure logging
            logger = ConfigureLogging(configuration);
            logger.Information("SOCKS5 Proxy Server starting...");

            // Load and validate proxy configuration
            var proxyConfig = LoadProxyConfiguration(configuration, logger);
            if (proxyConfig == null)
            {
                return 1; // Error loading configuration
            }

            // Create friendly name resolver (safe even if no mappings)
            var resolver = new FriendlyNameResolver(proxyConfig.IPAddressMappings, logger);

            // Setup cancellation token for graceful shutdown
            using var cancellationTokenSource = new CancellationTokenSource();
            
            // Handle Ctrl+C gracefully
            Console.CancelKeyPress += (sender, e) =>
            {
                logger.Information("Shutdown signal received, stopping server...");
                e.Cancel = true; // Prevent immediate termination
                cancellationTokenSource.Cancel();
            };

            // Create and start the server
            server = new Server(proxyConfig, logger, resolver);
            
            logger.Information("Starting SOCKS5 proxy server on {Address}:{Port}", 
                proxyConfig.ListenIPAddress, proxyConfig.ListenPort);

            await server.StartAsync(cancellationTokenSource.Token).ConfigureAwait(false);
            
            logger.Information("SOCKS5 proxy server stopped gracefully");
            return 0;
        }
        catch (OperationCanceledException)
        {
            logger?.Information("Server operation was cancelled");
            return 0;
        }
        catch (Exception ex)
        {
            logger?.Error(ex, "Fatal error occurred");
            Console.Error.WriteLine($"Fatal error: {ex.Message}");
            return 1;
        }
        finally
        {
            try
            {
                server?.Dispose();
            }
            catch (Exception ex)
            {
                logger?.Error(ex, "Error disposing server");
            }

            // Ensure all logs are flushed
            Log.CloseAndFlush();
        }
    }

    /// <summary>
    /// Builds the configuration from appsettings.json, proxy.json, and command line arguments.
    /// </summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>The built configuration.</returns>
    private static IConfiguration BuildConfiguration(string[] args)
    {
        var builder = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);

        // Check for custom proxy configuration file path from command line
        string proxyConfigPath = "proxy.json";
        
        if (args.Length >= 2 && args[0].Equals("--config", StringComparison.OrdinalIgnoreCase))
        {
            proxyConfigPath = args[1];
        }

        // Check if proxy configuration file exists and provide friendly error message
        var fullProxyConfigPath = Path.IsPathRooted(proxyConfigPath) 
            ? proxyConfigPath 
            : Path.Combine(Directory.GetCurrentDirectory(), proxyConfigPath);
            
        if (!File.Exists(fullProxyConfigPath))
        {
            throw new FileNotFoundException(
                $"Proxy configuration file not found: '{fullProxyConfigPath}'. " +
                $"Please create the configuration file or specify a valid path using --config <path>.",
                fullProxyConfigPath);
        }

        // Add proxy configuration file
        builder.AddJsonFile(proxyConfigPath, optional: false, reloadOnChange: false);

        // Add command line arguments
        builder.AddCommandLine(args);

        return builder.Build();
    }

    /// <summary>
    /// Configures Serilog logging based on the configuration.
    /// </summary>
    /// <param name="configuration">The configuration.</param>
    /// <returns>The configured logger.</returns>
    private static ILogger ConfigureLogging(IConfiguration configuration)
    {
        var loggerConfiguration = new LoggerConfiguration()
            .ReadFrom.Configuration(configuration);

        Log.Logger = loggerConfiguration.CreateLogger();
        return Log.Logger;
    }

    /// <summary>
    /// Loads and validates the proxy configuration.
    /// </summary>
    /// <param name="configuration">The configuration.</param>
    /// <param name="logger">The logger instance.</param>
    /// <returns>The proxy configuration or null if invalid.</returns>
    private static ProxyConfiguration? LoadProxyConfiguration(IConfiguration configuration, ILogger logger)
    {
        try
        {
            var proxyConfig = new ProxyConfiguration();
            configuration.Bind(proxyConfig);

            // Validate configuration
            if (!proxyConfig.IsValid(out string errorMessage))
            {
                logger.Error("Invalid proxy configuration: {ErrorMessage}", errorMessage);
                Console.Error.WriteLine($"Configuration error: {errorMessage}");
                return null;
            }

            logger.Information("Proxy configuration loaded successfully");
            logger.Debug("Listen Address: {Address}, Listen Port: {Port}", 
                proxyConfig.ListenIPAddress, proxyConfig.ListenPort);

            return proxyConfig;
        }
        catch (Exception ex)
        {
            logger.Error(ex, "Error loading proxy configuration");
            Console.Error.WriteLine($"Configuration error: {ex.Message}");
            return null;
        }
    }
}
