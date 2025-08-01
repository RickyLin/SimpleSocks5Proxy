namespace Socks5Proxy;

/// <summary>
/// Constants and enums for SOCKS5 protocol values.
/// </summary>
public static class Socks5Protocol
{
    /// <summary>
    /// SOCKS version 5
    /// </summary>
    public const byte Version = 0x05;

    /// <summary>
    /// SOCKS5 authentication methods
    /// </summary>
    public static class AuthMethod
    {
        /// <summary>
        /// No authentication required
        /// </summary>
        public const byte NoAuth = 0x00;

        /// <summary>
        /// GSSAPI authentication
        /// </summary>
        public const byte GSSAPI = 0x01;

        /// <summary>
        /// Username/password authentication
        /// </summary>
        public const byte UsernamePassword = 0x02;

        /// <summary>
        /// No acceptable methods
        /// </summary>
        public const byte NoAcceptableMethods = 0xFF;
    }

    /// <summary>
    /// SOCKS5 commands
    /// </summary>
    public static class Command
    {
        /// <summary>
        /// CONNECT command - establish a TCP connection
        /// </summary>
        public const byte Connect = 0x01;

        /// <summary>
        /// BIND command - bind to a port for incoming connections
        /// </summary>
        public const byte Bind = 0x02;

        /// <summary>
        /// UDP ASSOCIATE command - establish UDP relay
        /// </summary>
        public const byte UdpAssociate = 0x03;
    }

    /// <summary>
    /// SOCKS5 address types
    /// </summary>
    public static class AddressType
    {
        /// <summary>
        /// IPv4 address
        /// </summary>
        public const byte IPv4 = 0x01;

        /// <summary>
        /// Domain name
        /// </summary>
        public const byte DomainName = 0x03;

        /// <summary>
        /// IPv6 address
        /// </summary>
        public const byte IPv6 = 0x04;
    }

    /// <summary>
    /// SOCKS5 reply codes
    /// </summary>
    public static class ReplyCode
    {
        /// <summary>
        /// Succeeded
        /// </summary>
        public const byte Succeeded = 0x00;

        /// <summary>
        /// General SOCKS server failure
        /// </summary>
        public const byte GeneralFailure = 0x01;

        /// <summary>
        /// Connection not allowed by ruleset
        /// </summary>
        public const byte ConnectionNotAllowed = 0x02;

        /// <summary>
        /// Network unreachable
        /// </summary>
        public const byte NetworkUnreachable = 0x03;

        /// <summary>
        /// Host unreachable
        /// </summary>
        public const byte HostUnreachable = 0x04;

        /// <summary>
        /// Connection refused
        /// </summary>
        public const byte ConnectionRefused = 0x05;

        /// <summary>
        /// TTL expired
        /// </summary>
        public const byte TtlExpired = 0x06;

        /// <summary>
        /// Command not supported
        /// </summary>
        public const byte CommandNotSupported = 0x07;

        /// <summary>
        /// Address type not supported
        /// </summary>
        public const byte AddressTypeNotSupported = 0x08;
    }

    /// <summary>
    /// Reserved byte value
    /// </summary>
    public const byte Reserved = 0x00;
}
