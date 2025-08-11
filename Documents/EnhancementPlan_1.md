# Enhancement Plan 1 — Friendly names for IPs in log output (Refined Requirements)

Date: 2025-08-08

## Summary

Add an optional “address book” that maps literal IPs to human‑friendly names for log output only. When enabled, logs will display FriendlyName alongside the original IP/endpoint so operators can quickly identify devices without sacrificing diagnostics. No network/protocol behavior changes.

## Goals

- Provide friendlier log output by mapping literal IPs (IPv4/IPv6) to names from configuration.
- Keep the raw IP/endpoint visible for troubleshooting.
- Zero impact to proxy functionality, performance, and protocol semantics.
- Backward compatible: unchanged logs when no mappings configured.

## Non-goals

- No reverse DNS, WHOIS, or automatic discovery.
- No CIDR/range/hostname mappings (single IP literal only).
- No runtime mutation of mappings; config is static at startup.
- No UI or persistence beyond the existing JSON config files.

## Definitions

- IP literal: A string accepted by System.Net.IPAddress.TryParse (v4 or v6).
- Endpoint: IP + port (e.g., 192.168.1.10:443). Mapping matches only by IP.
- FriendlyName: A short human label (e.g., “Laptop-Mark”).

## User stories

- As an operator, I want to see device names in logs so I can identify clients quickly.
- As a developer, I want the raw endpoint preserved so I can debug issues precisely.
- As an SRE, I want the feature to be safe-by-default and not degrade performance.

## Functional requirements

1) Configuration
	 - Add `IPAddressMappings` to `proxy.json`.
	 - Each item: `{ "IPAddress": string, "FriendlyName": string }`.
	 - Optional section. Missing/empty ⇒ feature disabled.

2) Logging behavior
	 - When logging an IP or endpoint that matches a configured mapping, append a friendly suffix in parentheses:
		 - Endpoint: `IP:Port (FriendlyName)`
		 - Bare IP: `IP (FriendlyName)`
	 - When no mapping exists, render the original value unchanged.
	 - Do not alter message templates’ property names; the friendly text is appended as a separate parameter/suffix in logs.

3) Scope of application
	 - Apply to logs that include client or destination IPs/endpoints in:
		 - `Server` (listener start/stop, client accepted, errors)
		 - `ConnectionHandler` (handshake, CONNECT, UDP ASSOCIATE, forwarding start/stop)
		 - `UdpRelay` (relay start/stop, packet forward summaries)

4) Validation and startup behavior
	 - On startup, parse mappings; log a single warning for duplicates where the last one wins.
	 - Invalid `IPAddress` strings are ignored with a warning listing the offending entries.
	 - Mapping is case-insensitive for the FriendlyName but IP matching is performed on the normalized `IPAddress.ToString()`.

5) Failure modes
	 - If the mapping feature initialization fails, continue without mappings and log a warning. Do not prevent the proxy from starting.

## Configuration schema

Example `proxy.json`:

```
{
	"ListenIPAddress": "0.0.0.0",
	"ListenPort": 1080,
	"IPAddressMappings": [
		{ "IPAddress": "192.168.1.10", "FriendlyName": "Laptop" },
		{ "IPAddress": "10.0.0.5", "FriendlyName": "NAS" },
		{ "IPAddress": "::1", "FriendlyName": "Localhost (IPv6)" }
	]
}
```

Validation rules:
- `IPAddress` must parse via `IPAddress.TryParse`.
- Duplicate IP literals allowed; last entry wins with a warning summarizing duplicates.
- `FriendlyName` must be 1–64 visible characters; trim whitespace; log warning and skip if empty.

## Logging format details

- Preferred rendering for endpoints: `{IP}:{Port} (FriendlyName)`.
- Preferred rendering for IP-only: `{IP} (FriendlyName)`.
- For domain destinations (e.g., CONNECT to a hostname), do not attempt mapping; keep domain unchanged.
- If an endpoint is unknown/null, preserve existing behavior (e.g., “Unknown”).

Before/After examples:
- Before: `New client connection from 192.168.1.10:51324`
	After:  `New client connection from 192.168.1.10:51324 (Laptop)`
- Before: `Successfully connected to 93.184.216.34:443`
	After:  `Successfully connected to 93.184.216.34:443 (ExampleEdge)` (when mapped)
- Before: `Connecting to example.org:80`
	After:  unchanged (domains aren’t mapped)

## Performance and memory

- Build a dictionary keyed by normalized `IPAddress.ToString()` at startup.
- O(1) lookup per log site; avoid allocations by pre-formatting reusable helpers.
- Do not introduce blocking I/O on hot paths; strictly in-memory lookups.

## Security and privacy

- This feature only affects log formatting; no network behavior changes.
- Ensure FriendlyName is treated as untrusted input (log safely; no interpolation into SQL/files etc.).
- Preserve raw IP to avoid losing forensic value.

## Edge cases

- IPv6 zero compression: normalize via `IPAddress.ToString()` to match.
- Mixed endpoint families: mapping ignores port; `IP:Port` shows whichever port applies.
- Loopback and unspecified addresses may be mapped if configured; otherwise unchanged.
- Duplicate config entries: last one wins; list all duplicates in a single startup warning.

## Acceptance criteria

- With no `IPAddressMappings`, log output is byte-for-byte compatible with current behavior.
- With mappings configured, any logged IP/endpoint that matches renders as `{IP[:Port]} (FriendlyName)`.
- Startup logs include:
	- Count of valid mappings loaded.
	- A warning summarizing any invalid entries and duplicates.
- Errors during resolver initialization do not stop the server; a warning is emitted and logs fall back to original formatting.

## Test plan

Unit tests (minimal):
- Resolves IPv4 and IPv6 addresses to names; returns original when missing.
- Appends friendly suffixes as ` (Friendly)` after IP or endpoint when mapped.
- Handles duplicates (last wins) and logs a warning hook (can be asserted via testable logger).
- Skips invalid `IPAddress` values and empty `FriendlyName` entries.

Manual verification:
- Start with sample mappings and observe friendly formatting for:
	- Client connection source endpoint (Server/ConnectionHandler).
	- Destination endpoint logs (ConnectionHandler CONNECT).
	- UDP relay logs (UdpRelay) where endpoints are printed.
- Verify domain destinations remain unchanged.

## Implementation outline (non-prescriptive)

- Add to `ProxyConfiguration`:
	- `List<IPAddressMapping> IPAddressMappings { get; set; } = new();`
	- `record IPAddressMapping(string IPAddress, string FriendlyName);`
- Implement `FriendlyNameResolver`:
	- Constructor accepts collection of mappings, validates/normalizes, builds dictionary.
	- `string ToFriendly(IPAddress ip, string? friendlyFallback = null)`
	- `string ToFriendlyEndPoint(EndPoint ep)` → returns formatted string following the spec.
- Instantiate resolver in `Program` and pass to `Server` (and then to children) or make it a small injectable service/static helper.
- Replace string formatting at log callsites to route endpoints through the resolver.

## Rollout and migration

- Default behavior unchanged. No migration required.
- Add a short section to README showing the optional `IPAddressMappings` snippet and before/after examples.

## Work items

1. Configuration model update (ProxyConfiguration + DTO) and validation.
2. Implement `FriendlyNameResolver` with tests.
3. Wire into `Program`, `Server`, `ConnectionHandler`, `UdpRelay` log sites.
4. Update `proxy.json` sample and README.
5. Manual verification checklist completion.

Effort: ~3–4 hours.

