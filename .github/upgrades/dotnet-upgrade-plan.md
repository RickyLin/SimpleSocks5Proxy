# .NET 10 Upgrade Plan

## Execution Steps

Execute steps below sequentially one by one in the order they are listed.

1. Validate that a .NET 10 SDK required for this upgrade is installed on the machine and if not, help to get it installed.
2. Ensure that the SDK version specified in global.json files is compatible with the .NET 10 upgrade.
3. Upgrade Socks5Proxy/Socks5Proxy.csproj
4. Run unit tests to validate upgrade in the projects listed below:

## Settings

### Excluded projects

No projects are excluded.

### Aggregate NuGet packages modifications across all projects

NuGet packages used across all selected projects or their dependencies that need version update in projects that reference them.

| Package Name                                     | Current Version | New Version | Description                           |
|:------------------------------------------------|:---------------:|:-----------:|:--------------------------------------|
| Microsoft.Extensions.Configuration.Binder       |     9.0.7       |   10.0.0    | Recommended for .NET 10               |
| Microsoft.Extensions.Configuration.CommandLine |     9.0.7       |   10.0.0    | Recommended for .NET 10               |
| Microsoft.Extensions.Configuration.Json        |     9.0.7       |   10.0.0    | Recommended for .NET 10               |

### Project upgrade details

#### Socks5Proxy/Socks5Proxy.csproj modifications

Project properties changes:
  - Target framework should be changed from `net9.0` to `net10.0`

NuGet packages changes:
  - Microsoft.Extensions.Configuration.Binder should be updated from `9.0.7` to `10.0.0` (*recommended for .NET 10*)
  - Microsoft.Extensions.Configuration.CommandLine should be updated from `9.0.7` to `10.0.0` (*recommended for .NET 10*)
  - Microsoft.Extensions.Configuration.Json should be updated from `9.0.7` to `10.0.0` (*recommended for .NET 10*)