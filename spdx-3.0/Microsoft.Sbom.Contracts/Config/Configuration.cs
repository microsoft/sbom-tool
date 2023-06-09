using Microsoft.Extensions.Logging;

namespace Microsoft.Sbom.Config;
public class Configuration
{
    public ILogger? Logger { get; init; }

    public string? BasePath { get; init; }

    public string? ComponentPath { get; init; }

    public string? OutputFilePath { get; init; }

    public Providers? Providers { get; init; }
}