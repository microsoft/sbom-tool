using Microsoft.Extensions.Logging;

namespace Microsoft.Sbom.Config;
public class Configuration
{
    public string Name { get; init; } = Constants.DefaultDocumentName;

    public Uri Namespace { get; init; } = Constants.DefaultNamespace;

    public ILogger? Logger { get; init; }

    public string? BasePath { get; init; }

    public string? ComponentPath { get; init; }

    public string? OutputFilePath { get; init; }

    public Providers? Providers { get; init; }
}