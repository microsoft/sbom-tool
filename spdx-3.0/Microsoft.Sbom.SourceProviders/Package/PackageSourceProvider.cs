using Microsoft.ComponentDetection.Orchestrator;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Sbom.Config;
using Microsoft.Sbom.Delegates;
using Microsoft.Sbom.Enums;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.Spdx3_0.Software;
using Microsoft.Sbom.Utils;

namespace Microsoft.Sbom.Package;
public class PackageSourceProvider : ISourceProvider
{
    private readonly ILogger logger;
    private readonly string componentPath;
    private readonly FileDelegates.IntegrityProvider integrityProvider;

    public PackageSourceProvider(Configuration? configuration)
    {
        this.logger = configuration?.Logger ?? NullLogger.Instance;
        this.componentPath = configuration?.ComponentPath ?? Directory.GetCurrentDirectory();
        this.integrityProvider = configuration?.Providers?.IntegrityProvider ?? FileIntegrityProvider.Sha256IntegrityProvider;
    }

    public SourceType SourceType => SourceType.Packages;

    public async IAsyncEnumerable<object> Get()
    {
        var argsString = $"scan --SourceDirectory {this.componentPath}";
        var orchestrator = new Orchestrator();
        var result = await orchestrator.LoadAsync(argsString.Split(" "));

        if (result.ResultCode == ComponentDetection.Contracts.ProcessingResultCode.Error)
        {
            throw new Exception($"Error while scanning packages, component detector failed with error code: {result.ResultCode}");
        }

        if (result.ComponentsFound.Count() == 0)
        {
            this.logger.LogWarning("No packages found in the component path: {componentPath}", this.componentPath);
            yield break;
        }

        foreach (var component in result.ComponentsFound)
        {
            yield return PackageConverter.Convert(component);
        }
    }
}
