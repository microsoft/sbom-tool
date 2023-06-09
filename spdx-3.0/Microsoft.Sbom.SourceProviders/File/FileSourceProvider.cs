using System.IO.Enumeration;
using System.Security.Cryptography;
using System.Threading.Tasks.Dataflow;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Sbom.Config;
using Microsoft.Sbom.Enums;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.Spdx3_0.Core;
using Microsoft.Sbom.Spdx3_0.Software;
using Microsoft.Sbom.Utils;
using static Microsoft.Sbom.Delegates.FileDelegates;

namespace Microsoft.Sbom.File;

public class FileSourceProvider : ISourceProvider
{
    private readonly string directory;
    private readonly IntegrityProvider integrityProvider;
    private readonly ILogger logger;

    public FileSourceProvider(Configuration? configuration)
    {
        this.logger = configuration?.Logger ?? NullLogger.Instance;
        this.directory = configuration?.BasePath ?? Directory.GetCurrentDirectory();
        this.integrityProvider = configuration?.Providers?.IntegrityProvider ?? FileIntegrityProvider.Sha256IntegrityProvider;
    }

    public SourceType SourceType => SourceType.Files;

    public async IAsyncEnumerable<SoftwareArtifact> Get()
    {
        var files = Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories);

        var transformBlock =
            new TransformBlock<string, Spdx3_0.Software.File>(CreateSpdxFile, new ExecutionDataflowBlockOptions { MaxDegreeOfParallelism = Environment.ProcessorCount });

        foreach (var file in files)
        {
            await transformBlock.SendAsync(file);
        }

        transformBlock.Complete();

        // Read from the TransformBlock and yield return the results
        while (await transformBlock.OutputAvailableAsync())
        {
            while (transformBlock.TryReceive(out var fileWithHash))
            {
                yield return fileWithHash;
            }
        }

        // wait for all processing to finish
        await transformBlock.Completion;
    }

    private async Task<Spdx3_0.Software.File> CreateSpdxFile(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, useAsync: true);
        using var sha256 = SHA256.Create();

        // Compute hash
        var hash = await Task.Run(() => sha256.ComputeHash(fs));

        return new Spdx3_0.Software.File(GetSpdxFileName(filePath))
        {
            verifiedUsing = new List<IntegrityMethod>()
            {
                new Hash(Spdx3_0.Core.Enums.HashAlgorithm.Sha256, BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant()),
            }
        };
    }

    private string? GetSpdxFileName(string filePath)
    {
        Uri fileUri = new (filePath);
        Uri parentUri = new (this.directory + Path.DirectorySeparatorChar);

        string relativePath = Uri.UnescapeDataString(
            parentUri.MakeRelativeUri(fileUri).ToString());
        return $"./{relativePath}";
    }
}
