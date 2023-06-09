using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Sbom.Config;
using Microsoft.Sbom.Enums;
using Microsoft.Sbom.Interfaces;
using Microsoft.Sbom.Utils;
using System.Threading.Tasks.Dataflow;
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

    public async IAsyncEnumerable<object> Get()
    {
        var files = Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories);

        var transformBlock =
            new TransformBlock<string, Spdx3_0.Software.File>(CreateSpdxFile, new ExecutionDataflowBlockOptions { MaxDegreeOfParallelism = Environment.ProcessorCount});

        foreach (var file in files)
        {
            await transformBlock.SendAsync(file);
        }

        transformBlock.Complete();

        // Read from the TransformBlock and yield return the results
        while (await transformBlock.OutputAvailableAsync())
        {
            while (transformBlock.TryReceive(out var spdxFile))
            {
                yield return spdxFile;
            }
        }

        // wait for all processing to finish
        await transformBlock.Completion;
    }

    private async Task<Spdx3_0.Software.File> CreateSpdxFile(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, useAsync: true);

        // Compute hash
        var integrityMethods = await integrityProvider(fs, logger);

        return new Spdx3_0.Software.File(GetSpdxFileName(filePath))
        {
            verifiedUsing = integrityMethods,
            spdxId = new Uri("https://hello"),
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
