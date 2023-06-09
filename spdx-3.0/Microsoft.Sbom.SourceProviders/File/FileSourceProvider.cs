using System.IO.Enumeration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Sbom.Config;
using Microsoft.Sbom.Enums;
using Microsoft.Sbom.Interfaces;
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
        var enumeration = await Task.Run(() =>
            new FileSystemEnumerable<Spdx3_0.Software.File>(
               directory: this.directory,
               transform: TransformToFileElement,
               options: new EnumerationOptions()
               {
                   RecurseSubdirectories = true
               })
            {
                // The following predicate will be used to filter the file entries
                ShouldIncludePredicate = (ref FileSystemEntry entry) => !entry.IsDirectory
            });

        foreach (var element in enumeration)
        {
            yield return element;
        }
    }

    private Spdx3_0.Software.File TransformToFileElement(ref FileSystemEntry entry)
    {
        return new Spdx3_0.Software.File(GetSpdxFileName(entry))
        {
            additionalPurpose = Spdx3_0.Software.Enums.SoftwarePurpose.File,
            verifiedUsing = integrityProvider(ref entry, logger),
        };
    }

    private string? GetSpdxFileName(FileSystemEntry entry)
    {
        Uri fileUri = new (entry.ToFullPath());
        Uri parentUri = new (this.directory + Path.DirectorySeparatorChar);

        string relativePath = Uri.UnescapeDataString(
            parentUri.MakeRelativeUri(fileUri).ToString());
        return $"./{relativePath}";
    }
}
