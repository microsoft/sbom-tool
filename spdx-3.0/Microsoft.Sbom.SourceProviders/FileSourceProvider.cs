using System.IO.Enumeration;
using Microsoft.Sbom.Enums;
using Microsoft.Sbom.Interfaces;

namespace Microsoft.Sbom;

public class FileSourceProvider : ISourceProvider<Spdx3_0.Software.File>
{
    private readonly string directory;

    public FileSourceProvider(string? directory)
    {
        this.directory = string.IsNullOrEmpty(directory) ? Directory.GetCurrentDirectory() : directory;
    }

    public SourceType SourceType => SourceType.Files;

    public async IAsyncEnumerable<Spdx3_0.Software.File> Get()
    {
        var enumeration = await Task.Run(() => 
            new FileSystemEnumerable<Spdx3_0.Software.File>(
               directory: this.directory,
               transform: TransformToFileElement,
               options: new EnumerationOptions()
               {
                   RecurseSubdirectories = true
               }));

        foreach (var element in enumeration) 
        { 
            yield return element; 
        }
    }

    private Spdx3_0.Software.File TransformToFileElement(ref FileSystemEntry entry)
    {
        throw new NotImplementedException();
    }
}
