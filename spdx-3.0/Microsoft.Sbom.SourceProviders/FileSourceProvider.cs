using System.IO;
using System.IO.Enumeration;
using Microsoft.Sbom.Enums;
using Microsoft.Sbom.Interfaces;

namespace Microsoft.Sbom;

public class FileSourceProvider : ISourceProvider<Spdx3_0.Software.File>
{
    private readonly string directory;

    public FileSourceProvider(string? directory = null)
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
