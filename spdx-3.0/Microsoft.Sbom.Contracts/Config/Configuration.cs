namespace Microsoft.Sbom.Config;
public class Configuration
{
    public string? Name { get; set; } 

    public Uri? Namespace { get; set; }

    public string? BasePath { get; set; }

    public string? ComponentPath { get; set; }

    public string? OutputFilePath { get; set; }

    public Providers? Providers { get; set; }
}