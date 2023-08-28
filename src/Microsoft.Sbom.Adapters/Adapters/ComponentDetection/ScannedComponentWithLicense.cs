using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Microsoft.Sbom.Adapters.ComponentDetection;
using Microsoft.Sbom.Adapters.Report;
using Microsoft.Sbom.Contracts;

public class ScannedComponentWithLicense : ScannedComponent
{
    public string? License { get; set; }

    public SbomPackage? ToSbomPackage(AdapterReport report)
    {
        return ScannedComponentExtensions.ToSbomPackage(this, report);
    }
}