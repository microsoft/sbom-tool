using Microsoft.Sbom.Spdx3_0.Software;

namespace Microsoft.Sbom.Entities;
public class PackageEntity : Entity
{
    public Package SpdxPackage { get; set; }
}
