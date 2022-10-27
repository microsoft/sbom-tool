using System;

namespace Microsoft.Sbom.Entities
{
    [Flags]
    public enum FileLocation
    {
        None,
        OnDisk,
        InSbomFile,
        All = OnDisk | InSbomFile,
    }
}
