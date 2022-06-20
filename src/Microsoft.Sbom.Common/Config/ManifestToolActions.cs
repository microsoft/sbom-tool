using System;

namespace Microsoft.Sbom.Common.Config
{
    [Flags]
    public enum ManifestToolActions
    {
        None = 0,
        Validate = 1,
        Generate = 2,

        All = Validate | Generate
    }
}
