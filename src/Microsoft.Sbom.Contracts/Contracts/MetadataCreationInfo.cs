using System;
using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts;
public class MetadataCreationInfo
{
    public DateTime Created { get; set; }

    public IEnumerable<string> Creators { get; set; }
}
