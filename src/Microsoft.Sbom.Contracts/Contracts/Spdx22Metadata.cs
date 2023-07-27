using System;
using System.Collections.Generic;

namespace Microsoft.Sbom.Contracts;
public class Spdx22Metadata
{
    public string SpdxVersion { get; set; }

    public string DataLicense { get; set; }

    public string Name { get; set; }

    public Uri DocumentNamespace { get; set; }

    public MetadataCreationInfo CreationInfo { get; set; }

    public IEnumerable<string> DocumentDescribes { get; set; }
    
    public string SpdxId { get; set; }
}
