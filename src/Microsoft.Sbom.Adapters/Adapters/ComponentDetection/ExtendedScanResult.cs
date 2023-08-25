using System.Collections.Generic;
using Microsoft.ComponentDetection.Contracts.BcdeModels;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Microsoft.Sbom.Adapters.ComponentDetection;

[JsonObject(MemberSerialization.OptOut, NamingStrategyType = typeof(CamelCaseNamingStrategy))]
public class ExtendedScanResult : ScanResult
{
    new public IEnumerable<ExtendedScannedComponent> ComponentsFound { get; set; }
}