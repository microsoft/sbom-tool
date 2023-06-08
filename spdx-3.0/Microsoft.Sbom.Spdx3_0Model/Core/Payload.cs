namespace Microsoft.Sbom.Spdx3_0.Core;

public abstract record Payload(CreationInfo? creationInfo, List<NamespaceMap>? namespaces, ExternalMap? imports);
