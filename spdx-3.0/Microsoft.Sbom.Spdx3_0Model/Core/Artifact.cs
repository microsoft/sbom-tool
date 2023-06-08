using Microsoft.Sbom.Spdx3_0.Core;

namespace Microsoft.Sbom.Core;
public abstract record Artifact(Agent? originatedBy, Agent? suppliedBy, DateTime? builtTime, DateTime? releaseTime, DateTime? validUntilTime, string? standard);
