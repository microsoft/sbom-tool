namespace Microsoft.Sbom.Entities;

public record FileElement(string? Path, IList<FileHash>? Hashes);
