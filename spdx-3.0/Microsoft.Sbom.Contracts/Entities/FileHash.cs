namespace Microsoft.Sbom.Entities;

// Algorithm should be one of these strings: https://github.com/spdx/spdx-3-model/blob/930dfaacf3ab4ec7108283f412ef3f4c6cad98d0/model/Core/Vocabularies/HashAlgorithm.md
// TODO: Enforce this behaviour
public record FileHash(string Algorithm, string Value);
