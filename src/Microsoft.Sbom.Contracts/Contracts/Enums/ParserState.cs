// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Contracts.Enums;

/// <summary>
/// Defines the current state of the SBOM parser. 
/// </summary>
public enum ParserState
{
    /// <summary>
    /// No state, or parsing has not yet begun
    /// </summary>
    NONE,

    /// <summary>
    /// The parser is currently returning file objects.
    /// </summary>
    FILES,

    /// <summary>
    /// The parser is currently returning packages objects.
    /// </summary>
    PACKAGES,

    /// <summary>
    /// The parser is currently returning relationship objects.
    /// </summary>
    RELATIONSHIPS,

    /// <summary>
    /// The parser is currently returning SBOM reference objects.
    /// </summary>
    REFERENCES,

    /// <summary>
    /// The parser is currently returning the SBOM metadata object.
    /// </summary>
    METADATA,

    /// <summary>
    /// The parser is in a state where its returned a property that needs to be skipped.
    /// This parser will never be in this state externally, internally we will try to move 
    /// to the next available state when we reach this state.
    /// </summary>
    INTERNAL_SKIP,

    /// <summary>
    /// The parser is in a state where its processing a metadata property. In this state
    /// the metadata object is not yet complete. This parser will never be in this state externally.
    /// </summary>
    INTERNAL_METADATA,

    /// <summary>
    /// The parser has completed parsing the SBOM.
    /// </summary>
    FINISHED
}
