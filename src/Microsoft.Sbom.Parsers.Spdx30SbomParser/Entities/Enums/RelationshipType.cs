// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json.Serialization;

namespace Microsoft.Sbom.Parsers.Spdx30SbomParser.Entities.Enums;

/// <summary>
/// Defines the type of <see cref="Relationship"/> between the source and the target element.
/// Full definition here: https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Vocabularies/RelationshipType/
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum RelationshipType
{
    /// <summary>
    /// The from Vulnerability affects each to Element.
    /// </summary>
    AFFECTS,

    /// <summary>
    /// The from Element is amended by each to Element.
    /// </summary>
    AMENDED_BY,

    /// <summary>
    /// The from Element is an ancestor of each to Element.
    /// </summary>
    ANCESTOR_OF,

    /// <summary>
    /// The from Element is available from the additional supplier described by each to Element.
    /// </summary>
    AVAILABLE_FROM,

    /// <summary>
    /// The from Element is a configuration applied to each to Element, during a LifecycleScopeType period.
    /// </summary>
    CONFIGURES,

    /// <summary>
    /// The from Element contains each to Element.
    /// </summary>
    CONTAINS,

    /// <summary>
    /// The from Vulnerability is coordinatedBy the to Agent(s) (vendor, researcher, or consumer agent).
    /// </summary>
    COORDINATED_BY,

    /// <summary>
    /// The from Element has been copied to each to Element.
    /// </summary>
    COPIED_TO,

    /// <summary>
    /// The from Agent is delegating an action to the Agent of the to Relationship (which must be of type invokedBy),
    /// during a LifecycleScopeType (e.g. the to invokedBy Relationship is being done on behalf of from).
    /// </summary>
    DELEGATED_TO,

    /// <summary>
    /// The from Element depends on each to Element, during a LifecycleScopeType period.
    /// </summary>
    DEPENDS_ON,

    /// <summary>
    /// The from Element is a descendant of each to Element.
    /// </summary>
    DESCENDANT_OF,

    /// <summary>
    /// The from Element describes each to Element. To denote the root(s) of a tree of elements in a collection, the rootElement property should be used.
    /// </summary>
    DESCRIBES,

    /// <summary>
    /// The from Vulnerability has no impact on each to Element. The use of the doesNotAffect is constrained to VexNotAffectedVulnAssessmentRelationship classed relationships.
    /// </summary>
    DOES_NOT_AFFECT,

    /// <summary>
    /// The from archive expands out as an artifact described by each to Element.
    /// </summary>
    EXPANDS_TO,

    /// <summary>
    /// The from Vulnerability has had an exploit created against it by each to Agent.
    /// </summary>
    EXPLOIT_CREATED_BY,

    /// <summary>
    /// Designates a from Vulnerability has been fixed by the to Agent(s).
    /// </summary>
    FIXED_BY,

    /// <summary>
    /// A from Vulnerability has been fixed in each to Element. The use of the fixedIn type is constrained to VexFixedVulnAssessmentRelationship classed relationships.
    /// </summary>
    FIXED_IN,

    /// <summary>
    /// Designates a from Vulnerability was originally discovered by the to Agent(s).
    /// </summary>
    FOUND_BY,

    /// <summary>
    /// The from Element generates each to Element.
    /// </summary>
    GENERATES,

    /// <summary>
    /// Every to Element is a file added to the from Element (from hasAddedFile to).
    /// </summary>
    HAS_ADDED_FILE,

    /// <summary>
    /// Relates a from Vulnerability and each to Element with a security assessment. To be used with VulnAssessmentRelationship types.
    /// </summary>
    HAS_ASSESSMENT_FOR,

    /// <summary>
    /// Used to associate a from Artifact with each to Vulnerability.
    /// </summary>
    HAS_ASSOCIATED_VULNERABILITY,

    /// <summary>
    /// The from SoftwareArtifact is concluded by the SPDX data creator to be governed by each to license.
    /// </summary>
    HAS_CONCLUDED_LICENSE,

    /// <summary>
    /// The from Element treats each to Element as a data file.
    /// A data file is an artifact that stores data required or optional for the from Element's functionality.
    /// A data file can be a database file, an index file, a log file, an AI model file, a calibration data file, a temporary file, a backup file, and more.
    /// For AI training dataset, test dataset, test artifact, configuration data, build input data, and build output data,
    /// please consider using the more specific relationship types: trainedOn, testedOn, hasTest, configures, hasInput, and hasOutput, respectively.
    /// This relationship does not imply dependency.
    /// </summary>
    HAS_DATA_FILE,

    /// <summary>
    /// The from SoftwareArtifact was discovered to actually contain each to license, for example as detected by use of automated tooling.
    /// </summary>
    HAS_DECLARED_LICENSE,

    /// <summary>
    /// Every to Element is a file deleted from the from Element (from hasDeletedFile to).
    /// </summary>
    HAS_DELETED_FILE,

    /// <summary>
    /// The from Element has manifest files that contain dependency information in each to Element.
    /// </summary>
    HAS_DEPENDENCY_MANIFEST,

    /// <summary>
    /// The from Element is distributed as an artifact in each to Element (e.g. an RPM or archive file).
    /// </summary>
    HAS_DISTRIBUTION_ARTIFACT,

    /// <summary>
    /// The from Element is documented by each to Element.
    /// </summary>
    HAS_DOCUMENTATION,

    /// <summary>
    /// The from Element dynamically links in each to Element, during a LifecycleScopeType period.
    /// </summary>
    HAS_DYNAMIC_LINK,

    /// <summary>
    /// Every to Element is considered as evidence for the from Element (from hasEvidence to).
    /// </summary>
    HAS_EVIDENCE,

    /// <summary>
    /// Every to Element is an example for the from Element (from hasExample to).
    /// </summary>
    HAS_EXAMPLE,

    /// <summary>
    /// The from Build was run on the to Element during a LifecycleScopeType period (e.g. the host that the build runs on).
    /// </summary>
    HAS_HOST,

    /// <summary>
    /// The from Build has each to Element as an input, during a LifecycleScopeType period.
    /// </summary>
    HAS_INPUT,

    /// <summary>
    /// Every to Element is metadata about the from Element (from hasMetadata to).
    /// </summary>
    HAS_METADATA,

    /// <summary>
    /// Every to Element is an optional component of the from Element (from hasOptionalComponent to).
    /// </summary>
    HAS_OPTIONAL_COMPONENT,

    /// <summary>
    /// The from Element optionally depends on each to Element, during a LifecycleScopeType period.
    /// </summary>
    HAS_OPTIONAL_DEPENDENCY,

    /// <summary>
    /// The from Build element generates each to Element as an output, during a LifecycleScopeType period.
    /// </summary>
    HAS_OUTPUT,

    /// <summary>
    /// The from Element has a prerequisite on each to Element, during a LifecycleScopeType period.
    /// </summary>
    HAS_PREREQUISITE,

    /// <summary>
    /// The from Element has a dependency on each to Element, dependency is not in the distributed artifact, but assumed to be provided, during a LifecycleScopeType period.
    /// </summary>
    HAS_PROVIDED_DEPENDENCY,

    /// <summary>
    /// The from Element has a requirement on each to Element, during a LifecycleScopeType period.
    /// </summary>
    HAS_REQUIREMENT,

    /// <summary>
    /// Every to Element is a specification for the from Element (from hasSpecification to), during a LifecycleScopeType period.
    /// </summary>
    HAS_SPECIFICATION,

    /// <summary>
    /// The from Element statically links in each to Element, during a LifecycleScopeType period.
    /// </summary>
    HAS_STATIC_LINK,

    /// <summary>
    /// Every to Element is a test artifact for the from Element (from hasTest to), during a LifecycleScopeType period.
    /// </summary>
    HAS_TEST,

    /// <summary>
    /// Every to Element is a test case for the from Element (from hasTestCase to).
    /// </summary>
    HAS_TEST_CASE,

    /// <summary>
    /// Every to Element is a variant the from Element (from hasVariant to).
    /// </summary>
    HAS_VARIANT,

    /// <summary>
    /// The from Element was invoked by the to Agent, during a LifecycleScopeType period (for example, a Build element that describes a build step).
    /// </summary>
    INVOKED_BY,

    /// <summary>
    /// The from Element is modified by each to Element.
    /// </summary>
    MODIFIED_BY,

    /// <summary>
    /// Every to Element is related to the from Element where the relationship type is not described by any of the SPDX relationship types (this relationship is directionless).
    /// </summary>
    OTHER,

    /// <summary>
    /// Every to Element is a packaged instance of the from Element (from packagedBy to).
    /// </summary>
    PACKAGED_BY,

    /// <summary>
    /// Every to Element is a patch for the from Element (from patchedBy to).
    /// </summary>
    PATCHED_BY,

    /// <summary>
    /// Designates a from Vulnerability was made available for public use or reference by each to Agent.
    /// </summary>
    PUBLISHED_BY,

    /// <summary>
    /// Designates a from Vulnerability was first reported to a project, vendor, or tracking database for formal identification by each to Agent.
    /// </summary>
    REPORTED_BY,

    /// <summary>
    /// Designates a from Vulnerability's details were tracked, aggregated, and/or enriched to improve context (i.e. NVD) by each to Agent.
    /// </summary>
    REPUBLISHED_BY,

    /// <summary>
    /// The from SpdxDocument can be found in a serialized form in each to Artifact.
    /// </summary>
    SERIALIZED_IN_ARTIFACT,

    /// <summary>
    /// The from Element has been tested on the to Element(s).
    /// </summary>
    TESTED_ON,

    /// <summary>
    /// The from Element has been trained on the to Element(s).
    /// </summary>
    TRAINED_ON,

    /// <summary>
    /// The from Vulnerability impact is being investigated for each to Element.
    /// The use of the underInvestigationFor type is constrained to VexUnderInvestigationVulnAssessmentRelationship classed relationships.
    /// </summary>
    UNDER_INVESTIGATION_FOR,

    /// <summary>
    /// The from Element uses each to Element as a tool, during a LifecycleScopeType period.
    /// </summary>
    USES_TOOL
}
