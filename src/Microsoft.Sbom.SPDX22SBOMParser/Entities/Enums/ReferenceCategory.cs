using System.Text.Json.Serialization;

namespace Microsoft.SPDX22SBOMParser.Entities.Enums
{
    /// <summary>
    /// Defines a Category for an external package reference.
    /// </summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum ReferenceCategory
    {
        OTHER,
        SECURITY,
        PACKAGE_MANAGER,
        PERSISTENT_ID
    }
}
