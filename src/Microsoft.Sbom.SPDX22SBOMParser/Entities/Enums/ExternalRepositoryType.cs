using System.Text.Json.Serialization;

namespace Microsoft.SPDX22SBOMParser.Entities.Enums
{

#pragma warning disable SA1629 // Documentation text should end with a period
    /// <summary>
    /// Type of the external reference. These are definined in an appendix in the SPDX specification.
    /// https://spdx.github.io/spdx-spec/appendix-VI-external-repository-identifiers/
    /// </summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
#pragma warning restore SA1629 // Documentation text should end with a period
    public enum ExternalRepositoryType
    {
        #region Security
        Cpe22,
        Cpe23,

        #endregion

        #region Persistent-Id
        
        swh,

        #endregion

        #region Package-Manager

        maven_central,
        npm,
        nuget,
        bower,
        purl,

        #endregion

        #region Other

        idstring

        #endregion
    }
}
