﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace Microsoft.SPDX22SBOMParser.Entities.Enums
{
    /// <summary>
    /// Type of the external reference. These are definined in an appendix in the SPDX specification.
    /// https://spdx.github.io/spdx-spec/appendix-VI-external-repository-identifiers/.
    /// </summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    [SuppressMessage("StyleCop.CSharp.NamingRules", "SA1300:Element should begin with upper-case letter",
        Justification = "These are enum types that are case sensitive and defined by external code.")]
    public enum ExternalRepositoryType
    {
        #region Security
        Cpe22,
        Cpe23,

        #endregion

        #region Persistent-Id
        
        Swh,

        #endregion

        #region Package-Manager

        Maven_central,
        Npm,
        Nuget,
        Bower,
        Purl,

        #endregion

        #region Other

        Idstring

        #endregion
    }
}
