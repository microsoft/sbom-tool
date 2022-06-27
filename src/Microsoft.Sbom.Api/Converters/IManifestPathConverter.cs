// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Convertors
{
    public interface IManifestPathConverter
    {
        /// <summary>
        /// Convert a file path from a relative path to a path format 
        /// that the manifest implements.
        /// </summary>
        /// <param name="path">The relative path of the file.</param>
        /// <returns>The file path in the manifest format and boolean for if the path is outside the BuildDropPath.</returns>
        (string, bool) Convert(string path);
    }
}
