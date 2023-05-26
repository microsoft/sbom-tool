// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.IO;
using System.Linq;
using Microsoft.Sbom.Common.Config;
using Microsoft.Sbom.Common.Config.Attributes;

namespace Microsoft.Sbom.Common.Utils;

/// <summary>
/// Provides utility function to convert an IConfiguration object to use OS-specific path separators.
/// </summary>
public static class PathUtils
{
    public static void ConvertToOSSpecificPathSeparators(IConfiguration configuration)
    {
        var pathProps = configuration.GetType().GetProperties().Where(p => p.GetCustomAttributes(typeof(PathAttribute), true).Any());
        foreach (var pathProp in pathProps)
        {
            var path = pathProp.GetValue(configuration) as ConfigurationSetting<string>;
            if (path != null)
            {
                path.Value = path.Value.Replace('\\', Path.DirectorySeparatorChar);
                pathProp.SetValue(configuration, path);
            }
        }

    }
}