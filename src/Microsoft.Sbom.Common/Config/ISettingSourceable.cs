// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common.Config
{
    /// <summary>
    /// Adds a setting source property to an object that defines where that setting came from.
    /// </summary>
    public interface ISettingSourceable
    {
        /// <summary>
        /// Gets or sets the <see cref="SettingSource">source</see> where this setting came from.
        /// </summary>
        SettingSource Source { get; set; }
    }
}
