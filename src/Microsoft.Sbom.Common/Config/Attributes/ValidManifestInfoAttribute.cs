// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Sbom.Common.Config.Attributes;

/// <summary>
/// Validate if the property value is a valid ManifestInfo.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Assembly, Inherited = false, AllowMultiple = false)]
public sealed class ValidManifestInfoAttribute : Attribute;
