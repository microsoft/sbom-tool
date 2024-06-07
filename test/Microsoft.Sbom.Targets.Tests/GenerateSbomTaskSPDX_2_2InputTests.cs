// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets.Tests;

using Microsoft.Sbom.Api.Utils;
using Microsoft.Sbom.Contracts;
using Microsoft.VisualStudio.TestTools.UnitTesting;

/// <summary>
/// Class to test the generation of SBOM using SPDX 2.2 specification.
/// </summary>
[TestClass]
public class GenerateSbomTaskSPDX_2_2InputTests : AbstractGenerateSBomTaskInputTests
{
    internal override SbomSpecification SbomSpecification => Constants.SPDX22Specification;
}
