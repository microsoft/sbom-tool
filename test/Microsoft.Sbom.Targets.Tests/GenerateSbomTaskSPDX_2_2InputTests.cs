// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets.Tests;

using Microsoft.VisualStudio.TestTools.UnitTesting;

/// <summary>
/// Class to test the generation of SBOM using SPDX 2.2 specification.
/// </summary>
[TestClass]
public class GenerateSbomTaskSPDX_2_2InputTests : AbstractGenerateSbomTaskInputTests
{
    internal override string SbomSpecification => "SPDX:2.2";

    [ClassInitialize]
    public static void Setup(TestContext testContext) => ClassSetup(nameof(GenerateSbomTaskSPDX_2_2InputTests));

    [ClassCleanup(ClassCleanupBehavior.EndOfClass)]
    public static void TearDown() => ClassTearDown();
}
