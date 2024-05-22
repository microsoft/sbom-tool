// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.FormatValidator;

using System;
using System.Threading.Tasks;
using Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

public interface IValidatedSBOM: IDisposable
{
    public Task<FormatValidationResults> GetValidationResults();

    public Task<FormatEnforcedSPDX2> GetRawSPDXDocument();
}
