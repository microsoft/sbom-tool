// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Executors;

public interface ISbomReferenceFactory
{
    public ISbomReferenceDescriber GetSbomReferenceDescriber(string sbomFilePath);
}
