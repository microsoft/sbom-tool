// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.FormatValidator;

using System.IO;

public class ValidatedSbomFactory
{
    public virtual IValidatedSbom CreateValidatedSbom(string sbomFilePath)
    {
        var sbomStream = new StreamReader(sbomFilePath);
        var validatedSbom = new ValidatedSbom(sbomStream.BaseStream);
        return validatedSbom;
    }
}
