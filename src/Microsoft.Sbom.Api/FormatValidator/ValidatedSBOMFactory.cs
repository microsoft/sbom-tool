// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.FormatValidator;

using System.IO;

public class ValidatedSBOMFactory
{
    public virtual IValidatedSbom CreateValidatedSBOM(string sbomFilePath)
    {
        var sbomStream = new StreamReader(sbomFilePath);
        var validatedSbom = new ValidatedSBOM(sbomStream.BaseStream);
        return validatedSbom;
    }
}
