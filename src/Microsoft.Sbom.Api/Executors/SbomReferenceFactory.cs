// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Executors;

using System;
using System.Collections.Generic;
using System.Linq;

public class SbomReferenceFactory : ISbomReferenceFactory, IDisposable
{
    private List<ISbomReferenceDescriber> sbomReferenceDescribers;
    private bool disposed = false;

    // Need to hook up a DI service that can construct and provide the ISbomReferenceDescribers.
    public SbomReferenceFactory(IEnumerable<ISbomReferenceDescriber> sbomReferenceDescribers)
    {
        this.sbomReferenceDescribers = sbomReferenceDescribers.ToList();
    }

    public ISbomReferenceDescriber GetSbomReferenceDescriber(string sbomFilePath)
    {
        foreach (var referenceDescriber in sbomReferenceDescribers)
        {
            if(referenceDescriber.IsSupportedFormat(sbomFilePath))
                return referenceDescriber;
        }
        return null;
    }

    public void Dispose()
    {
        if (!disposed)
        {
            foreach (var describer in sbomReferenceDescribers)
            {
                if (describer is IDisposable disposable)
                {
                    disposable.Dispose();
                }
            }
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
