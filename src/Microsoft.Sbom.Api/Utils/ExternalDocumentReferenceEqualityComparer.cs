// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Sbom.Extensions.Entities;
using Microsoft.Sbom.Contracts;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Microsoft.Sbom.Api.Utils
{
    /// <summary>
    /// Compares two ExternalDocumentReferenceInfo objects to see if they represent the same underlying external document.
    /// </summary>
    public class ExternalDocumentReferenceEqualityComparer : IEqualityComparer<ExternalDocumentReferenceInfo>
    {
        public bool Equals([AllowNull] ExternalDocumentReferenceInfo x, [AllowNull] ExternalDocumentReferenceInfo y)
        {
            if (x == null && y == null)
            {
                return true;
            }
            else if (x == null || y == null)
            {
                return false;
            }
            else if (string.Equals(x.DocumentNamespace, y.DocumentNamespace, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public int GetHashCode([DisallowNull] ExternalDocumentReferenceInfo obj)
        {
            if (obj.DocumentNamespace is null)
            {
                throw new ArgumentNullException(nameof(obj.DocumentNamespace));
            }

            return obj.DocumentNamespace.GetHashCode();
        }
    }
}
