// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.FormatValidator;

using System.Collections.Generic;

public class FormatValidationResults
{
    public FormatValidationStatus Status { get; private set; } = FormatValidationStatus.Unknown;

    // Update the validation status, without overwriting a previous NotValid status.
    public void AggregateValidationStatus(FormatValidationStatus newStatus)
    {
        // If status never set, always overwrite.
        if (Status == FormatValidationStatus.Unknown)
        {
            Status = newStatus;
            return;
        }

        // If previous status not valid, never overwrite.
        if (Status == FormatValidationStatus.NotValid)
        {
            return;
        }

        // If previous status valid, always overwrite.
        Status = newStatus;
    }

    public List<string> Errors { get; set; } = new List<string>();
}
