// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Common;

public interface IProcessExecutor
{
    string ExecuteCommand(string fileName, string arguments, int timeoutInMilliseconds);
}
