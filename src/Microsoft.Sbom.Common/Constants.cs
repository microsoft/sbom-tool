// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Serilog.Events;

namespace Microsoft.Sbom.Common;

public static class Constants
{
    public const int DefaultStreamBufferSize = 4096;

    public const int MinParallelism = 2;
    public const int DefaultParallelism = 8;
    public const int MaxParallelism = 48;

    public const LogEventLevel DefaultLogLevel = LogEventLevel.Warning;
}