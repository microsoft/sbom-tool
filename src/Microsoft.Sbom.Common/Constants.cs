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

    public const int DefaultLicenseFetchTimeoutInSeconds = 30;
    public const int MaxLicenseFetchTimeoutInSeconds = 86400;

    public const LogEventLevel DefaultLogLevel = LogEventLevel.Warning;

    public const string DefaultManifestInfoName = "SPDX";
    public const string DefaultManifestInfoVersion = "2.2";

    public const string SPDXContextHeaderName = "@context";
    public const string SPDXGraphHeaderName = "@graph";
    public const string SPDXRefFile = "SPDXRef-File";
    public const string SPDXRefPackage = "SPDXRef-Package";
    public const string SPDXRefExternalDocument = "DocumentRef";
    public const string NoAssertionValue = "NOASSERTION";
}
