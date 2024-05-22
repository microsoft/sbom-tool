// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Parsers.Spdx22SbomParser.Entities;

using System;
using System.Text.Json.Serialization;

public class Annotation
{
    [JsonPropertyName("annotationDate")]
    public DateTime AnnotationDate { get; set; }

    [JsonPropertyName("annotationType")]
    public string AnnotationType { get; set; }

    [JsonPropertyName("annotator")]
    public string Annotator { get; set; }

    [JsonPropertyName("comment")]
    public string Comment { get; set; }
}
