namespace Microsoft.Sbom.Entities;
#pragma warning disable SA1313 // Parameter names should begin with lower-case letter
internal record ErrorInfo(string ClassName, Exception Exception, string? Message = null);
#pragma warning restore SA1313 // Parameter names should begin with lower-case letter
