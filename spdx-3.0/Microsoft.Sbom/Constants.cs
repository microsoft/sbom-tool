namespace Microsoft.Sbom;
internal class Constants
{
    internal const string SpecVersion = "3.0.0";
    internal const string DataLicense = "CC0-1.0";
    internal const string SBOMName = "SBOM";
    internal const string CreationInfoId = "_a";
    internal const string FileIdString = "SPDXRef-File";
    internal const string PackageIdString = "SPDXRef-Package";
    internal const string SpdxDocumentIdString = "SPDXRef-DOCUMENT";
    internal const string ActorIdString = "SPDXRef-Actor";

    internal static Uri DefaultNamespace = new ("https://sbom.microsoft");
    internal const string DefaultDocumentName = "spdxDocument";
}
