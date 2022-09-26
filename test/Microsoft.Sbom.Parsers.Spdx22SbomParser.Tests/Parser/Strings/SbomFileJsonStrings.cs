namespace Microsoft.Sbom.Parser.Strings;

internal struct SbomFileJsonStrings
{
    public SbomFileJsonStrings()
    {
    }

    public const string GoodJsonWith2FilesString = @"{
            ""files"": [
            {
                ""fileName"": ""./file1"",
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""checksums"": [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ],
                ""copyrightText"": ""NOASSERTION""
            },
            {
                ""fileName"": ""./file2"",
                ""SPDXID"": ""SPDXRef-File--test.xml-E55F25E239D8D3572D75D5CDC5CA24899FD4993E"",
                ""checksums"": [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad2""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd49932""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION"", ""GNU""
                ],
                ""copyrightText"": ""NOASSERTION""
            }
        ]}";

    public const string MalformedJsonEmptyObjectNoArrayEnd = @"{
            ""files"": [{
                ""fileName"": ""./file1"",
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""checksums"": [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ,
                ""copyrightText"": ""NOASSERTION""
            }]}";

    public const string MalformedJsonEmptyObject = @"{""files"":{}";
    public const string MalformedJsonEmptyArray = @"{""files"": []";
    public const string MalformedJson = @"{
            ""files"": [
            {
                ""fileName"": ""./file1"",
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""checksums"" [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ],
                ""copyrightText"": ""NOASSERTION""
            }]}";

    public const string GoodJsonWith1FileAdditionalStringPropertyString = @"{
            ""files"": [
            {
                ""fileName"": ""./additional"",
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""additionalProperty"": ""Additional property value"",
                ""checksums"": [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ],
                ""copyrightText"": ""NOASSERTION""
            }]}";
          
    public const string GoodJsonWith1FileAdditionalValueArrayPropertyString = @"{
            ""files"": [
            {
                ""fileName"": ""./file1"",
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""additionalProperty"": [""Additional value 1"", ""Additional value 2""],
                ""checksums"": [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ],
                ""copyrightText"": ""NOASSERTION""
            }]}";

    public const string GoodJsonWith1FileAdditionalArrayPropertyString = @"{
            ""files"": [
            {
                ""fileName"": ""./file1"",
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""additionalProperty"": [
                    {""childAddtionalProperty"": ""Additional property value"" 
                }],
                ""checksums"": [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ],
                ""copyrightText"": ""NOASSERTION""
            }]}";

    public const string GoodJsonWith1FileAdditionalObjectPropertyString = @"{
            ""files"": [
            {
                ""fileName"": ""./file1"",
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""additionalProperty"": {
                    ""childAddtionalProperty"": ""Additional property value""
                },
                ""checksums"": [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ],
                ""copyrightText"": ""NOASSERTION""
            }]}";

    public const string JsonWith1FileMissingNameString = @"{
            ""files"": [
            {
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""checksums"": [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ],
                ""copyrightText"": ""NOASSERTION""
            }]}";

    public const string JsonWith1FileMissingIDString = @"{
            ""files"": [
            {                
                ""fileName"": ""./file1"",
                ""checksums"": [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ],
                ""copyrightText"": ""NOASSERTION""
            }]}";

    public const string JsonWith1FileMissingChecksumsString = @"{
            ""files"": [
            {
                ""fileName"": ""./file1"",
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ],
                ""copyrightText"": ""NOASSERTION""
            }]}";

    public const string JsonWith1FileMissingSHA256ChecksumsString = @"{
            ""files"": [
            {
                ""fileName"": ""./file1"",
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""checksums"": [
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ],
                ""copyrightText"": ""NOASSERTION""
            }]}";

    public const string JsonWith1FileMissingLicenseConcludedString = @"{
            ""files"": [
            {
                ""fileName"": ""./file1"",
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""checksums"": [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ],
                ""copyrightText"": ""NOASSERTION""
            }]}";

    public const string JsonWith1FileMissingLicenseInfoInFilesString = @"{
            ""files"": [
            {
                ""fileName"": ""./file1"",
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""checksums"": [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""copyrightText"": ""NOASSERTION""
            }]}";

    public const string JsonWith1FileMissingCopyrightString = @"{
            ""files"": [
            {
                ""fileName"": ""./file1"",
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""checksums"": [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ]
            }]}";

    public const string JsonWith1FileMissingCopyrightAndPathString = @"{
            ""files"": [
            {
                ""SPDXID"": ""SPDXRef-File--sbom-tool-win-x64.exe-E55F25E239D8D3572D75D5CDC5CA24899FD4993F"",
                ""checksums"": [
                {
                    ""algorithm"": ""SHA256"",
                    ""checksumValue"": ""56624d8ab67ac0e323bcac0ae1ec0656f1721c6bb60640ecf9b30e861062aad5""
                },
                {
                    ""algorithm"": ""SHA1"",
                    ""checksumValue"": ""e55f25e239d8d3572d75d5cdc5ca24899fd4993f""
                }
                ],
                ""licenseConcluded"": ""NOASSERTION"",
                ""licenseInfoInFiles"": [
                    ""NOASSERTION""
                ]
            }]}";
}
