// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Tests.PackageDetails;

public static class SampleMetadataFiles
{
    public const string PomWithLicensesAndDevelopers = @"<?xml version=""1.0"" encoding=""ISO-8859-1""?>
                        <project xmlns=""http://maven.apache.org/POM/4.0.0"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
                        xsi:schemaLocation=""http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd"">
                        <modelVersion>4.0.0</modelVersion>

                        <groupId>org.test</groupId>
                        <artifactId>test-package</artifactId>
                        <version>1.3</version>
                        <packaging>pom</packaging>

                        <licenses>
                            <license>
                            <name>New BSD License</name>
                            <url>http://www.opensource.org/licenses/bsd-license.php</url>
                            <distribution>repo</distribution>
                            </license>
                        </licenses>

                        <developers>
                            <developer>
                            <id>SAMPLE</id>
                            <name>Sample Name</name>
                            <roles>
                                <role>Developer</role>
                            </roles>
                            </developer>
                        </developers>
                        </project>";

    public const string PomWithoutDevelopersSection = @"<?xml version=""1.0"" encoding=""ISO-8859-1""?>
                        <project xmlns=""http://maven.apache.org/POM/4.0.0"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
                        xsi:schemaLocation=""http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd"">
                        <modelVersion>4.0.0</modelVersion>

                        <groupId>org.test</groupId>
                        <artifactId>test-package</artifactId>
                        <version>1.3</version>
                        <packaging>pom</packaging>

                        <licenses>
                            <license>
                            <name>New BSD License</name>
                            <url>http://www.opensource.org/licenses/bsd-license.php</url>
                            <distribution>repo</distribution>
                            </license>
                        </licenses>
                        </project>";

    public const string PomWithoutLicense = @"<?xml version=""1.0"" encoding=""ISO-8859-1""?>
                        <project xmlns=""http://maven.apache.org/POM/4.0.0"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""
                        xsi:schemaLocation=""http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd"">
                        <modelVersion>4.0.0</modelVersion>

                        <groupId>org.test</groupId>
                        <artifactId>test-package</artifactId>
                        <version>1.3</version>
                        <packaging>pom</packaging>

                        <developers>
                            <developer>
                            <id>SAMPLE</id>
                            <name>Sample Name</name>
                            <roles>
                                <role>Developer</role>
                            </roles>
                            </developer>
                        </developers>
                        </project>";

    public const string NuspecWithValidLicenseAndAuthors = @"<package>
                                <metadata>
                                    <id>FakePackageName</id>
                                    <version>1.0</version>
                                    <authors>FakeAuthor</authors>
                                    <license type=""expression"">FakeLicense</license>
                                </metadata>-
                            </package>";

    public const string NuspecWithInvalidLicense = @"<package>
                                <metadata>
                                    <id>FakePackageName</id>
                                    <version>1.0</version>
                                    <authors>FakeAuthor</authors>
                                    <license type=""file"">FakeLicense</license>
                                </metadata>-
                            </package>";

    public const string NuspecWithoutAuthor = @"<package>
                                <metadata>
                                    <id>FakePackageName</id>
                                    <version>1.0</version>
                                </metadata>-
                            </package>";
}
