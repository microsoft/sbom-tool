// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Tests.FormatValidator;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

internal readonly struct SpdxExemplars
{
    public const string JsonSpdx23Exemplar = /*lang=json,strict*/ @"{
  ""SPDXID"" : ""SPDXRef-DOCUMENT"",
  ""spdxVersion"" : ""SPDX-2.3"",
  ""creationInfo"" : {
    ""comment"" : ""This package has been shipped in source and binary form.\nThe binaries were created with gcc 4.5.1 and expect to link to\ncompatible system run time libraries."",
    ""created"" : ""2010-01-29T18:30:22Z"",
    ""creators"" : [ ""Tool: LicenseFind-1.0"", ""Organization: ExampleCodeInspect ()"", ""Person: Jane Doe ()"" ],
    ""licenseListVersion"" : ""3.17""
  },
  ""name"" : ""SPDX-Tools-v2.0"",
  ""dataLicense"" : ""CC0-1.0"",
  ""comment"" : ""This document was created using SPDX 2.0 using licenses from the web site."",
  ""externalDocumentRefs"" : [ {
    ""externalDocumentId"" : ""DocumentRef-spdx-tool-1.2"",
    ""checksum"" : {
      ""algorithm"" : ""SHA1"",
      ""checksumValue"" : ""d6a770ba38583ed4bb4525bd96e50461655d2759""
    },
    ""spdxDocument"" : ""http://spdx.org/spdxdocs/spdx-tools-v1.2-3F2504E0-4F89-41D3-9A0C-0305E82C3301""
  } ],
  ""hasExtractedLicensingInfos"" : [ {
    ""licenseId"" : ""LicenseRef-1"",
    ""extractedText"" : ""/*\n * (c) Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Hewlett-Packard Development Company, LP\n * All rights reserved.\n *\n * Redistribution and use in source and binary forms, with or without\n * modification, are permitted provided that the following conditions\n * are met:\n * 1. Redistributions of source code must retain the above copyright\n *    notice, this list of conditions and the following disclaimer.\n * 2. Redistributions in binary form must reproduce the above copyright\n *    notice, this list of conditions and the following disclaimer in the\n *    documentation and/or other materials provided with the distribution.\n * 3. The name of the author may not be used to endorse or promote products\n *    derived from this software without specific prior written permission.\n *\n * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR\n * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES\n * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.\n * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,\n * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT\n * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF\n * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n*/""
  }, {
    ""licenseId"" : ""LicenseRef-2"",
    ""extractedText"" : ""This package includes the GRDDL parser developed by Hewlett Packard under the following license:\n© Copyright 2007 Hewlett-Packard Development Company, LP\n\nRedistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: \n\nRedistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. \nRedistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution. \nThe name of the author may not be used to endorse or promote products derived from this software without specific prior written permission. \nTHIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.""
  }, {
    ""licenseId"" : ""LicenseRef-4"",
    ""extractedText"" : ""/*\n * (c) Copyright 2009 University of Bristol\n * All rights reserved.\n *\n * Redistribution and use in source and binary forms, with or without\n * modification, are permitted provided that the following conditions\n * are met:\n * 1. Redistributions of source code must retain the above copyright\n *    notice, this list of conditions and the following disclaimer.\n * 2. Redistributions in binary form must reproduce the above copyright\n *    notice, this list of conditions and the following disclaimer in the\n *    documentation and/or other materials provided with the distribution.\n * 3. The name of the author may not be used to endorse or promote products\n *    derived from this software without specific prior written permission.\n *\n * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR\n * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES\n * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.\n * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,\n * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT\n * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF\n * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n*/""
  }, {
    ""licenseId"" : ""LicenseRef-Beerware-4.2"",
    ""comment"" : ""The beerware license has a couple of other standard variants."",
    ""extractedText"" : ""\""THE BEER-WARE LICENSE\"" (Revision 42):\nphk@FreeBSD.ORG wrote this file. As long as you retain this notice you\ncan do whatever you want with this stuff. If we meet some day, and you think this stuff is worth it, you can buy me a beer in return Poul-Henning Kamp"",
    ""name"" : ""Beer-Ware License (Version 42)"",
    ""seeAlsos"" : [ ""http://people.freebsd.org/~phk/"" ]
  }, {
    ""licenseId"" : ""LicenseRef-3"",
    ""comment"" : ""This is tye CyperNeko License"",
    ""extractedText"" : ""The CyberNeko Software License, Version 1.0\n\n \n(C) Copyright 2002-2005, Andy Clark.  All rights reserved.\n \nRedistribution and use in source and binary forms, with or without\nmodification, are permitted provided that the following conditions\nare met:\n\n1. Redistributions of source code must retain the above copyright\n   notice, this list of conditions and the following disclaimer. \n\n2. Redistributions in binary form must reproduce the above copyright\n   notice, this list of conditions and the following disclaimer in\n   the documentation and/or other materials provided with the\n   distribution.\n\n3. The end-user documentation included with the redistribution,\n   if any, must include the following acknowledgment:  \n     \""This product includes software developed by Andy Clark.\""\n   Alternately, this acknowledgment may appear in the software itself,\n   if and wherever such third-party acknowledgments normally appear.\n\n4. The names \""CyberNeko\"" and \""NekoHTML\"" must not be used to endorse\n   or promote products derived from this software without prior \n   written permission. For written permission, please contact \n   andyc@cyberneko.net.\n\n5. Products derived from this software may not be called \""CyberNeko\"",\n   nor may \""CyberNeko\"" appear in their name, without prior written\n   permission of the author.\n\nTHIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED\nWARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES\nOF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE\nDISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR OTHER CONTRIBUTORS\nBE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, \nOR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT \nOF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR \nBUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, \nWHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE \nOR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, \nEVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."",
    ""name"" : ""CyberNeko License"",
    ""seeAlsos"" : [ ""http://people.apache.org/~andyc/neko/LICENSE"", ""http://justasample.url.com"" ]
  } ],
  ""annotations"" : [ {
    ""annotationDate"" : ""2010-01-29T18:30:22Z"",
    ""annotationType"" : ""OTHER"",
    ""annotator"" : ""Person: Jane Doe ()"",
    ""comment"" : ""Document level annotation""
  }, {
    ""annotationDate"" : ""2010-02-10T00:00:00Z"",
    ""annotationType"" : ""REVIEW"",
    ""annotator"" : ""Person: Joe Reviewer"",
    ""comment"" : ""This is just an example.  Some of the non-standard licenses look like they are actually BSD 3 clause licenses""
  }, {
    ""annotationDate"" : ""2011-03-13T00:00:00Z"",
    ""annotationType"" : ""REVIEW"",
    ""annotator"" : ""Person: Suzanne Reviewer"",
    ""comment"" : ""Another example reviewer.""
  } ],
  ""documentDescribes"" : [ ""SPDXRef-File"", ""SPDXRef-Package"" ],
  ""documentNamespace"" : ""http://spdx.org/spdxdocs/spdx-example-444504E0-4F89-41D3-9A0C-0305E82C3301"",
  ""packages"" : [ {
    ""SPDXID"" : ""SPDXRef-Package"",
    ""annotations"" : [ {
      ""annotationDate"" : ""2011-01-29T18:30:22Z"",
      ""annotationType"" : ""OTHER"",
      ""annotator"" : ""Person: Package Commenter"",
      ""comment"" : ""Package level annotation""
    } ],
    ""attributionTexts"" : [ ""The GNU C Library is free software.  See the file COPYING.LIB for copying conditions, and LICENSES for notices about a few contributions that require these additional notices to be distributed.  License copyright years may be listed using range notation, e.g., 1996-2015, indicating that every year in the range, inclusive, is a copyrightable year that would otherwise be listed individually."" ],
    ""builtDate"" : ""2011-01-29T18:30:22Z"",
    ""checksums"" : [ {
      ""algorithm"" : ""MD5"",
      ""checksumValue"" : ""624c1abb3664f4b35547e7c73864ad24""
    }, {
      ""algorithm"" : ""SHA1"",
      ""checksumValue"" : ""85ed0817af83a24ad8da68c2b5094de69833983c""
    }, {
      ""algorithm"" : ""SHA256"",
      ""checksumValue"" : ""11b6d3ee554eedf79299905a98f9b9a04e498210b59f15094c916c91d150efcd""
    }, {
      ""algorithm"" : ""BLAKE2b-384"",
      ""checksumValue"" : ""aaabd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706""
    } ],
    ""copyrightText"" : ""Copyright 2008-2010 John Smith"",
    ""description"" : ""The GNU C Library defines functions that are specified by the ISO C standard, as well as additional features specific to POSIX and other derivatives of the Unix operating system, and extensions specific to GNU systems."",
    ""downloadLocation"" : ""http://ftp.gnu.org/gnu/glibc/glibc-ports-2.15.tar.gz"",
    ""externalRefs"" : [ {
      ""referenceCategory"" : ""SECURITY"",
      ""referenceLocator"" : ""cpe:2.3:a:pivotal_software:spring_framework:4.1.0:*:*:*:*:*:*:*"",
      ""referenceType"" : ""cpe23Type""
    }, {
      ""comment"" : ""This is the external ref for Acme"",
      ""referenceCategory"" : ""OTHER"",
      ""referenceLocator"" : ""acmecorp/acmenator/4.1.3-alpha"",
      ""referenceType"" : ""http://spdx.org/spdxdocs/spdx-example-444504E0-4F89-41D3-9A0C-0305E82C3301#LocationRef-acmeforge""
    } ],
    ""filesAnalyzed"" : true,
    ""homepage"" : ""http://ftp.gnu.org/gnu/glibc"",
    ""licenseComments"" : ""The license for this project changed with the release of version x.y.  The version of the project included here post-dates the license change."",
    ""licenseConcluded"" : ""(LGPL-2.0-only OR LicenseRef-3)"",
    ""licenseDeclared"" : ""(LGPL-2.0-only AND LicenseRef-3)"",
    ""licenseInfoFromFiles"" : [ ""GPL-2.0-only"", ""LicenseRef-2"", ""LicenseRef-1"" ],
    ""name"" : ""glibc"",
    ""originator"" : ""Organization: ExampleCodeInspect (contact@example.com)"",
    ""packageFileName"" : ""glibc-2.11.1.tar.gz"",
    ""packageVerificationCode"" : {
      ""packageVerificationCodeExcludedFiles"" : [ ""./package.spdx"" ],
      ""packageVerificationCodeValue"" : ""d6a770ba38583ed4bb4525bd96e50461655d2758""
    },
    ""primaryPackagePurpose"" : ""SOURCE"",
    ""hasFiles"" : [ ""SPDXRef-Specification"", ""SPDXRef-Specification"", ""SPDXRef-CommonsLangSrc"", ""SPDXRef-Specification"", ""SPDXRef-CommonsLangSrc"", ""SPDXRef-JenaLib"", ""SPDXRef-Specification"", ""SPDXRef-CommonsLangSrc"", ""SPDXRef-JenaLib"", ""SPDXRef-DoapSource"", ""SPDXRef-Specification"", ""SPDXRef-CommonsLangSrc"", ""SPDXRef-JenaLib"", ""SPDXRef-DoapSource"" ],
    ""releaseDate"" : ""2012-01-29T18:30:22Z"",
    ""sourceInfo"" : ""uses glibc-2_11-branch from git://sourceware.org/git/glibc.git."",
    ""summary"" : ""GNU C library."",
    ""supplier"" : ""Person: Jane Doe (jane.doe@example.com)"",
    ""validUntilDate"" : ""2014-01-29T18:30:22Z"",
    ""versionInfo"" : ""2.11.1""
  }, {
    ""SPDXID"" : ""SPDXRef-fromDoap-1"",
    ""copyrightText"" : ""NOASSERTION"",
    ""downloadLocation"" : ""NOASSERTION"",
    ""filesAnalyzed"" : false,
    ""homepage"" : ""http://commons.apache.org/proper/commons-lang/"",
    ""licenseConcluded"" : ""NOASSERTION"",
    ""licenseDeclared"" : ""NOASSERTION"",
    ""supplier"" : ""Person: Jane Doe (jane.doe@example.com)"",
    ""name"" : ""Apache Commons Lang""
  }, {
    ""SPDXID"" : ""SPDXRef-fromDoap-0"",
    ""downloadLocation"" : ""https://search.maven.org/remotecontent?filepath=org/apache/jena/apache-jena/3.12.0/apache-jena-3.12.0.tar.gz"",
    ""externalRefs"" : [ {
      ""referenceCategory"" : ""PACKAGE-MANAGER"",
      ""referenceLocator"" : ""pkg:maven/org.apache.jena/apache-jena@3.12.0"",
      ""referenceType"" : ""purl""
    } ],
    ""supplier"": ""NOASSERTION"",
    ""filesAnalyzed"" : false,
    ""homepage"" : ""http://www.openjena.org/"",
    ""name"" : ""Jena"",
    ""versionInfo"" : ""3.12.0""
  }, {
    ""SPDXID"" : ""SPDXRef-Saxon"",
    ""checksums"" : [ {
      ""algorithm"" : ""SHA1"",
      ""checksumValue"" : ""85ed0817af83a24ad8da68c2b5094de69833983c""
    } ],
    ""copyrightText"" : ""Copyright Saxonica Ltd"",
    ""description"" : ""The Saxon package is a collection of tools for processing XML documents."",
    ""downloadLocation"" : ""https://sourceforge.net/projects/saxon/files/Saxon-B/8.8.0.7/saxonb8-8-0-7j.zip/download"",
    ""filesAnalyzed"" : false,
    ""homepage"" : ""http://saxon.sourceforge.net/"",
    ""licenseComments"" : ""Other versions available for a commercial license"",
    ""licenseConcluded"" : ""MPL-1.0"",
    ""licenseDeclared"" : ""MPL-1.0"",
    ""name"" : ""Saxon"",
    ""packageFileName"" : ""saxonB-8.8.zip"",
    ""supplier"" : ""Person: Jane Doe (jane.doe@example.com)"",
    ""versionInfo"" : ""8.8""
  } ],
  ""files"" : [ {
    ""SPDXID"" : ""SPDXRef-DoapSource"",
    ""checksums"" : [ {
      ""algorithm"" : ""SHA1"",
      ""checksumValue"" : ""2fd4e1c67a2d28fced849ee1bb76e7391b93eb12""
    } ],
    ""copyrightText"" : ""Copyright 2010, 2011 Source Auditor Inc."",
    ""fileContributors"" : [ ""Protecode Inc."", ""SPDX Technical Team Members"", ""Open Logic Inc."", ""Source Auditor Inc."", ""Black Duck Software In.c"" ],
    ""fileName"" : ""./src/org/spdx/parser/DOAPProject.java"",
    ""fileTypes"" : [ ""SOURCE"" ],
    ""licenseConcluded"" : ""Apache-2.0"",
    ""licenseInfoInFiles"" : [ ""Apache-2.0"" ]
  }, {
    ""SPDXID"" : ""SPDXRef-CommonsLangSrc"",
    ""checksums"" : [ {
      ""algorithm"" : ""SHA1"",
      ""checksumValue"" : ""c2b4e1c67a2d28fced849ee1bb76e7391b93f125""
    } ],
    ""comment"" : ""This file is used by Jena"",
    ""copyrightText"" : ""Copyright 2001-2011 The Apache Software Foundation"",
    ""fileContributors"" : [ ""Apache Software Foundation"" ],
    ""fileName"" : ""./lib-source/commons-lang3-3.1-sources.jar"",
    ""fileTypes"" : [ ""ARCHIVE"" ],
    ""licenseConcluded"" : ""Apache-2.0"",
    ""licenseInfoInFiles"" : [ ""Apache-2.0"" ],
    ""noticeText"" : ""Apache Commons Lang\nCopyright 2001-2011 The Apache Software Foundation\n\nThis product includes software developed by\nThe Apache Software Foundation (http://www.apache.org/).\n\nThis product includes software from the Spring Framework,\nunder the Apache License 2.0 (see: StringUtils.containsWhitespace())""
  }, {
    ""SPDXID"" : ""SPDXRef-JenaLib"",
    ""checksums"" : [ {
      ""algorithm"" : ""SHA1"",
      ""checksumValue"" : ""3ab4e1c67a2d28fced849ee1bb76e7391b93f125""
    } ],
    ""comment"" : ""This file belongs to Jena"",
    ""copyrightText"" : ""(c) Copyright 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Hewlett-Packard Development Company, LP"",
    ""fileContributors"" : [ ""Apache Software Foundation"", ""Hewlett Packard Inc."" ],
    ""fileName"" : ""./lib-source/jena-2.6.3-sources.jar"",
    ""fileTypes"" : [ ""ARCHIVE"" ],
    ""licenseComments"" : ""This license is used by Jena"",
    ""licenseConcluded"" : ""LicenseRef-1"",
    ""licenseInfoInFiles"" : [ ""LicenseRef-1"" ]
  }, {
    ""SPDXID"" : ""SPDXRef-Specification"",
    ""checksums"" : [ {
      ""algorithm"" : ""SHA1"",
      ""checksumValue"" : ""fff4e1c67a2d28fced849ee1bb76e7391b93f125""
    } ],
    ""comment"" : ""Specification Documentation"",
    ""fileName"" : ""./docs/myspec.pdf"",
    ""fileTypes"" : [ ""DOCUMENTATION"" ]
  }, {
    ""SPDXID"" : ""SPDXRef-File"",
    ""annotations"" : [ {
      ""annotationDate"" : ""2011-01-29T18:30:22Z"",
      ""annotationType"" : ""OTHER"",
      ""annotator"" : ""Person: File Commenter"",
      ""comment"" : ""File level annotation""
    } ],
    ""checksums"" : [ {
      ""algorithm"" : ""SHA1"",
      ""checksumValue"" : ""d6a770ba38583ed4bb4525bd96e50461655d2758""
    }, {
      ""algorithm"" : ""MD5"",
      ""checksumValue"" : ""624c1abb3664f4b35547e7c73864ad24""
    } ],
    ""comment"" : ""The concluded license was taken from the package level that the file was included in.\nThis information was found in the COPYING.txt file in the xyz directory."",
    ""copyrightText"" : ""Copyright 2008-2010 John Smith"",
    ""fileContributors"" : [ ""The Regents of the University of California"", ""Modified by Paul Mundt lethal@linux-sh.org"", ""IBM Corporation"" ],
    ""fileName"" : ""./package/foo.c"",
    ""fileTypes"" : [ ""SOURCE"" ],
    ""licenseComments"" : ""The concluded license was taken from the package level that the file was included in."",
    ""licenseConcluded"" : ""(LGPL-2.0-only OR LicenseRef-2)"",
    ""licenseInfoInFiles"" : [ ""GPL-2.0-only"", ""LicenseRef-2"" ],
    ""noticeText"" : ""Copyright (c) 2001 Aaron Lehmann aaroni@vitelus.com\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \""Software\""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: \nThe above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \""AS IS\"", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.""
  } ],
  ""snippets"" : [ {
    ""SPDXID"" : ""SPDXRef-Snippet"",
    ""comment"" : ""This snippet was identified as significant and highlighted in this Apache-2.0 file, when a commercial scanner identified it as being derived from file foo.c in package xyz which is licensed under GPL-2.0."",
    ""copyrightText"" : ""Copyright 2008-2010 John Smith"",
    ""licenseComments"" : ""The concluded license was taken from package xyz, from which the snippet was copied into the current file. The concluded license information was found in the COPYING.txt file in package xyz."",
    ""licenseConcluded"" : ""GPL-2.0-only"",
    ""licenseInfoInSnippets"" : [ ""GPL-2.0-only"" ],
    ""name"" : ""from linux kernel"",
    ""ranges"" : [ {
      ""endPointer"" : {
        ""offset"" : 420,
        ""reference"" : ""SPDXRef-DoapSource""
      },
      ""startPointer"" : {
        ""offset"" : 310,
        ""reference"" : ""SPDXRef-DoapSource""
      }
    }, {
      ""endPointer"" : {
        ""lineNumber"" : 23,
        ""reference"" : ""SPDXRef-DoapSource""
      },
      ""startPointer"" : {
        ""lineNumber"" : 5,
        ""reference"" : ""SPDXRef-DoapSource""
      }
    } ],
    ""snippetFromFile"" : ""SPDXRef-DoapSource""
  } ],
  ""relationships"" : [ {
    ""spdxElementId"" : ""SPDXRef-DOCUMENT"",
    ""relationshipType"" : ""CONTAINS"",
    ""relatedSpdxElement"" : ""SPDXRef-Package""
  }, {
    ""spdxElementId"" : ""SPDXRef-DOCUMENT"",
    ""relationshipType"" : ""COPY_OF"",
    ""relatedSpdxElement"" : ""DocumentRef-spdx-tool-1.2:SPDXRef-ToolsElement""
  }, {
    ""spdxElementId"" : ""SPDXRef-Package"",
    ""relationshipType"" : ""DYNAMIC_LINK"",
    ""relatedSpdxElement"" : ""SPDXRef-Saxon""
  }, {
    ""spdxElementId"" : ""SPDXRef-CommonsLangSrc"",
    ""relationshipType"" : ""GENERATED_FROM"",
    ""relatedSpdxElement"" : ""NOASSERTION""
  }, {
    ""spdxElementId"" : ""SPDXRef-JenaLib"",
    ""relationshipType"" : ""CONTAINS"",
    ""relatedSpdxElement"" : ""SPDXRef-Package""
  }, {
    ""spdxElementId"" : ""SPDXRef-Specification"",
    ""relationshipType"" : ""SPECIFICATION_FOR"",
    ""relatedSpdxElement"" : ""SPDXRef-fromDoap-0""
  }, {
    ""spdxElementId"" : ""SPDXRef-File"",
    ""relationshipType"" : ""GENERATED_FROM"",
    ""relatedSpdxElement"" : ""SPDXRef-fromDoap-0""
  } ]
}";
}
