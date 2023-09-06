// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Api.Tests;

internal class HttpRequestUtils
{
    public const string GoodClearlyDefinedAPIResponse = @"{
  ""npm/npmjs/-/json5/2.2.3"": {
    ""described"": {
      ""releaseDate"": ""2022-12-31"",
      ""sourceLocation"": {
        ""type"": ""git"",
        ""provider"": ""github"",
        ""namespace"": ""json5"",
        ""name"": ""json5"",
        ""revision"": ""c3a75242772a5026a49c4017a16d9b3543b62776"",
        ""url"": ""https://github.com/json5/json5/tree/c3a75242772a5026a49c4017a16d9b3543b62776""
      },
      ""urls"": {
        ""registry"": ""https://npmjs.com/package/json5"",
        ""version"": ""https://npmjs.com/package/json5/v/2.2.3"",
        ""download"": ""https://registry.npmjs.com/json5/-/json5-2.2.3.tgz""
      },
      ""projectWebsite"": ""http://json5.org/"",
      ""issueTracker"": ""https://github.com/json5/json5/issues"",
      ""hashes"": {
        ""sha1"": ""78cd6f1a19bdc12b73db5ad0c61efd66c1e29283"",
        ""sha256"": ""08afb33db600d11fc89b98fac4054f19d5d3e0fe527063116150e1ecc2d2377b""
      },
      ""files"": 20,
      ""tools"": [
        ""clearlydefined/1.3.4"",
        ""reuse/1.3.0"",
        ""licensee/9.14.0"",
        ""scancode/30.3.0""
      ],
      ""toolScore"": {
        ""total"": 100,
        ""date"": 30,
        ""source"": 70
      },
      ""score"": {
        ""total"": 100,
        ""date"": 30,
        ""source"": 70
      }
    },
    ""licensed"": {
      ""declared"": ""MIT"",
      ""toolScore"": {
        ""total"": 61,
        ""declared"": 30,
        ""discovered"": 1,
        ""consistency"": 0,
        ""spdx"": 15,
        ""texts"": 15
      },
      ""facets"": {
        ""core"": {
          ""attribution"": {
            ""unknown"": 17,
            ""parties"": [
              ""(c) 2019 Denis Pushkarev"",
              ""copyright (c) 2019 Denis Pushkarev"",
              ""Copyright (c) 2012-2018 Aseem Kishore, and others""
            ]
          },
          ""discovered"": {
            ""unknown"": 17,
            ""expressions"": [
              ""MIT"",
              ""MIT AND NOASSERTION""
            ]
          },
          ""files"": 20
        }
      },
      ""score"": {
        ""total"": 61,
        ""declared"": 30,
        ""discovered"": 1,
        ""consistency"": 0,
        ""spdx"": 15,
        ""texts"": 15
      }
    },
    ""coordinates"": {
      ""type"": ""npm"",
      ""provider"": ""npmjs"",
      ""name"": ""json5"",
      ""revision"": ""2.2.3""
    },
    ""_meta"": {
      ""schemaVersion"": ""1.6.1"",
      ""updated"": ""2023-01-17T15:44:42.747Z""
    },
    ""scores"": {
      ""effective"": 80,
      ""tool"": 80
    }
  },
}";

    public const string BadClearlyDefinedAPIResponse = @"{""score"": {
        ""total"": 61,
        ""declared"": 30,
        ""discovered"": 1,
        ""consistency"": 0,
        ""spdx"": 15,
        ""texts"": 15
      }}";
}
