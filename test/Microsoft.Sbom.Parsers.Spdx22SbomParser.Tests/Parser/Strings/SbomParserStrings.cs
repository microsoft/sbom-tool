namespace Microsoft.Sbom.Parser.Strings;

internal readonly struct SbomParserStrings
{
    public const string JsonWithAll4Properties = @"{
                ""files"":[],
                ""packages"":[],
                ""testSkip1"":""testValue"",
                ""testSkip2"":[],
                ""relationships"":[],
                ""testSkip3"":[""test"", ""test2""],
                ""testSkip4"":[
                    {""test1"":""val""},
                    {""test2"":[{""test"":""final""}]}],
                ""externalDocumentRefs"":[],
                ""testSkip4"":{
                    ""test"":{""rr"":22}}}";

    public const string JsonWithMissingFiles = @"{
                ""packages"":[],
                ""testSkip1"":""testValue"",
                ""testSkip2"":[],
                ""relationships"":[],
                ""testSkip3"":[""test"", ""test2""],
                ""testSkip4"":[
                    {""test1"":""val""},
                    {""test2"":[{""test"":""final""}]}],
                ""externalDocumentRefs"":[],
                ""testSkip4"":{
                    ""test"":{""rr"":22}}}";

    public const string JsonWithMissingPackages = @"{
                ""files"":[],
                ""testSkip1"":""testValue"",
                ""testSkip2"":[],
                ""relationships"":[],
                ""testSkip3"":[""test"", ""test2""],
                ""testSkip4"":[
                    {""test1"":""val""},
                    {""test2"":[{""test"":""final""}]}],
                ""externalDocumentRefs"":[],
                ""testSkip4"":{
                    ""test"":{""rr"":22}}}";

    public const string JsonWithMissingRelationships = @"{
                ""files"":[],
                ""testSkip1"":""testValue"",
                ""testSkip2"":[],
                ""testSkip3"":[""test"", ""test2""],
                ""testSkip4"":[
                    {""test1"":""val""},
                    {""test2"":[{""test"":""final""}]}],
                ""externalDocumentRefs"":[],
                ""testSkip4"":{
                    ""test"":{""rr"":22}}}";

    public const string JsonWithMissingReferences = @"{
                ""files"":[],
                ""testSkip1"":""testValue"",
                ""testSkip2"":[],
                ""relationships"":[],
                ""testSkip3"":[""test"", ""test2""],
                ""testSkip4"":[
                    {""test1"":""val""},
                    {""test2"":[{""test"":""final""}]}],
                ""testSkip4"":{
                    ""test"":{""rr"":22}}}";

    public const string MalformedJson = @"{
                ""files"":[],
                ""packages"":[],
                ""testSkip1"":""testValue"",
                ""testSkip2"":[],
                ""relationships"":],
                ""testSkip3"":[""test"", ""test2""],
                ""testSkip4"":[
                    {""test1"":""val""},
                    {""test2"":[{""test"":""final""}]}],
                ""externalDocumentRefs"":[],
                ""testSkip4"":{
                    ""test"":{""rr"":22}}}";

    public const string MalformedJsonIncorrectFilesType = @"{
                ""files"":{},
                ""packages"":[],
                ""testSkip1"":""testValue"",
                ""testSkip2"":[],
                ""relationships"":[],
                ""testSkip3"":[""test"", ""test2""],
                ""testSkip4"":[
                    {""test1"":""val""},
                    {""test2"":[{""test"":""final""}]}],
                ""externalDocumentRefs"":[],
                ""testSkip4"":{
                    ""test"":{""rr"":22}}}";

    public const string MalformedJsonIncorrectPackagesType = @"{
                ""files"":[],
                ""packages"":{},
                ""testSkip1"":""testValue"",
                ""testSkip2"":[],
                ""relationships"":[],
                ""testSkip3"":[""test"", ""test2""],
                ""testSkip4"":[
                    {""test1"":""val""},
                    {""test2"":[{""test"":""final""}]}],
                ""externalDocumentRefs"":[],
                ""testSkip4"":{
                    ""test"":{""rr"":22}}}";

    public const string MalformedJsonIncorrectRefsType = @"{
                ""files"":[],
                ""packages"":[],
                ""testSkip1"":""testValue"",
                ""testSkip2"":[],
                ""relationships"":[],
                ""testSkip3"":[""test"", ""test2""],
                ""testSkip4"":[
                    {""test1"":""val""},
                    {""test2"":[{""test"":""final""}]}],
                ""externalDocumentRefs"":{},
                ""testSkip4"":{
                    ""test"":{""rr"":22}}}";

    public const string MalformedJsonIncorrectRelationshipsType = @"{
                ""files"":[],
                ""packages"":[],
                ""testSkip1"":""testValue"",
                ""testSkip2"":[],
                ""relationships"":{},
                ""testSkip3"":[""test"", ""test2""],
                ""testSkip4"":[
                    {""test1"":""val""},
                    {""test2"":[{""test"":""final""}]}],
                ""externalDocumentRefs"":[],
                ""testSkip4"":{
                    ""test"":{""rr"":22}}}";

    public const string MalformedJsonEmptyJsonObject = @"{
                ""files"":[],
                ""packages"":[],
                ""testSkip1"":""testValue"",
                ""testSkip2"":[],
                ""relationships"":[],
                ""testSkip3"":[""test"", ""test2""],
                ""testSkip4"":[
                    {},
                    {""test2"":[{""test"":""final""}]}],
                ""externalDocumentRefs"":[],
                ""testSkip4"":{
                    ""test"":{""rr"":22}}}";

    public const string MalformedJsonEmptyArrayObject = @"{
                ""files"":[],
                ""packages"":[],
                ""testSkip1"":""testValue"",
                ""testSkip2"":[],
                ""relationships"":[],
                ""testSkip3"":[""test"", ""test2""],
                ""testSkip4"":[
                    {},
                    {""test2"":[{""test"":""final""}]}],
                ""externalDocumentRefs"":[],
                ""testSkip4"":{
                    ""test"":{""rr"":22}}}";
}
