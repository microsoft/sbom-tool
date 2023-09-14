// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace JsonStreaming;

public class LargeJsonParser
{
    private const int DefaultReadBufferSize = 4096;
    private readonly Stream stream;
    private readonly IReadOnlyDictionary<string, PropertyHandler> handlers;
    private readonly JsonSerializerOptions jsonSerializerOptions;
    private byte[] buffer;
    private JsonReaderState readerState;
    private bool isFinalBlock;
    private bool isParsingStarted = false;
    private bool enumeratorActive = false;
    private ParserStateResult? previousResultState = null;

    // TODO: Throw this away
    private string? previousParameter = null;

    public LargeJsonParser(
        Stream stream,
        IReadOnlyDictionary<string, PropertyHandler> handlers,
        JsonSerializerOptions? jsonSerializerOptions = default,
        int bufferSize = DefaultReadBufferSize)
    {
        this.stream = stream ?? throw new ArgumentNullException(nameof(stream));
        this.handlers = handlers ?? throw new ArgumentNullException(nameof(handlers));
        this.jsonSerializerOptions = jsonSerializerOptions ?? new JsonSerializerOptions();

        this.buffer = new byte[bufferSize];

        // Validate buffer is not of 0 length.
        if (this.buffer.Length == 0)
        {
            throw new ArgumentException($"The {nameof(this.buffer)} value can't be null or of 0 length.");
        }

        this.stream.Position = GetStartPosition(this.stream);

        if (!stream.CanRead || stream.Read(this.buffer) == 0)
        {
            throw new EndOfStreamException();
        }

        static int GetStartPosition(Stream stream)
        {
            var bom = Encoding.UTF8.Preamble.ToArray();
            stream.Position = 0;
            var buffer = new byte[bom.Length];
            _ = stream.Read(buffer, 0, buffer.Length);

            return Enumerable.SequenceEqual(buffer, bom) ? 3 : 0;
        }
    }

    /// <summary>
    /// Begin evaluating the next section of the json stream.
    /// </summary>
    /// <returns>A ParserStateResult object describing the section that was encountered or null if this was the final state.</returns>
    /// <remarks>If the result object is an enumerable you MUST ensure that you've walked it entirely before calling next again.</remarks>
    public ParserStateResult? Next()
    {
        if (this.enumeratorActive)
        {
            throw new ParserException("You must walk the entire enumerable from the previous result before calling Next() again.");
        }

        try
        {
            var reader = new Utf8JsonReader(this.buffer, isFinalBlock: this.isFinalBlock, this.readerState);

            if (!this.isParsingStarted)
            {
                ParserUtils.SkipNoneTokens(this.stream, ref this.buffer, ref reader);

                ParserUtils.AssertTokenType(this.stream, ref reader, JsonTokenType.StartObject);
                ParserUtils.GetMoreBytesFromStream(this.stream, ref this.buffer, ref reader);

                this.isParsingStarted = true;
            }

            ParserUtils.Read(this.stream, ref this.buffer, ref reader);

            // If the end of the Json Object is reached, return null to indicate completion.
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                return null;
            }
            else if (this.previousResultState is not null && this.previousResultState.YieldReturn && reader.TokenType == JsonTokenType.EndArray)
            {
                // yield returning json arrays means we can't pass it the same Utf8JsonReader ref, so we need to create a new one.
                // BUT when we do that we end up consuming the next token, so we need to leave it in the array case to be eatten by the next caller.
                ParserUtils.Read(this.stream, ref this.buffer, ref reader);
            }

            // If the end of the Json Object is reached, return null to indicate completion.
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                return null;
            }

            ParserUtils.AssertTokenType(this.stream, ref reader, JsonTokenType.PropertyName);
            var propertyName = reader.GetString() ?? throw new NotImplementedException();
            this.previousParameter = propertyName;
            ParserUtils.Read(this.stream, ref this.buffer, ref reader);

            ParserStateResult resultState;
            if (this.handlers.ContainsKey(propertyName))
            {
                resultState = this.HandleExplicitProperty(ref reader, propertyName);
            }
            else
            {
                resultState = this.HandleExtraProperty(ref reader, propertyName);
            }

            // yield return is a special case where we need to leave the reader in the same state as we found it.
            if (!resultState.YieldReturn)
            {
                ParserUtils.GetMoreBytesFromStream(this.stream, ref this.buffer, ref reader);

                this.isFinalBlock = reader.IsFinalBlock;
                this.readerState = reader.CurrentState;
            }

            this.previousResultState = resultState;

            return resultState;
        }
        catch (JsonException ex)
        {
            throw new ParserException($"Error parsing json at position {this.stream.Position}", ex);
        }
    }

    private ParserStateResult HandleExplicitProperty(ref Utf8JsonReader reader, string propertyName)
    {
        var handler = this.handlers![propertyName];

        object? result;
        switch (handler.Type)
        {
            case ParameterType.String:
                ParserUtils.AssertTokenType(this.stream, ref reader, JsonTokenType.String);
                result = reader.GetString();
                break;
            case ParameterType.Skip:
                ParserUtils.SkipProperty(this.stream, ref this.buffer, ref reader);
                result = null;
                break;
            case ParameterType.Int:
                ParserUtils.AssertTokenType(this.stream, ref reader, JsonTokenType.Number);
                var i = reader.GetInt32();
                result = i;
                break;
            case ParameterType.Object:
                var objType = handler.GetType().GetGenericArguments()[0];
                result = this.ParseObject(ref reader, objType);
                break;
            case ParameterType.Array:
                var aryType = handler.GetType().GetGenericArguments()[0];
                result = this.ParseArray(ref reader, aryType);
                break;
            default:
                throw new InvalidOperationException($"Unknown {nameof(ParameterType)}: {handler.Type}");
        }

        return new ParserStateResult(propertyName, result, ExplicitField: true, YieldReturn: handler.Type == ParameterType.Array);
    }

    private ParserStateResult HandleExtraProperty(ref Utf8JsonReader reader, string propertyName)
    {
        // We skip objects and arrays to avoid having to parse them.
        object? result = reader.TokenType switch
        {
            JsonTokenType.String => reader.GetString(),
            JsonTokenType.Number => reader.GetInt32(),
            JsonTokenType.True => true,
            JsonTokenType.False => false,
            JsonTokenType.StartArray => ParserUtils.ParseArray(this.stream, ref this.buffer, ref reader),
            JsonTokenType.StartObject => ParserUtils.ParseObject(this.stream, ref this.buffer, ref reader),
            JsonTokenType.None => throw new NotImplementedException(),
            JsonTokenType.EndObject => throw new NotImplementedException(),
            JsonTokenType.EndArray => throw new NotImplementedException(),
            JsonTokenType.PropertyName => throw new NotImplementedException(),
            JsonTokenType.Comment => throw new NotImplementedException(),
            JsonTokenType.Null => throw new NotImplementedException(),
            _ => throw new InvalidOperationException($"Unknown {nameof(JsonTokenType)}: {reader.TokenType}"),
        };
        return new ParserStateResult(propertyName, result, ExplicitField: true, YieldReturn: false);
    }

    private IEnumerable<object> ParseArray(ref Utf8JsonReader reader, Type objType)
    {
        ParserUtils.AssertTokenType(this.stream, ref reader, JsonTokenType.StartArray);

        // We can't pass the current reader along, so we need to save it's state for it.
        ParserUtils.GetMoreBytesFromStream(this.stream, ref this.buffer, ref reader);

        this.isFinalBlock = reader.IsFinalBlock;
        this.readerState = reader.CurrentState;

        return this.GetArray(objType);
    }

    private object ParseObject(ref Utf8JsonReader reader, Type objType, bool consumeEnding = false)
    {
        return this.GetObject(objType, ref reader, consumeEnding);
    }

    private IEnumerable<object> GetArray(Type type)
    {
        this.enumeratorActive = true;
        while (true)
        {
            var obj = this.ReadArrayObject(type);
            if (obj is not null)
            {
                yield return obj;
            }
            else
            {
                this.enumeratorActive = false;
                yield break;
            }
        }
    }

    private object GetObject(Type type, ref Utf8JsonReader reader, bool consumeEnding)
    {
        var jsonObject = this.ReadObject(ref reader, consumeEnding);
        object? result = jsonObject;
        if (type != typeof(JsonNode))
        {
            result = jsonObject.Deserialize(type, this.jsonSerializerOptions);
        }

        if (result is null)
        {
            throw new NotImplementedException();
        }

        return result;
    }

    private object? ReadArrayObject(Type type)
    {
        try
        {
            var reader = new Utf8JsonReader(this.buffer, this.isFinalBlock, this.readerState);

            if (reader.TokenType == JsonTokenType.StartArray)
            {
                ParserUtils.SkipFirstArrayToken(this.stream, ref this.buffer, ref reader);
            }
            else
            {
                ParserUtils.Read(this.stream, ref this.buffer, ref reader);
            }

            object? result;
            if (reader.TokenType == JsonTokenType.EndArray)
            {
                result = null;
            }
            else
            {
                result = this.GetObject(type, ref reader, consumeEnding: false);
            }

            ParserUtils.GetMoreBytesFromStream(this.stream, ref this.buffer, ref reader);

            this.isFinalBlock = reader.IsFinalBlock;
            this.readerState = reader.CurrentState;

            return result;
        }
        catch (JsonException ex)
        {
            throw new ParserException($"Error parsing json at position {this.stream.Position}", ex);
        }
    }

    private JsonNode ReadObject(ref Utf8JsonReader reader, bool consumeEnding = true)
    {
        var obj = ParserUtils.ParseObject(this.stream, ref this.buffer, ref reader);
        if (consumeEnding)
        {
            ParserUtils.Read(this.stream, ref this.buffer, ref reader);
        }

        return obj;
    }
}
