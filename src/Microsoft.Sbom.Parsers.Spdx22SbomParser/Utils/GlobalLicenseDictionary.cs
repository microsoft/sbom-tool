// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

// I know use of a global state is not ideal. I could use feedback on how to achieve this in a better way.
public static class GlobalLicenseDictionary
{
    private static Dictionary<string, string> _licenseDictionary = new Dictionary<string, string>();

    public static Dictionary<string, string> LicenseDictionary
    {
        get { return _licenseDictionary; }
        set { _licenseDictionary = value; }
    }
}