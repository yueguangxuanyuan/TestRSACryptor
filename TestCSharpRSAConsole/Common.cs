using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TestCSharpRSAConsole
{
    class Common
    {
        public static String RSAPublicKey = @"MFowDQYJKoZIhvcNAQEBBQADSQAwRgJBAKizDEwS3CL9obsSOxIcWi6KcoiiDOUPmu+kPme/
CllyP+i1Sltz+LKdldmd5YncH1QTmPxFL4AnoBaB8LHLdAcCARE=
";
        public static String RSAPrivateKey = @"MIIBUQIBADANBgkqhkiG9w0BAQEFAASCATswggE3AgEAAkEAqLMMTBLcIv2huxI7EhxaLopy
iKIM5Q+a76Q+Z78KWXI/6LVKW3P4sp2V2Z3lidwfVBOY/EUvgCegFoHwsct0BwIBEQJANpRH
vkJWR45K6bMTHHKVpaVDLDRtlWbuXJcFIZChd0oVLOekpTnAUHUCYlj2wt4DK7YV0QQJSkoQ
THqXSEC8zQIhAOOz0TI9Zq+xgQaMomDsmq6G+Mqwtn/izX+EkcDl2iDlAiEAvaoYGzagmXzK
KtcuW1o2IS65c5b2kuZGqF+7FmD6rnsCIFBdlSDKYHo+pgJPwNbqGHnVSMACIktA/TwQq+m6
iTjJAiBkaRvSK/qrnGsHnxiKt0nVVPjEuVVc1EOGUMx1QmaYmwIgbKFhVWXQJfHAGjcNAXLM
jfahduCd3ryP6iD8ON2OJuw=
";

        public static int GetOEAPFixedMaxPlainTextLength(int ChipterLength)
        {
            return ChipterLength - 42;
        }
    }
}
