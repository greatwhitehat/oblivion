using System;
using System.Text;

namespace Oblivion
{
    class Conversions
    {
        //Convert a byte array to string (HEX)
        public static string byteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        //Convert byte to HEX
        public static string byteToHex(byte b)
        {
            StringBuilder hex = new StringBuilder(2);
            hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        //Convert string (HEX) to a byte array
        public static byte[] stringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        //Convert string (ASCII) to string (HEX)
        public static string stringToHex(string asciiString)
        {
            string hex = "";
            foreach (char c in asciiString)
            {
                int tmp = c;
                hex += String.Format("{0:x2}", (uint)System.Convert.ToUInt32(tmp.ToString()));
            }
            return hex;
        }

        
    }
}