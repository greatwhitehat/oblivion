using System.Security.Cryptography;

namespace Oblivion
{
    class KeyMgmt
    {
        //Create a SHA-512 hash string
        public static string generateSHA512(byte[] data)
        {
            byte[] result;

            SHA512 hash = new SHA512Managed();
            result = hash.ComputeHash(data);

            return Conversions.byteArrayToString(result);
        }

        public static string[] generateKeys(string password)
        {
            string[] keys = new string[5];

            keys[0] = BCrypt.GenerateSalt();
            keys[1] = BCrypt.HashPassword(password, keys[0]);
            keys[2] = BCrypt.HashPassword(keys[1], keys[0]);
            keys[3] = BCrypt.HashPassword(keys[2], keys[0]);
            keys[4] = BCrypt.HashPassword(keys[3], keys[0]);

            return keys;
        }

        //Generate round key
        public static string generateRoundKey(string masterKey, int round)
        {
            string roundKey = string.Empty;

            round = round % masterKey.Length;
            if (round < masterKey.Length - 1)
                roundKey = masterKey.Substring(round, 2);
            else
                roundKey = masterKey.Substring(masterKey.Length - 1, 1) + masterKey.Substring(0, 1);
            
            return roundKey;
        }


        
    }
}
