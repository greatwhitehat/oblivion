using System;

namespace Oblivion
{
    class Crypto
    {
        //encryption
        public static byte[] encrypt(byte[] data, string masterkey)
        {
            byte[] block = new byte[8];
            int readByteCounter = 0;
            int writeByteCounter = 0;
            int blockByteCounter = 0;

            while (readByteCounter <= data.Length - 8)
            {
                while (blockByteCounter < 8)
                {
                    block[blockByteCounter] = data[readByteCounter + blockByteCounter];
                    blockByteCounter++;
                }

                block = encryptBlock(masterkey, block);
                blockByteCounter = 0;

                while (blockByteCounter < 8)
                {
                    data[writeByteCounter] = block[blockByteCounter];
                    blockByteCounter++;
                    writeByteCounter++;
                }
                blockByteCounter = 0;
                readByteCounter += 4;
                writeByteCounter = readByteCounter;
            }

            block[0] = data[0];
            block[1] = data[1];
            block[2] = data[2];
            block[3] = data[3];
            block[4] = data[data.Length - 4];
            block[5] = data[data.Length - 3];
            block[6] = data[data.Length - 2];
            block[7] = data[data.Length - 1];

            block = encryptBlock(masterkey, block);

            data[0] = block[0];
            data[1] = block[1];
            data[2] = block[2];
            data[3] = block[3];
            data[data.Length - 4] = block[4];
            data[data.Length - 3] = block[5];
            data[data.Length - 2] = block[6];
            data[data.Length - 1] = block[7];

            return data;
        }
        
        //encrypt block
        public static byte[] encryptBlock(string masterkey, byte[] data)
        {
            String roundKey = string.Empty;
            int round = 0;

            string strState = Conversions.byteArrayToString(data);

            byte[] byteState;

            while (round < masterkey.Length)
            {
                roundKey = KeyMgmt.generateRoundKey(masterkey, round);

                byteState = Conversions.stringToByteArray(strState);
                strState = string.Empty;

                foreach (byte b in byteState)
                {
                    strState += Conversions.byteToHex(substitute(b, roundKey));
                }
                strState = scrambleBlock(strState, roundKey[0]);

                byteState = Conversions.stringToByteArray(strState);
                strState = string.Empty;

                foreach (byte b in byteState)
                {
                    strState += Conversions.byteToHex(substitute(b, roundKey));
                }
                strState = scrambleBlock(strState, roundKey[1]);

                round++;
            }
            byteState = Conversions.stringToByteArray(strState);
            return byteState;
        }

        //decryption
        public static byte[] decrypt(byte[] data, string masterkey)
        {
            byte[] block = new byte[8];
            int readByteCounter = data.Length - 8;
            int writeByteCounter = data.Length - 8;
            int blockByteCounter = 0;

            block[0] = data[0];
            block[1] = data[1];
            block[2] = data[2];
            block[3] = data[3];
            block[4] = data[data.Length - 4];
            block[5] = data[data.Length - 3];
            block[6] = data[data.Length - 2];
            block[7] = data[data.Length - 1];

            block = decryptBlock(masterkey, block);

            data[0] = block[0];
            data[1] = block[1];
            data[2] = block[2];
            data[3] = block[3];
            data[data.Length - 4] = block[4];
            data[data.Length - 3] = block[5];
            data[data.Length - 2] = block[6];
            data[data.Length - 1] = block[7];

            while (readByteCounter >= 0)
            {
                while (blockByteCounter < 8)
                {
                    block[blockByteCounter] = data[readByteCounter + blockByteCounter];
                    blockByteCounter++;
                }

                block = decryptBlock(masterkey, block);
                blockByteCounter = 0;

                while (blockByteCounter < 8)
                {
                    data[writeByteCounter] = block[blockByteCounter];
                    blockByteCounter++;
                    writeByteCounter++;
                }
                blockByteCounter = 0;
                readByteCounter -= 4;
                writeByteCounter = readByteCounter;
            }

            return data;
        }

        //decrypt block
        public static byte[] decryptBlock(string masterkey, byte[] data)
        {
            String roundKey = string.Empty;
            int round = masterkey.Length - 1;

            string strState = Conversions.byteArrayToString(data);
            byte[] byteState;

            while (round >= 0)
            {
                roundKey = KeyMgmt.generateRoundKey(masterkey, round);

                strState = unscrambleBlock(strState, roundKey[1]);
                byteState = Conversions.stringToByteArray(strState);
                strState = string.Empty;

                foreach (byte b in byteState)
                {
                    strState += Conversions.byteToHex(revSubstitute(b, roundKey));
                }

                strState = unscrambleBlock(strState, roundKey[0]);
                byteState = Conversions.stringToByteArray(strState);
                strState = string.Empty;

                foreach (byte b in byteState)
                {
                    strState += Conversions.byteToHex(revSubstitute(b, roundKey));
                }

                round--;
            }
            byteState = Conversions.stringToByteArray(strState);
            return byteState;
        }

        //add padding
        public static byte[] addPadding(byte[] data)
        {
            int padding = 0;

            if (data.Length % 8 != 0)
                padding = 8 - (data.Length % 8);

            if (((data.Length + padding) / 8) % 2 != 0)
                padding += 8;

            if (padding > 0)
            {
                Array.Resize<byte>(ref data, data.Length + padding);
                data[data.Length - 1] = (Byte)padding;
            }

            return data;
        }

        //remove padding
        public static byte[] removePadding(byte[] data)
        {
            int padding = data[data.Length - 1];
            if (padding < 16)
            {
                int newSize = data.Length - padding;
                Array.Resize<byte>(ref data, newSize);
            }
            return data;
        }

        //generate substitution box
        public static byte[,] generateSubBox(string roundKey)
        {
            byte[,] subBox = new byte[16, 16];

            byte byteX = Conversions.stringToByteArray(roundKey)[0];

            int y = 0;
            while (y < 16)
            {
                int x = 0;
                while (x < 16)
                {
                    subBox[x, y] = byteX;
                    if (byteX == Byte.MaxValue)
                        byteX = Byte.MinValue;
                    else
                        byteX++;

                    x++;
                }
                y++;
            }
            return subBox;
        }

        //byte substitution
        public static byte substitute(byte b, string roundKey)
        {
            byte[,] subBox = generateSubBox(roundKey);
            
            char b1 = Conversions.byteToHex(b)[0];
            char b2 = Conversions.byteToHex(b)[1];

            char[] hex = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

            int bi1 = Array.IndexOf(hex, b1);
            int bi2 = Array.IndexOf(hex, b2);

            return subBox[bi1,bi2];
        }
        
        //reversed byte substitution
        public static byte revSubstitute(byte b, string roundKey)
        {
            byte[,] subBox = generateSubBox(roundKey);

            int x = 0;
            int y = 0;
            char[] hex = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
            string newHex = "";

            while (y < 16 && newHex == "")
            {
                while (x < 16 && newHex == "")
                {
                    if (subBox[x, y] == b)
                    {
                        newHex = hex[x].ToString() + hex[y].ToString();
                    }
                    x++;
                }
                y++;
                x = 0;
            }

            return Conversions.stringToByteArray(newHex)[0];

        }

        //scramble block
        public static string scrambleBlock(string state, char pattern)
        {
            int[] pattern0 = { 15, 11, 7, 3, 14, 10, 6, 2, 13, 9, 5, 1, 12, 8, 4, 0 };
            int[] pattern1 = { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
            int[] pattern2 = { 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12 };
            int[] pattern3 = { 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3 };
            int[] pattern4 = { 15, 11, 7, 3, 14, 0, 1, 2, 13, 4, 5, 6, 12, 8, 9, 10 };
            int[] pattern5 = { 4, 0, 1, 2, 8, 9, 5, 3, 12, 10, 6, 7, 13, 14, 15, 11 };
            int[] pattern6 = { 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14 };
            int[] pattern7 = { 4, 0, 6, 2, 5, 1, 7, 3, 12, 8, 14, 10, 13, 9, 15, 11 };
            int[] pattern8 = { 12, 8, 4, 0, 13, 9, 5, 1, 14, 10, 6, 2, 15, 11, 7, 3 };
            int[] pattern9 = { 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7, 0, 9, 2, 11 };
            int[] patternA = { 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
            int[] patternB = { 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12 };
            int[] patternC = { 3, 2, 1, 0, 4, 5, 6, 7, 11, 10, 9, 8, 12, 13, 14, 15 };
            int[] patternD = { 11, 10, 13, 12, 15, 14, 9, 8, 7, 6, 1, 0, 3, 2, 5, 4 };
            int[] patternE = { 14, 15, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
            int[] patternF = { 15, 14, 10, 11, 7, 6, 2, 3, 13, 12, 8, 9, 5, 4, 0, 1 };

            int[] p = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
            string alteredState = "";

            switch (pattern)
            {
                case '0':
                    p = pattern0;
                    break;
                case '1':
                    p = pattern1;
                    break;
                case '2':
                    p = pattern2;
                    break;
                case '3':
                    p = pattern3;
                    break;
                case '4':
                    p = pattern4;
                    break;
                case '5':
                    p = pattern5;
                    break;
                case '6':
                    p = pattern6;
                    break;
                case '7':
                    p = pattern7;
                    break;
                case '8':
                    p = pattern8;
                    break;
                case '9':
                    p = pattern9;
                    break;
                case 'a':
                    p = patternA;
                    break;
                case 'b':
                    p = patternB;
                    break;
                case 'c':
                    p = patternC;
                    break;
                case 'd':
                    p = patternD;
                    break;
                case 'e':
                    p = patternE;
                    break;
                case 'f':
                    p = patternF;
                    break;
            }

            foreach (int pos in p)
            {
                alteredState += state[pos];
            }

            return alteredState;
        }
        
        //unscramble block
        public static string unscrambleBlock(string state, char pattern)
        {
            int[] pattern0 = { 15, 11, 7, 3, 14, 10, 6, 2, 13, 9, 5, 1, 12, 8, 4, 0 };
            int[] pattern1 = { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
            int[] pattern2 = { 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12 };
            int[] pattern3 = { 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3 };
            int[] pattern4 = { 5, 6, 7, 3, 9, 10, 11, 2, 13, 14, 15, 1, 12, 8, 4, 0 };
            int[] pattern5 = { 1, 2, 3, 7, 0, 6, 10, 11, 4, 5, 9, 15, 8, 12, 13, 14 };
            int[] pattern6 = { 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14 };
            int[] pattern7 = { 1, 5, 3, 7, 0, 4, 2, 6, 9, 13, 11, 15, 8, 12, 10, 14 };
            int[] pattern8 = { 3, 7, 11, 15, 2, 6, 10, 14, 1, 5, 9, 13, 0, 4, 8, 12 };
            int[] pattern9 = { 12, 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3 };
            int[] patternA = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0 };
            int[] patternB = { 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12 };
            int[] patternC = { 3, 2, 1, 0, 4, 5, 6, 7, 11, 10, 9, 8, 12, 13, 14, 15 };
            int[] patternD = { 11, 10, 13, 12, 15, 14, 9, 8, 7, 6, 1, 0, 3, 2, 5, 4 };
            int[] patternE = { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 0, 1 };
            int[] patternF = { 14, 15, 6, 7, 13, 12, 5, 4, 10, 11, 2, 3, 9, 8, 1, 0 };

            int[] p = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

            string alteredState = "";

            switch (pattern)
            {
                case '0':
                    p = pattern0;
                    break;
                case '1':
                    p = pattern1;
                    break;
                case '2':
                    p = pattern2;
                    break;
                case '3':
                    p = pattern3;
                    break;
                case '4':
                    p = pattern4;
                    break;
                case '5':
                    p = pattern5;
                    break;
                case '6':
                    p = pattern6;
                    break;
                case '7':
                    p = pattern7;
                    break;
                case '8':
                    p = pattern8;
                    break;
                case '9':
                    p = pattern9;
                    break;
                case 'a':
                    p = patternA;
                    break;
                case 'b':
                    p = patternB;
                    break;
                case 'c':
                    p = patternC;
                    break;
                case 'd':
                    p = patternD;
                    break;
                case 'e':
                    p = patternE;
                    break;
                case 'f':
                    p = patternF;
                    break;
            }

            foreach (int pos in p)
            {
                alteredState += state[pos];
            }

            return alteredState;
        }
    }
}