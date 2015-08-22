import java.io.*;

class dec903 {

   static String pass;

   public final static byte[] base64decode(byte[] buffin)
   {
      int i=0;
      byte ret[];
      int even, odd;

      while(i<buffin.length && buffin[i]!='=')
      {
         if (buffin[i]=='=')    
            buffin[i]=0;
         else if (buffin[i]=='/') 
            buffin[i]=63;
         else if (buffin[i]=='+') 
            buffin[i]=62;
         else if (buffin[i]>='0' && buffin[i]<='9')
            buffin[i]=(byte)(buffin[i]-('0'-52));
         else if (buffin[i]>='a' && buffin[i]<='z')
            buffin[i]=(byte)(buffin[i] - ('a' - 26));
         else if (buffin[i]>='A' && buffin[i]<='Z')
            buffin[i]=(byte)(buffin[i]-'A');
         i++;
      }

      ret=new byte[i-buffin.length/4];

      for(even=0,odd=0;odd<(ret.length-2);even+=4,odd+=3)
      {
         ret[odd]=(byte)(((buffin[even]<<2)&255)|((buffin[even+1]>>>4)&3));
         ret[odd+1]=(byte)(((buffin[even+1]<<4)&255)|((buffin[even+2]>>>2)&017));
         ret[odd+2]=(byte)(((buffin[even+2]<<6)&255)|(buffin[even+3]&077));
      }
      if(odd<ret.length)
      {
         ret[odd]=(byte)(((buffin[even]<<2)&255)|((buffin[even+1]>>>4)&3));
      }
      odd++;
      if(odd<ret.length)
      {
         ret[odd]=(byte)(((buffin[even+1]<<4)&255)|((buffin[even+2]>>>2)&017));
      }
      return ret;
   }


   public static void help()
   {
      System.out.println("Usage : dec903 [OPTIONS]");
      System.out.println("\t -h help");
      System.out.println("\t -f file \t\t use this hashes file");
      System.out.println("\t hash \t\t\t including {903}");
   }

   public static void main (String[] arg)
   {
      if(arg.length == 0 || arg[0].equals("-f") && arg.length != 2)
      {
         help();
      }
      else
      {
         if(arg[0].equals("-h"))
         {
            help();
         }
         else
         {
            if(arg[0].equals("-f"))
            {
               try{
                  InputStream ips=new FileInputStream(arg[1]);
                  InputStreamReader ipsr = new InputStreamReader(ips);
                  BufferedReader br=new BufferedReader(ipsr);
                  String line;
                  while((line=br.readLine())!=null)
                  {
                     try{
                        pass = deObfuscatePassword(line);
                     }
                     catch (IOException e)
                     {
                        System.out.println("Malformed passwords detected.");
                     }
                        System.out.println(pass + "      ("+line + ")");
                  }
                  br.close();
               }
               catch (Exception e){
                  System.out.println(e.toString());
               } 
         
            }
            else
            {
               try{
                  pass = deObfuscatePassword(arg[0]);
               }
               catch (IOException e)
               {
                  System.out.println("Malformed passwords detected.");
               }
               System.out.println(pass + "      ("+arg[0] + ")");
            }
         }
      }
   }

   static String deObfuscatePassword(String pw)
    throws IOException
   {
       String cred = null;
       if (pw.charAt(0) == '!')
       {
         cred = pw.substring(1);
       }
       else if (pw.startsWith("{903}"))
       {
         pw=pw.substring(5);
         byte[] currCred = base64decode(pw.getBytes());
         cred = new String(Enc.db(currCred));
       }
       else if (!pw.startsWith("{902}"))
       {
         cred = pw;
       }
       return cred;
   }
}


class Enc 
{
   private static final byte[] _iv = { 76, 51, 115, 13, 122, 48, 113, 93 };
   private static final EncCl _enccl = new EncCl(_iv);

   public static byte[] db(byte[] ba)
   {
       final byte[] _k = { 65, 42, 44, 32, 122, 10, 51, 81, 48, 107 };

       try
       {
         if (ba == null) {
           return null;
         }

         byte[] plainba = new byte[ba.length - 8];
         System.arraycopy(ba, 8, plainba, 0, plainba.length);
         byte[] dbout = null;

         dbout = _enccl.processBuffer(plainba, _k);

         byte[] output = new byte[dbout.length - 8];
         System.arraycopy(dbout, 8, output, 0, dbout.length - 8);
         return output;
       }
       catch (NegativeArraySizeException e)
       {
         System.out.println("Malformed passwords detected. Please check your JAZN Data store.");
       }
      byte[] output = new byte[1];
      return output;
   }


   private static class EncCl
   {
      private byte[] _chainBlock;
      private byte[] _myIV;
      private int[] _ks;

      public EncCl(byte[] iv)
      {
         this._myIV = iv;
         this._chainBlock = new byte[8];
      }

      private void desfunc(int[] block, int[] keys)
      {
         int i = 0;int k = 0;
         final int[] SP1 = { 16843776, 0, 65536, 16843780, 16842756, 66564, 4, 65536, 1024, 16843776, 16843780, 1024, 16778244, 16842756, 16777216, 4, 1028, 16778240, 16778240, 66560, 66560, 16842752, 16842752, 16778244, 65540, 16777220, 16777220, 65540, 0, 1028, 66564, 16777216, 65536, 16843780, 4, 16842752, 16843776, 16777216, 16777216, 1024, 16842756, 65536, 66560, 16777220, 1024, 4, 16778244, 66564, 16843780, 65540, 16842752, 16778244, 16777220, 1028, 66564, 16843776, 1028, 16778240, 16778240, 0, 65540, 66560, 0, 16842756 };
         final int[] SP2 = { -2146402272, -2147450880, 32768, 1081376, 1048576, 32, -2146435040, -2147450848, -2147483616, -2146402272, -2146402304, Integer.MIN_VALUE, -2147450880, 1048576, 32, -2146435040, 1081344, 1048608, -2147450848, 0, Integer.MIN_VALUE, 32768, 1081376, -2146435072, 1048608, -2147483616, 0, 1081344, 32800, -2146402304, -2146435072, 32800, 0, 1081376, -2146435040, 1048576, -2147450848, -2146435072, -2146402304, 32768, -2146435072, -2147450880, 32, -2146402272, 1081376, 32, 32768, Integer.MIN_VALUE, 32800, -2146402304, 1048576, -2147483616, 1048608, -2147450848, -2147483616, 1048608, 1081344, 0, -2147450880, 32800, Integer.MIN_VALUE, -2146435040, -2146402272, 1081344 };
         final int[] SP3 = { 520, 134349312, 0, 134348808, 134218240, 0, 131592, 134218240, 131080, 134217736, 134217736, 131072, 134349320, 131080, 134348800, 520, 134217728, 8, 134349312, 512, 131584, 134348800, 134348808, 131592, 134218248, 131584, 131072, 134218248, 8, 134349320, 512, 134217728, 134349312, 134217728, 131080, 520, 131072, 134349312, 134218240, 0, 512, 131080, 134349320, 134218240, 134217736, 512, 0, 134348808, 134218248, 131072, 134217728, 134349320, 8, 131592, 131584, 134217736, 134348800, 134218248, 520, 134348800, 131592, 8, 134348808, 131584 };
         final int[] SP4 = { 8396801, 8321, 8321, 128, 8396928, 8388737, 8388609, 8193, 0, 8396800, 8396800, 8396929, 129, 0, 8388736, 8388609, 1, 8192, 8388608, 8396801, 128, 8388608, 8193, 8320, 8388737, 1, 8320, 8388736, 8192, 8396928, 8396929, 129, 8388736, 8388609, 8396800, 8396929, 129, 0, 0, 8396800, 8320, 8388736, 8388737, 1, 8396801, 8321, 8321, 128, 8396929, 129, 1, 8192, 8388609, 8193, 8396928, 8388737, 8193, 8320, 8388608, 8396801, 128, 8388608, 8192, 8396928 };
         final int[] SP5 = { 256, 34078976, 34078720, 1107296512, 524288, 256, 1073741824, 34078720, 1074266368, 524288, 33554688, 1074266368, 1107296512, 1107820544, 524544, 1073741824, 33554432, 1074266112, 1074266112, 0, 1073742080, 1107820800, 1107820800, 33554688, 1107820544, 1073742080, 0, 1107296256, 34078976, 33554432, 1107296256, 524544, 524288, 1107296512, 256, 33554432, 1073741824, 34078720, 1107296512, 1074266368, 33554688, 1073741824, 1107820544, 34078976, 1074266368, 256, 33554432, 1107820544, 1107820800, 524544, 1107296256, 1107820800, 34078720, 0, 1074266112, 1107296256, 524544, 33554688, 1073742080, 524288, 0, 1074266112, 34078976, 1073742080 };
         final int[] SP6 = { 536870928, 541065216, 16384, 541081616, 541065216, 16, 541081616, 4194304, 536887296, 4210704, 4194304, 536870928, 4194320, 536887296, 536870912, 16400, 0, 4194320, 536887312, 16384, 4210688, 536887312, 16, 541065232, 541065232, 0, 4210704, 541081600, 16400, 4210688, 541081600, 536870912, 536887296, 16, 541065232, 4210688, 541081616, 4194304, 16400, 536870928, 4194304, 536887296, 536870912, 16400, 536870928, 541081616, 4210688, 541065216, 4210704, 541081600, 0, 541065232, 16, 16384, 541065216, 4210704, 16384, 4194320, 536887312, 0, 541081600, 536870912, 4194320, 536887312 };
         final int[] SP7 = { 2097152, 69206018, 67110914, 0, 2048, 67110914, 2099202, 69208064, 69208066, 2097152, 0, 67108866, 2, 67108864, 69206018, 2050, 67110912, 2099202, 2097154, 67110912, 67108866, 69206016, 69208064, 2097154, 69206016, 2048, 2050, 69208066, 2099200, 2, 67108864, 2099200, 67108864, 2099200, 2097152, 67110914, 67110914, 69206018, 69206018, 2, 2097154, 67108864, 67110912, 2097152, 69208064, 2050, 2099202, 69208064, 2050, 67108866, 69208066, 69206016, 2099200, 0, 2, 69208066, 0, 2099202, 69206016, 2048, 67108866, 67110912, 2048, 2097154 };
         final int[] SP8 = { 268439616, 4096, 262144, 268701760, 268435456, 268439616, 64, 268435456, 262208, 268697600, 268701760, 266240, 268701696, 266304, 4096, 64, 268697600, 268435520, 268439552, 4160, 266240, 262208, 268697664, 268701696, 4160, 0, 0, 268697664, 268435520, 268439552, 266304, 262144, 266304, 262144, 268701696, 4096, 64, 268697664, 4096, 266304, 268439552, 64, 268435520, 268697600, 268697664, 268435456, 262144, 268439616, 0, 268701760, 262208, 268435520, 268697600, 268439552, 268439616, 0, 268701760, 266240, 266240, 4160, 4160, 262208, 268435456, 268701696 };
 
         int leftt = block[0];
         int right = block[1];
         int work = (leftt >>> 4 ^ right) & 0xF0F0F0F;
         right ^= work;
         leftt ^= work << 4;
         work = (leftt >>> 16 ^ right) & 0xFFFF;
         right ^= work;
         leftt ^= work << 16;
         work = (right >>> 2 ^ leftt) & 0x33333333;
         leftt ^= work;
         right ^= work << 2;
         work = (right >>> 8 ^ leftt) & 0xFF00FF;
         leftt ^= work;
         right ^= work << 8;
         right = (right << 1 | right >>> 31 & 0x1) & 0xFFFFFFFF;
         work = (leftt ^ right) & 0xAAAAAAAA;
         leftt ^= work;
         right ^= work;
         leftt = (leftt << 1 | leftt >>> 31 & 0x1) & 0xFFFFFFFF;

         for (int round = 0; round < 8; round++)
         {
           work = right << 28 | right >>> 4;
           long tempkeys = 0L;
           tempkeys = keys[k] | 0x0;
           work ^= keys[k];
           k++;
           int fval = SP7[(work & 0x3F)];
           fval |= SP5[(work >>> 8 & 0x3F)];
           fval |= SP3[(work >>> 16 & 0x3F)];
           fval |= SP1[(work >>> 24 & 0x3F)];
           
           work = right ^ keys[k];
           k++;
           fval |= SP8[(work & 0x3F)];
           fval |= SP6[(work >>> 8 & 0x3F)];
           fval |= SP4[(work >>> 16 & 0x3F)];
           fval |= SP2[(work >>> 24 & 0x3F)];
           leftt ^= fval;
           
           work = leftt << 28 | leftt >>> 4;
           work ^= keys[k];
           k++;
           fval = SP7[(work & 0x3F)];
           fval |= SP5[(work >>> 8 & 0x3F)];
           fval |= SP3[(work >>> 16 & 0x3F)];
           fval |= SP1[(work >>> 24 & 0x3F)];
           work = leftt ^ keys[k];
           k++;
           fval |= SP8[(work & 0x3F)];
           fval |= SP6[(work >>> 8 & 0x3F)];
           fval |= SP4[(work >>> 16 & 0x3F)];
           fval |= SP2[(work >>> 24 & 0x3F)];
           right ^= fval;

         }
         right = right << 31 | right >>> 1;
         work = (leftt ^ right) & 0xAAAAAAAA;
         leftt ^= work;
         right ^= work;
         leftt = leftt << 31 | leftt >>> 1;
         work = (leftt >>> 8 ^ right) & 0xFF00FF;
         right ^= work;
         leftt ^= work << 8;
         work = (leftt >>> 2 ^ right) & 0x33333333;
         right ^= work;
         leftt ^= work << 2;
         work = (right >>> 16 ^ leftt) & 0xFFFF;
         leftt ^= work;
         right ^= work << 16;
         work = (right >>> 4 ^ leftt) & 0xF0F0F0F;
         leftt ^= work;
         right ^= work << 4;
         
         block[0] = right;
         block[1] = leftt;
      }

      private void bytesToInts(byte[] outof, int[] into)
      {
         int i = 0;
         into[0] = ((outof[i] & 0xFF) << 24);
         i++;
         into[0] |= (outof[i] & 0xFF) << 16;
         i++;
         into[0] |= (outof[i] & 0xFF) << 8;
         i++;
         into[0] |= outof[i] & 0xFF;
         i++;
         into[1] = ((outof[i] & 0xFF) << 24);
         i++;
         into[1] |= (outof[i] & 0xFF) << 16;
         i++;
         into[1] |= (outof[i] & 0xFF) << 8;
         i++;
         into[1] |= outof[i] & 0xFF;
      }

      private void intsToBytes(int[] outof, byte[] into)
      {
         int i = 0;
         into[i] = ((byte)(outof[0] >> 24 & 0xFF));
         i++;
         into[i] = ((byte)(outof[0] >> 16 & 0xFF));
         i++;
         into[i] = ((byte)(outof[0] >> 8 & 0xFF));
         i++;
         into[i] = ((byte)(outof[0] & 0xFF));
         i++;
         into[i] = ((byte)(outof[1] >> 24 & 0xFF));
         i++;
         into[i] = ((byte)(outof[1] >> 16 & 0xFF));
         i++;
         into[i] = ((byte)(outof[1] >> 8 & 0xFF));
         i++;
         into[i] = ((byte)(outof[1] & 0xFF));
      }

      private void des_blk(byte[] data, int[] ks)
      {
         int[] work = new int[2];
         
         bytesToInts(data, work);
         desfunc(work, ks);
         intsToBytes(work, data);
      }

      private void decryptBlk(byte[] buffer, byte[] output)
      {
         System.arraycopy(buffer, 0, output, 0, 8);
         des_blk(output, this._ks);
      }


      protected static void byteXOR(byte[] in1, byte[] in2, byte[] output, int offset)
      {
         for (int i = 0; i < 8; i++) {
           output[(i + offset)] = ((byte)(in1[i] ^ in2[i]));
         }
      }


      private void decryptBlock(byte[] input, byte[] out, int outOff)
      {
         byte[] tempBuf = new byte[8];
         decryptBlk(input, tempBuf);
 
         byteXOR(this._chainBlock, tempBuf, out, outOff);
         System.arraycopy(input, 0, this._chainBlock, 0, 8); 
      }

      private int[] cookey(int[] raw1)
      {
         int[] cook = new int[32];
         int[] raw0 = raw1;
         int i = 0;int r0 = 0;int r1 = 0;

         for (int c = 0; i < 16; r1++)
         {
           r0 = r1++;
           cook[c] = ((raw0[r0] & 0xFC0000) << 6);
           cook[c] |= (raw0[r0] & 0xFC0) << 10;
           cook[c] |= (raw1[r1] & 0xFC0000) >> 10;
           cook[c] |= (raw1[r1] & 0xFC0) >> 6;
           c++;
           cook[c] = ((raw0[r0] & 0x3F000) << 12);
           cook[c] |= (raw0[r0] & 0x3F) << 16;
           cook[c] |= (raw1[r1] & 0x3F000) >> 4;
           cook[c] |= raw1[r1] & 0x3F;
           c++;i++;
         }
         return cook;
      }

      private int[] generateKey(byte[] deskey)
      {
         byte[] pc1m = new byte[56];
         byte[] pcr = new byte[56];
         int[] kn = new int[32];
         byte[] PC1 = { 56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3 };
         byte[] bytebit = { Byte.MIN_VALUE, 64, 32, 16, 8, 4, 2, 1 }; // MIN_VALUE : -128
         int[] totrot = { 1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28 };
         byte[] PC2 = { 13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31 };
         int[] bigbyte = { 8388608, 4194304, 2097152, 1048576, 524288, 262144, 131072, 65536, 32768, 16384, 8192, 4096, 2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1 };
 
         int j; 

         for (j = 0; j < 56; j++)
         {
           int l = PC1[j];
           int m = l & 0x7;
           pc1m[j] = ((byte)((deskey[(l >>> 3)] & bytebit[m]) != 0 ? 1 : 0));
         }
         for (int i = 0; i < 16; i++)
         {
           int m;
           m = 15 - i << 1;

           int n = m + 1;
           kn[m] = (kn[n] = 0);

           for (j = 0; j < 28; j++)
           {
             int l = j + totrot[i];
             if (l < 28) {
               pcr[j] = pc1m[l];
             } else {
               pcr[j] = pc1m[(l - 28)];
             }
           }
           for (j = 28; j < 56; j++)
           {
             int l = j + totrot[i];
             if (l < 56) {
               pcr[j] = pc1m[l];
             } else {
               pcr[j] = pc1m[(l - 28)];
             }
           }
           for (j = 0; j < 24; j++)
           {
             if (pcr[PC2[j]] != 0) {
               kn[m] |= bigbyte[j];
             }
             if (pcr[PC2[(j + 24)]] != 0) {
               kn[n] |= bigbyte[j];
             }
           }
         }


         return cookey(kn);
      }


      private static int getEncryptedLen(int plainTextLen)
      {
         if (plainTextLen % 8 == 0) {
           return plainTextLen;
         }
         return (plainTextLen / 8 + 1) * 8;
      }

      protected byte[] processBuffer(byte[] input, byte[] key)
      {

         if (key.length < 8) {
            return "Error".getBytes();
         }
         int len = 0;
         byte[] encBuf = new byte[getEncryptedLen(input.length)];
         byte[] ebyte = new byte[8];

         this._ks = generateKey(key);
         System.arraycopy(this._myIV, 0, this._chainBlock, 0, 8); 

         if (input.length % 8 != 0) {
            return "Error".getBytes();
         }
         for (len = 0; len < input.length; len += 8)
         {
            System.arraycopy(input, len, ebyte, 0, 8);
            decryptBlock(ebyte, encBuf, len);
         }
         int zeroes = 0;
         len = input.length;
         while (encBuf[(--len)] == 0) {
            zeroes++;
         }
         if (zeroes >= 8) {
            return "Error".getBytes();
         }
         byte[] decBuf = new byte[input.length - zeroes];
         System.arraycopy(encBuf, 0, decBuf, 0, decBuf.length);
         return decBuf;
      }
   }
}
