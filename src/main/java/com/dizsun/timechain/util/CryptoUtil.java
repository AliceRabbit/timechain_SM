package com.dizsun.timechain.util;
import com.dizsun.timechain.sm.SM3Digest;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;


public class CryptoUtil {
    private CryptoUtil() {
    }
    public static String getSHA256(String str){
        MessageDigest messageDigest;
        String encodeStr="";
        try{
            messageDigest=MessageDigest.getInstance("SHA-256");
            messageDigest.update(str.getBytes(StandardCharsets.UTF_8));
            encodeStr=byte2Hex(messageDigest.digest());
        }catch (Exception e){
            System.out.println("getSHA256 is error"+e.getMessage());
        }
        return encodeStr;
    }

    public static String getSM3(String str){
        SM3Digest sm3 = new SM3Digest();
        String encodeStr="";
        try{
            byte[] md = new byte[32];
            byte[] msg1 = str.getBytes(StandardCharsets.UTF_8);
            sm3.update(msg1, 0, msg1.length);
            sm3.doFinal(md, 0);
            encodeStr = new String(Hex.encode(md));
        }catch (Exception e){
            System.out.println("getSM3 is error"+e.getMessage());
        }
        return encodeStr;
    }

    /**
     * 将字节码转化为十六进制
     * @param bytes
     * @return
     */
    private static String byte2Hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        String temp;
        for (int i = 0; i < bytes.length; i++) {
            temp=Integer.toHexString(bytes[i]&0xFF);
            if(temp.length()==1){
                builder.append("0");
            }
            builder.append(temp);
        }
        return builder.toString();
    }
}
