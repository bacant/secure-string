package de.bacant;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class SecureUtils {

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();


    private SecureUtils() {
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Convert char array to byte array without charset interpretation.
     *
     * @param chars
     * @return
     */
    public static byte[] charToByte(char[] chars) {
        byte[] result = new byte[chars.length * 2];
        for (int i = 0; i < chars.length; i++) {
            result[i * 2] = (byte) (chars[i] >> 8);
            result[i * 2 + 1] = (byte) chars[i];
        }
        return result;
    }

    /**
     * Convert byte array to char array without charset interpretation.
     *
     * @param bytes
     * @return
     */
    public static char[] byteToChar(byte[] bytes) {
        char[] result = new char[bytes.length / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (char) ((bytes[i * 2] << 8) + bytes[i * 2 + 1]);
        }
        return result;
    }

    public static String createSha256Hash(byte[] bytes) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        byte[] encodedHash = digest.digest(bytes);
        return bytesToHex(encodedHash);
    }

    public static boolean verifySha256Hash(byte[] bytes, String hash){
        return createSha256Hash(bytes).equals(hash);
    }


    public static void clear(char[] chars){
        if (chars !=null){
            Arrays.fill(chars, (char)0);
        }
    }


    public static void clear(byte[] bytes){
        if (bytes !=null){
            Arrays.fill(bytes, (byte) 0);
        }
    }


}
