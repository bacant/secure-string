package de.bacant;

import com.sanguinecomputing.securestr.Long2Char;
import sun.misc.Unsafe;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Random;
import java.util.ServiceLoader;
/**
 * Use this class for long-term storage of sensitive strings
 * like passwords. The idea is to make it hard for an intruder
 * capable of reading this application's memory to figure out
 * the content of this string.
 *
 * Check out https://sourceforge.net/projects/javasecurestr/ for documentation
 *
 * @author igor urisman
 * @author bacant
 */

public class SecureString implements Serializable, Comparable<SecureString>, CharSequence, Cloneable{

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();


    private final byte[] bytes;
    private final byte[] salt = new byte[8];

    public SecureString(char[] chars) throws GeneralSecurityException {
        new Random(System.currentTimeMillis()).nextBytes(salt);
        this.bytes = encrypt(charToByte(chars));
    }

    public SecureString(InputStream inputStream) throws IOException {
        java.io.ObjectInputStream objectInputStream = new java.io.ObjectInputStream(inputStream);
        byte[] b = null;
        byte[] s = null;
        try {
            b = (byte[]) objectInputStream.readObject();
            s = (byte[]) objectInputStream.readObject();
            System.arraycopy(s, 0, salt, 0 ,8);
        } catch (ClassNotFoundException e) {
        }
        bytes =b;
    }

    @Override
    public int length() {
        try {
            return getValue().length;
        } catch (GeneralSecurityException e) {

        }
        return -1;
    }

    @Override
    public char charAt(int index) {
        try {
            return getValue()[index];
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        throw new IndexOutOfBoundsException();
    }

    @Override
    public CharSequence subSequence(int start, int end) {
        final char[] dst = new char[end];
        try {
            System.arraycopy(getValue(), start,dst, 0, end);
            return new SecureString(dst);
        } catch (GeneralSecurityException e) {
        }
        throw new IndexOutOfBoundsException();
    }

    private static char[] getMetaPassword() {
        ServiceLoader<ApplicationKeyStore> service = ServiceLoader.load(ApplicationKeyStore.class);
        return service.iterator().next().getGlobalApplicationPassword();
    }


    private byte[] decrypt() throws GeneralSecurityException {

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(getMetaPassword()));
        Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(salt, 20));
        return pbeCipher.doFinal(bytes);
    }


    /**
     * Convert char array to byte array without charset interpretation.
     * @param chars
     * @return
     */
    private static byte[] charToByte(char[] chars) {
        byte[] result = new byte[chars.length*2];
        for (int i=0; i < chars.length; i++) {
            result[i*2] = (byte) (chars[i] >> 8);
            result[i*2+1] = (byte) chars[i];
        }
        return result;
    }

    /**
     * Convert byte array to char array without charset interpretation.
     * @param bytes
     * @return
     */
    private static char[] byteToChar(byte[] bytes) {
        char[] result = new char[bytes.length/2];
        for (int i=0; i < result.length; i++) {
            result[i] = (char) ((bytes[i*2] << 8) + bytes[i*2+1]);
        }
        return result;
    }

    /**
     * Get the content of this string as char[]
     * @return
     * @throws GeneralSecurityException
     */
    public char[] getValue() throws GeneralSecurityException {
        return byteToChar(decrypt());
    }



    private byte[] encrypt(byte[] cleartext) throws GeneralSecurityException {

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(getMetaPassword()));
        Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, 20));
        return pbeCipher.doFinal(cleartext);
    }


    @Override
    public int compareTo(SecureString anotherString) {
        int len1 = length();
        int len2 = anotherString.length();
        int lim = Math.min(len1, len2);
        char v1[];
        try {
            v1 = getValue();
        } catch (GeneralSecurityException e) {
            return 1;
        }
        char v2[];
        try {
            v2 = anotherString.getValue();
        } catch (GeneralSecurityException e) {
            return -1;
        }

        int k = 0;
        while (k < lim) {
            char c1 = v1[k];
            char c2 = v2[k];
            if (c1 != c2) {
                return c1 - c2;
            }
            k++;
        }
        return len1 - len2;
    }

    @Override
    public boolean equals(Object obj) {
        if(this == obj){
            return true;
        }
        if (obj instanceof SecureString){
            SecureString other = (SecureString) obj;
            try {
                return Arrays.equals(other.getValue(), this.getValue());
            } catch (GeneralSecurityException e) {
                // do nothing
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(chars().toArray());
    }

    @Override
    public String toString() {
        return bytesToHex(bytes);
    }


    public int indexOf(char ch, int fromIndex) {
        try {
            return Arrays.binarySearch(getValue(), fromIndex, length(), ch);
        } catch (GeneralSecurityException e) {
        }
        return -1;
    }
    public int indexOf(char ch) {
        return indexOf(ch, 0);
    }

    public int indexOf(String ch) {
        return indexOf(ch.charAt(0), 0);
    }
    public int indexOf(String ch, int fromIndex) {
        return indexOf(ch.charAt(0), fromIndex);
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }


    public String toClearText(){
        try {
            return new String(getValue());
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public SecureString clone() throws CloneNotSupportedException {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            writeObject(new java.io.ObjectOutputStream(byteArrayOutputStream));
            byteArrayOutputStream.close();
            System.out.println(byteArrayOutputStream.toByteArray().length);
            SecureString n = new SecureString(new char[0]);
            n.readObject(new java.io.ObjectInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray())));
            return n;
        } catch (Throwable e) {
        }
        throw new CloneNotSupportedException();
    }


    public OutputStream outputStream() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            writeObject(new java.io.ObjectOutputStream(byteArrayOutputStream));
            return byteArrayOutputStream;
        } finally {
            byteArrayOutputStream.close();
        }
    }

    private void writeObject(java.io.ObjectOutputStream stream)
            throws IOException {
        System.out.println("writeObject");
        stream.writeObject(bytes);
        stream.writeObject(salt);
    }

    private void readObject(java.io.ObjectInputStream stream)
            throws Throwable {
        Unsafe unsafe = getUnsafe();
        System.out.println("unsafe");
        unsafe.putObject(this,unsafe.objectFieldOffset(this.getClass().getDeclaredField("bytes")), stream.readObject());
        unsafe.putObject(this,unsafe.objectFieldOffset(this.getClass().getDeclaredField("salt")), stream.readObject());
    }


    @SuppressWarnings("restriction")
    private static Unsafe getUnsafe() throws Throwable{
        Field singleoneInstanceField = Unsafe.class.getDeclaredField("theUnsafe");
        singleoneInstanceField.setAccessible(true);
        return (Unsafe) singleoneInstanceField.get(null);

    }

}
