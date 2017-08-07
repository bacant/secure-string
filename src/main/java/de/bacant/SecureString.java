package de.bacant;

import com.sanguinecomputing.securestr.Long2Char;

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
import java.util.Base64;
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
    private final int length;
    private int _hashCode;
    private boolean hash;



    private static final ObjectStreamField[] serialPersistentFields = {};


    public SecureString() throws GeneralSecurityException {
        this(new char[0]);
    }

    public SecureString(char[] chars) throws GeneralSecurityException {
        new Random(System.currentTimeMillis()).nextBytes(salt);
        this.length = chars.length;
        this.bytes = encrypt(SecureUtils.charToByte(chars));
    }

    /**
     * Only for serialization
     * @param bytes
     * @param salt
     */
    private SecureString(byte[] bytes, byte[] salt, int length){
        this.bytes = bytes;
        System.arraycopy(salt, 0, this.salt, 0 ,8);
        this.length = length;
    }


    @Override
    public int length() {
        return length;
    }

    @Override
    public char charAt(int index) {
        return getValueInternal()[index];
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
     * Get the content of this string as char[]
     * @return
     * @throws GeneralSecurityException
     */
    public char[] getValue() throws GeneralSecurityException {
        return SecureUtils.byteToChar(decrypt());
    }



    private byte[] encrypt(byte[] cleartext) throws GeneralSecurityException {

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(getMetaPassword()));
        Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, 20));
        try {
            return pbeCipher.doFinal(cleartext);
        } finally {
            SecureUtils.clear(cleartext);
        }
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
            SecureUtils.clear(v1);
            return -1;
        }

        int k = 0;
        try {
            while (k < lim) {
                char c1 = v1[k];
                char c2 = v2[k];
                if (c1 != c2) {
                    return c1 - c2;
                }
                k++;
            }
            return len1 - len2;
        } finally {
            SecureUtils.clear(v1);
            SecureUtils.clear(v2);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if(this == obj){
            return true;
        }
        if (obj instanceof SecureString){
            SecureString other = (SecureString) obj;
            char[] otherVal = null;
            char[] thisVal = null;
            try {
                otherVal =other.getValue();
                thisVal = this.getValue();
                return Arrays.equals(otherVal, thisVal);
            } catch (GeneralSecurityException e) {
                // do nothing
            } finally {
                if (otherVal != null)
                    SecureUtils.clear(otherVal);
                if (otherVal != null)
                    SecureUtils.clear(thisVal);
            }
        }
        return false;
    }

    @Override
    public int hashCode() {
        if (!hash){
            char[] value = getValueInternal();
            _hashCode = Arrays.hashCode(value);
            SecureUtils.clear(value);
        }
        return _hashCode;
    }

    @Override
    public String toString() {
        return SecureUtils.bytesToHex(bytes);
    }

    public boolean isEmpty() {
        return length == 0;
    }

    public char[] toCharArray() {
        return getValueInternal();
    }
/*
    public void clear(){
        SecureUtils.clear(bytes);
        SecureUtils.clear(salt);
    }
*/
    private char[] getValueInternal(){
        try {
            return getValue();
        } catch (GeneralSecurityException e) {
        }
        return null;
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


    @Override
    public SecureString clone() throws CloneNotSupportedException {
        byte[] bytes = new byte[this.bytes.length];
        byte[] salt = new byte[8];
        System.arraycopy(this.bytes, 0, bytes, 0, bytes.length);
        System.arraycopy(this.salt, 0, salt, 0, salt.length);
        SecureString clone = new SecureString(bytes, salt, length);
        if (clone.equals(this)) {
            return clone;
        }
        throw new CloneNotSupportedException();
    }


    Object writeReplace() throws ObjectStreamException {
        return new Serialized(this);
    }

    private static final class Serialized implements Serializable {


        private static final long serialVersionUID = -2247778550767786666L;


        private byte[] bytes;
        private byte[] salt;
        private int length;

        private static final ObjectStreamField[] serialPersistentFields = {
                new ObjectStreamField("bytes", byte[].class),
                new ObjectStreamField("salt", byte[].class),
                new ObjectStreamField("length", int.class)
        };


        private void writeObject(java.io.ObjectOutputStream stream)
                throws IOException {
            System.out.println("writeObject");
            ObjectOutputStream.PutField f = stream.putFields();
            f.put("bytes", bytes);
            f.put("salt", salt);
            f.put("length", length);
            stream.close();
        }

        private void readObject(java.io.ObjectInputStream stream)
                throws Throwable {
            ObjectInputStream.GetField f= stream.readFields();
            bytes = (byte[]) f.get("bytes", new byte[0]);
            salt = (byte[]) f.get("salt", new byte[8]);
            length = f.get("length", 0);
        }

        private Serialized(SecureString original) {
            this.bytes = original.bytes;
            this.salt = original.salt;
            this.length = original.length;
        }

        Object readResolve() throws ObjectStreamException {
            return new SecureString(bytes, salt, length);
        }
    }
}
