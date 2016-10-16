package pk.muneebahmad.aes.lib.crypto;

import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author ¶ muneebahmad ¶ (http://1-dot-muneeb-ahmad.appspot.com)
 *         <p/>
 *         IDE | IntelliJ Idea | Android Studio | NetBeans IDE (http://www.netbeans.org)
 *         | Eclipse (http://eclipse.org)
 *         <p/>
 *         For all entities this program is free software; you can redistribute
 *         it and/or modify it under the terms of the 'MyGdxEngine | muneeb-ahmad@MyKENGINE' license with
 *         the additional provision that 'MyGdxEngine' must be credited in a manner
 *         that can be be observed by end users, for example, in the credits or during
 *         start up. (please find MyGdxEngine logo in sdk's logo folder)
 *         <p/>
 *         Permission is hereby granted, free of charge, to any person obtaining a copy
 *         of this software and associated documentation files (the "Software"), to deal
 *         in the Software without restriction, including without limitation the rights
 *         to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *         copies of the Software, and to permit persons to whom the Software is
 *         furnished to do so, subject to the following conditions:
 *         <p/>
 *         The above copyright notice and this permission notice shall be included in
 *         all copies or substantial portions of the Software.
 *         <p/>
 *         The following source - code IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *         IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *         FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *         AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *         LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *         OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *         THE SOFTWARE.
 */
public class AES2 {

    public static final String BASE_ALGORITHM = "AES";
    public static final String BASE_ENCODING = "UTF-8";
    public static final String TRANSFORM_ECB_NO_PADDING = "AES/ECB/NoPadding";
    public static final String TRANSFORM_ECB_PKCS5PADDING = "AES/ECB/PKCS5Padding";
    public static final String TRANSFORM_CBC_NO_PADDING = "AES/CBC/NoPadding";
    public static final String TRANSFORM_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding";
    private static final String TAG_ECB_ECRYPT = "ECB ENCRYPT";
    private static final String TAG_ECB_DECRYPT = "ECB DECRYPT";
    private static final String TAG_CBC_ENCRYPT = "CBC ENCRYPT";
    private static final String TAG_CBC_DECRYPT = "CBC DECRYPT";

    /**
     *
     * @param key {@link java.lang.String}
     * @param value {@link java.lang.String}
     * @param transform Select one {@link java.lang.String} form above
     * @return ECB encrypted {@link java.lang.String}
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String encryptECB(String key, String value, String transform) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(BASE_ENCODING), BASE_ALGORITHM);
        Cipher cipher = Cipher.getInstance(transform);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encrypted = cipher.doFinal(value.getBytes());
        byte[] encoded = Base64.encode(encrypted, Base64.DEFAULT);
        System.out.println("ENCRYPTED: " + new String(encoded));
        return new String(encoded);
    }

    /**
     *
     * @param key {@link java.lang.String}
     * @param encrypted {@link java.lang.String}
     * @param transform Select one {@link java.lang.String} form above
     * @return ECB decrypted {@link java.lang.String}
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String decryptECB(String key, String encrypted, String transform) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(BASE_ENCODING), BASE_ALGORITHM);
        Cipher cipher = Cipher.getInstance(transform);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] original = cipher.doFinal(Base64.decode(encrypted, Base64.DEFAULT));
        System.out.println("DECRYPTED: " + new String(original));
        return new String(original);
    }

    /**
     *
     * @param key {@link java.lang.String}
     * @param initVector {@link java.lang.String}
     * @param value {@link java.lang.String}
     * @param transform Select a {@link java.lang.String} from above.
     * @return CBC encrypted {@link java.lang.String}
     */
    public static String encryptCBC(String key, String initVector, String value, String transform) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(BASE_ENCODING));
            SecretKeySpec sKeySpec = new SecretKeySpec(key.getBytes(BASE_ENCODING), BASE_ALGORITHM);
            Cipher cipher = Cipher.getInstance(transform);
            cipher.init(Cipher.ENCRYPT_MODE, sKeySpec, iv);
            byte[] encrypted = cipher.doFinal(value.getBytes());
            String encoded = Base64.encodeToString(encrypted, Base64.DEFAULT);
            System.out.println("CBC ENCRYPTED: " + encoded);
            return encoded;
        } catch (Exception e) {
            Log.e(TAG_CBC_ENCRYPT, "Exception: " + e.toString());
            e.printStackTrace();
        }
        return null;
    }

    /**
     *
     * @param key {@link java.lang.String}
     * @param initVector {@link java.lang.String}
     * @param encrypted {@link java.lang.String}
     * @param transform Select one {@link java.lang.String} form above
     * @return CBC decrypted {@link java.lang.String}
     */
    public static String decryptCBC(String key, String initVector, String encrypted, String transform) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes(BASE_ENCODING));
            SecretKeySpec sKeySpec = new SecretKeySpec(key.getBytes(BASE_ENCODING), BASE_ALGORITHM);
            Cipher cipher = Cipher.getInstance(transform);
            cipher.init(Cipher.DECRYPT_MODE, sKeySpec, iv);
            byte[] decode = Base64.decode(encrypted, Base64.DEFAULT);
            byte[] original = cipher.doFinal(decode);
            String result = new String(original);
            System.out.println("CBC DECRYPTED: " + result);
            return result;
        } catch (Exception e) {
            Log.e(TAG_CBC_DECRYPT, "Exception: " + e.toString());
            e.printStackTrace();
        }
        return null;
    }

}/** end class. */
