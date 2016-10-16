package pk.muneebahmad.aes.lib.crypto;

import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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

public class AES {

    private static SecretKeySpec secretKeySpec;
    private static byte[] key;
    private static String decryptedString;
    private static String encryptedString;

    public static final String CIPHER_TRANSFORMATION = "AES/ECB/PKCS5PADDING";
    public static final String TAG = "AES TEST APP";

    /**
     *
     * @param newKey {@link java.lang.String}
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     */
    public static void setKey(String newKey) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        key = newKey.getBytes("UTF-8");
        System.out.println("KEY LENGTH: " + key.length);
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        //use only first 128 bit
        key = Arrays.copyOf(key, 16);
        System.out.println("KEY LENGTH: " + key.length);
        System.out.println("KEY: " + new String(key, "UTF-8"));
        secretKeySpec = new SecretKeySpec(key, "AES");
    }

    /**
     *
     * @return decrypted {@link java.lang.String}
     */
    public static String getDecryptedString() {
        return AES.decryptedString;
    }

    /**
     *
     * @param decryptedString as a {@link java.lang.String}
     */
    public static void setDecryptedString(String decryptedString) {
        AES.decryptedString = decryptedString;
    }

    /**
     *
     * @return encrypted {@link java.lang.String}
     */
    public static String getEncryptedString() {
        return AES.encryptedString;
    }

    /**
     *
     * @param encryptedString as a {@link java.lang.String}
     */
    public static void setEncryptedString(String encryptedString) {
        AES.encryptedString = encryptedString;
    }

    /**
     *
     * @param strToEncrypt aa a {@link java.lang.String}
     * @return encrypted {@link java.lang.String}, mostly null
     */
    public static String encrypt(String strToEncrypt) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            setEncryptedString(Base64.encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")), Base64.DEFAULT));
        } catch (NoSuchPaddingException nsae) {
            Log.e(TAG, "Padding error while encrypting string: " + nsae.toString());
            nsae.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Algorithm error while encrypting: " + e.toString());
            e.printStackTrace();
        } catch (InvalidKeyException ie) {
            Log.e(TAG, "Invalid key error while encrypting: " + ie.toString());
            ie.printStackTrace();
        } catch (UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException ue) {
            Log.e(TAG, "Unsupported or Bad padding or Illegal Block Size error: "  + ue.toString());
            ue.printStackTrace();
        }
        return null;
    }

    /**
     *
     * @param strToDecrypt as a {@link java.lang.String}
     * @return {@link java.lang.String}, mostly null
     */
    public static String decrypt(String strToDecrypt) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            setDecryptedString(new String(cipher.doFinal(Base64.decode(strToDecrypt, Base64.DEFAULT))));
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            Log.e(TAG, "Error while decrypting: " + e.toString());
            e.printStackTrace();
        }
        return null;
    }

}/** end class. */
