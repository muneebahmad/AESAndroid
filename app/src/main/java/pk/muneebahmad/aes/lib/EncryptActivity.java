package pk.muneebahmad.aes.lib;

import android.content.DialogInterface;
import android.os.Bundle;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;

import pk.muneebahmad.aes.lib.crypto.AES2;

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
public class EncryptActivity extends AppCompatActivity {

    private EditText etEncrypt;
    private EditText etKey;
    private Button encryptButt;
    private Button decryptButt;
    private Spinner bitSpin;

    private String[] bitsArr = {AES2.TRANSFORM_ECB_PKCS5PADDING, AES2.TRANSFORM_ECB_NO_PADDING, AES2.TRANSFORM_CBC_PKCS5PADDING, AES2.TRANSFORM_CBC_NO_PADDING};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_encrypt);
        this.etEncrypt = (EditText) findViewById(R.id.et_encrypt);
        this.etKey = (EditText) findViewById(R.id.et_key);
        this.encryptButt = (Button) findViewById(R.id.butt_encrypt);
        this.decryptButt = (Button) findViewById(R.id.butt_decrypt);
        this.bitSpin = (Spinner) findViewById(R.id.spinner_bit);

        ArrayAdapter<String> spinAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, bitsArr);
        bitSpin.setAdapter(spinAdapter);

        this.encryptButt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String strToEncrypt = etEncrypt.getText().toString();
                String key = etKey.getText().toString();
                System.out.println("Selected Transform: " + bitSpin.getSelectedItem().toString());
                try {
                    if (bitSpin.getSelectedItem().toString().equalsIgnoreCase(AES2.TRANSFORM_ECB_PKCS5PADDING) ||
                            bitSpin.getSelectedItem().toString().equalsIgnoreCase(AES2.TRANSFORM_ECB_NO_PADDING)) {
                        String res = AES2.encryptECB(key, strToEncrypt, bitSpin.getSelectedItem().toString());
                        makeResultDialog("ENCRYPTED ECB", res);
                        etEncrypt.setText(res);
                    } else if (bitSpin.getSelectedItem().toString().equalsIgnoreCase(AES2.TRANSFORM_CBC_NO_PADDING) ||
                            bitSpin.getSelectedItem().toString().equalsIgnoreCase(AES2.TRANSFORM_CBC_PKCS5PADDING)) {
                        String initVector = "RandomInitVector";
                        String res = AES2.encryptCBC(key, initVector, strToEncrypt, bitSpin.getSelectedItem().toString());
                        makeResultDialog("ENCRYPTED CBC", res);
                        etEncrypt.setText(res);
                    }
                } catch (Exception e) {
                    Log.e("ENCRYPT: ", e.toString());
                    e.printStackTrace();
                }
            }
        });

        this.decryptButt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String strToDecrypt = etEncrypt.getText().toString();
                String key = etKey.getText().toString();
                System.out.println("Selected Transform: " + bitSpin.getSelectedItem().toString());
                try {
                    if (bitSpin.getSelectedItem().toString().equalsIgnoreCase(AES2.TRANSFORM_ECB_PKCS5PADDING) ||
                            bitSpin.getSelectedItem().toString().equalsIgnoreCase(AES2.TRANSFORM_ECB_NO_PADDING)) {
                        String res = AES2.decryptECB(key, strToDecrypt, bitSpin.getSelectedItem().toString());
                        makeResultDialog("DECRYPTED ECB", res);
                        etEncrypt.setText(res);
                    } else if (bitSpin.getSelectedItem().toString().equalsIgnoreCase(AES2.TRANSFORM_CBC_NO_PADDING) ||
                            bitSpin.getSelectedItem().toString().equalsIgnoreCase(AES2.TRANSFORM_CBC_PKCS5PADDING)) {
                        String initVector = "RandomInitVector";
                        String res = AES2.decryptCBC(key, initVector, strToDecrypt, bitSpin.getSelectedItem().toString());
                        makeResultDialog("DECRYPTED CBC", res);
                        etEncrypt.setText(res);
                    }
                } catch (Exception e) {
                    Log.e("DECRYPT: ", e.toString());
                    e.printStackTrace();
                }
            }
        });
    }

    /**
     *
     * @param title {@link java.lang.String}
     * @param message {@link java.lang.String}
     */
    private void makeResultDialog(String title, String message) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(title);
        builder.setIcon(R.drawable.ic_launcher);
        builder.setMessage(message);
        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.dismiss();
            }
        });
        AlertDialog dialog = builder.create();
        dialog.show();
    }

}/** end class. */
