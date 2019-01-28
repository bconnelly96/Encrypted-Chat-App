package edu.temple.encryptedchatapp;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {
    Button decryptButton, encryptButton, getKeyButton;
    EditText userInput;
    TextView encrypted, decrypted;

    KeyService keyService;
    KeyPair userKeyPair = null;
    boolean connected;
    boolean keyAcquired = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        decryptButton = findViewById(R.id.button2);
        encryptButton = findViewById(R.id.button);
        getKeyButton = findViewById(R.id.button3);
        userInput = findViewById(R.id.editText);
        encrypted = findViewById(R.id.textView);
        decrypted = findViewById(R.id.textView2);

        decryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (connected && keyAcquired) {
                    try {
                        userKeyPair = keyService.getMyKeyPair();
                        String textToDecrypt = encrypted.getText().toString();
                        String decryptedText = decrypt(textToDecrypt);
                        decrypted.setText(decryptedText);
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (InvalidKeySpecException e) {
                        e.printStackTrace();
                    }
                } else {
                    Toast.makeText(MainActivity.this, "Acquire Key Pair to Decrypt", Toast.LENGTH_SHORT).show();
                }
            }
        });

        encryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (connected && keyAcquired) {
                    try {
                        userKeyPair = keyService.getMyKeyPair();
                        String textToEncrypt = userInput.getText().toString();
                        String encryptedText = encrypt(textToEncrypt);
                        encrypted.setText(encryptedText);
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (InvalidKeySpecException e) {
                        e.printStackTrace();
                    }
                } else {
                    Toast.makeText(MainActivity.this, "Acquire Key Pair to Decrypt", Toast.LENGTH_SHORT).show();
                }
            }
        });

        getKeyButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (connected) {
                    try {
                        userKeyPair = keyService.getMyKeyPair();
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (InvalidKeySpecException e) {
                        e.printStackTrace();
                    }
                    if (userKeyPair != null) {
                        keyAcquired = true;
                        Toast.makeText(MainActivity.this, "Key Acquired", Toast.LENGTH_SHORT).show();
                    }
                }
            }
        });
    }

    @Override
    public void onStart() {
        super.onStart();
        Intent serviceIntent = new Intent(this, KeyService.class);
        bindService(serviceIntent, serviceConnection, Context.BIND_AUTO_CREATE);
    }

    @Override
    public void onStop() {
        super.onStop();
        unbindService(serviceConnection);
    }

    ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            KeyService.TestBinder binder = (KeyService.TestBinder) service;
            keyService = binder.getService();
            connected = true;
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            connected = false;
        }
    };

    String encrypt(String plainText) {
        String encryptedText = null;

        try {
            Cipher cipher = Cipher.getInstance("RSA");
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPrivateKey privateKey = (RSAPrivateKey) userKeyPair.getPrivate();
            String privateKeyString = privateKey.getPrivateExponent().toString();
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(privateKey.getModulus(), new BigInteger(privateKeyString));
            privateKey = (RSAPrivateKey) factory.generatePrivate(privateKeySpec);

            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] encrypted = cipher.doFinal(plainText.getBytes());
            encryptedText = Base64.encodeToString(encrypted, Base64.DEFAULT);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return encryptedText;
    }

    String decrypt(String encryptedText) {
        String decryptedText = null;

        try {
            Cipher cipher = Cipher.getInstance("RSA");
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPublicKey publicKey = (RSAPublicKey) userKeyPair.getPublic();
            String publicKeyString = publicKey.getPublicExponent().toString();
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(publicKey.getModulus(), new BigInteger(publicKeyString));
            publicKey = (RSAPublicKey) factory.generatePublic(publicKeySpec);

            byte [] encryptedByte = Base64.decode(encryptedText, Base64.DEFAULT);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            decryptedText = new String(cipher.doFinal(encryptedByte));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return decryptedText;
    }
}