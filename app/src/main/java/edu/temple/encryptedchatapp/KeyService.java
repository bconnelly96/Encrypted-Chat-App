package edu.temple.encryptedchatapp;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyService extends Service {
    final String ALGORITHM = "RSA";
    final String USER_KEYPAIR_DIR = "USER_KEYPAIR_DIR";

    IBinder iBinder = new TestBinder();
    boolean pairGenerated = false;
    FileInputStream inputStream = null;
    FileOutputStream outputStream = null;


    public KeyService() {

    }

    @Override
    public IBinder onBind(Intent intent) {
        return iBinder;
    }

    public class TestBinder extends Binder {
        KeyService getService() {
            return KeyService.this;
        }
    }

    public KeyPair getMyKeyPair() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        KeyPair myKeyPair;
        File userStoreDir = new File(getFilesDir(), USER_KEYPAIR_DIR);
        File file1 = new File(userStoreDir, "userPublicKey");
        File file2 = new File(userStoreDir, "userPrivateKey");

        byte [] publicKeyBytes = null;
        byte [] privateKeyBytes = null;

        if (pairGenerated) {
            inputStream = new FileInputStream(file1);
            publicKeyBytes = new byte[(int)file1.length()];
            inputStream.read(publicKeyBytes);
            inputStream.close();
            inputStream = new FileInputStream(file2);
            privateKeyBytes = new byte[(int) file2.length()];
            inputStream.read(privateKeyBytes);
            inputStream.close();

            PublicKey publicKey = KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            PrivateKey privateKey = KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

            myKeyPair = new KeyPair(publicKey, privateKey);
        } else {
            pairGenerated = true;
            userStoreDir.mkdir();

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
            myKeyPair = kpg.generateKeyPair();

            publicKeyBytes = myKeyPair.getPublic().getEncoded();
            privateKeyBytes = myKeyPair.getPrivate().getEncoded();


            outputStream = new FileOutputStream(file1);
            outputStream.write(publicKeyBytes);
            outputStream.close();
            outputStream = new FileOutputStream(file2);
            outputStream.write(privateKeyBytes);
            outputStream.close();
        }
        return myKeyPair;
    }

    //stores publicKey with partnerName as filename in internal storage
    public void storePublicKey(String partnerName, String publicKey) throws IOException {
        byte [] publicKeyBytes = publicKey.getBytes();

        File keyFile = new File(getFilesDir(), partnerName);
        outputStream = new FileOutputStream(keyFile);
        outputStream.write(publicKeyBytes);
        outputStream.close();
    }

    //retrieves public key saved with partnerName as filename from internal storage
    public RSAPublicKey getPublicKey(String partnerName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File file = new File(getFilesDir(), partnerName);
        inputStream = new FileInputStream(file);
        byte[] key = null;
        inputStream.read(key);
        inputStream.close();

        X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
        KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
        return (RSAPublicKey) factory.generatePublic(spec);
    }
}