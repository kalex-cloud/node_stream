package io.nodestream.identity.model;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Dictionary;

import javax.crypto.spec.SecretKeySpec;


public class plumbing {

    public void theEverythingfunction()throws Exception{
        // --- key generators
        KeyGenerator symKey = KeyGenerator.getInstance("aes");
         symKey.init(256);

        SecretKey genSymKey = symKey.generateKey();
                
        File outputPath = new File("/home/kevin/Documents/rsa/aesplainttext.key");
         FileOutputStream putPath = new FileOutputStream(outputPath);
         putPath.write(Base64.getEncoder().encode(genSymKey.getEncoded()));
         putPath.close();

        KeyPairGenerator selectInstanceStandard = KeyPairGenerator.getInstance("RSA");
         selectInstanceStandard.initialize(2048);
         KeyPair pubprivKeys = selectInstanceStandard.genKeyPair();

        File outputPath1 = new File("/home/kevin/Documents/rsa/privKey.key");
         FileOutputStream putPath1 = new FileOutputStream(outputPath1);
         putPath1.write(Base64.getEncoder().encode(pubprivKeys.getPrivate().getEncoded())); 
         putPath1.close();
        
        File outputPath2 = new File("/home/kevin/Documents/rsa/pubKey.key");
        FileOutputStream putPath2 = new FileOutputStream(outputPath2);
        putPath2.write(Base64.getEncoder().encode(pubprivKeys.getPublic().getEncoded())); 
        putPath2.close();

        // --- encryption

        File inputPath = new File("/home/kevin/Documents/rsa/aesplainttext.key");
         FileInputStream inpath1 = new FileInputStream(inputPath);
        
        byte[] textAsByte = inpath1.readAllBytes();
        byte[] decodedTextAsByte = Base64.getDecoder().decode(textAsByte);
        inpath1.close();

        SecretKey reconstructedKey = new SecretKeySpec(decodedTextAsByte, "AES");

        Cipher encryptTextWithAES  = Cipher.getInstance("AES/ECB/PKCS5Padding");
         encryptTextWithAES.init(Cipher.ENCRYPT_MODE, reconstructedKey);
         byte[] cipherText = encryptTextWithAES.doFinal(("full end-to-end test 2025!").getBytes());
        
        File outputPath3 = new File("/home/kevin/Documents/rsa/encryptedAESText.key");
         FileOutputStream putPath3 = new FileOutputStream(outputPath3);
         putPath3.write(Base64.getEncoder().encode(cipherText)); 
         putPath3.close();

        // --- decryption 

        File inputPath2 = new File("/home/kevin/Documents/rsa/encryptedAESText.key");
         FileInputStream inpath3 = new FileInputStream(inputPath2);
         byte[] textAsByte2 = inpath3.readAllBytes();
         byte[] decodedTextAsByte2 = Base64.getDecoder().decode(textAsByte2);
         inpath3.close();

        Cipher decryptTextWithAES = Cipher.getInstance("AES/ECB/PKCS5Padding");
         decryptTextWithAES.init(Cipher.DECRYPT_MODE, reconstructedKey);
         byte[] plainText = decryptTextWithAES.doFinal(decodedTextAsByte2);

        File outputPath4 = new File("/home/kevin/Documents/rsa/decryptedAESText.key");
         FileOutputStream putPath5 = new FileOutputStream(outputPath4);
         putPath5.write(Base64.getEncoder().encode(plainText)); 
         putPath5.close();

        // --- encrypt aes key with public key
        File rsaInputFile1 = new File("/home/kevin/Documents/rsa/pubKey.key");
         FileInputStream rsaInputFileStream1 = new FileInputStream(rsaInputFile1);
         byte[] encodedFileStream1 = rsaInputFileStream1.readAllBytes();
         byte[] decodeFileStream1 = Base64.getDecoder().decode(encodedFileStream1);
         rsaInputFileStream1.close();

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodeFileStream1);
         KeyFactory factory = KeyFactory.getInstance("RSA"); // or "EC" or "DSA" depending on your key type
         PublicKey publicKeyRebuild = factory.generatePublic(keySpec);

        Cipher getCipherInstance = Cipher.getInstance("RSA/ECB/PKCS1Padding");
         getCipherInstance.init(Cipher.ENCRYPT_MODE, publicKeyRebuild);
         byte[] plainTextRSA = getCipherInstance.doFinal(decodedTextAsByte);

        File outputPath5 = new File("/home/kevin/Documents/rsa/aesEncryptedWithRSA.key");
         FileOutputStream putPath6 = new FileOutputStream(outputPath5);
         putPath6.write(Base64.getEncoder().encode(plainTextRSA)); 
         putPath6.close();
        
        
        // --- decrypt aes key with private key
        File rsaInputFile3 = new File("/home/kevin/Documents/rsa/privKey.key");
         FileInputStream rsaInputFileStream3 = new FileInputStream(rsaInputFile3);
         byte[] encodedFileStream3 = rsaInputFileStream3.readAllBytes();
         byte[] decodeFileStream3 = Base64.getDecoder().decode(encodedFileStream3);
         rsaInputFileStream3.close();

        File rsaInputPath4 = new File("/home/kevin/Documents/rsa/aesEncryptedWithRSA.key");
         FileInputStream rsaIFileInputStream4 = new FileInputStream(rsaInputPath4);
         byte[] encodedFileStream4 = rsaIFileInputStream4.readAllBytes();
         byte[] decodedFileStream4 = Base64.getDecoder().decode(encodedFileStream4);
         rsaIFileInputStream4.close();

        PKCS8EncodedKeySpec keySpec2 = new PKCS8EncodedKeySpec(decodeFileStream3);
         KeyFactory factory3 = KeyFactory.getInstance("RSA");
         PrivateKey privateKeyRebuild = factory3.generatePrivate(keySpec2);
        
        Cipher compareAES  = Cipher.getInstance("RSA/ECB/PKCS1Padding");
         compareAES.init(Cipher.DECRYPT_MODE, privateKeyRebuild);
         byte[] cipherTextAES = compareAES.doFinal(decodedFileStream4);

        SecretKey reconstructedKeyEncrypted = new SecretKeySpec(cipherTextAES, "AES");

        Boolean isTrue = reconstructedKey.equals(reconstructedKeyEncrypted);
        String istrue = new String(isTrue.toString());

        File outputPath6 = new File("/home/kevin/Documents/rsa/isKeyTrue.txt");
         FileOutputStream putPath7 = new FileOutputStream(outputPath6);
         putPath7.write(istrue.getBytes()); 
         putPath7.close();
        
        // -- encrypt string with aes plaint-text --> decrypt using aesEncryptedKEy

        Cipher textWithAES  = Cipher.getInstance("AES/ECB/PKCS5Padding");
         textWithAES.init(Cipher.ENCRYPT_MODE, genSymKey);
         byte[] cipherAESText = textWithAES.doFinal(("full end-to-end test 2025!").getBytes());

        Cipher textWithRSA = Cipher.getInstance("AES/ECB/PKCS5Padding");
         textWithRSA.init(Cipher.DECRYPT_MODE, reconstructedKeyEncrypted);
         byte[] plainRSAtext = textWithRSA.doFinal(cipherAESText);
        
        File test = new File("/home/kevin/Documents/rsa/decryptedAESStringFromDeconstructedPrivateKey.txt");
         FileOutputStream test1 = new FileOutputStream(test);
         test1.write(plainRSAtext);
         test1.close();
         
    }
}
