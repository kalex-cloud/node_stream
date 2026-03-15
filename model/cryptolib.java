package io.nodestream.identity.model;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.*;

public class cryptolib {

    private PrivateKey getPrivateKey;
    private PublicKey getPublicKey;
    private SecretKey getSecretKey;
    private Boolean getTestFlag;
    private String getReconstructedPrivateKeyStatus;
    private String getReconstructedPublicKeyStatus;
    private String getReconstructedSecretKeyStatus;
    private static final int ACCESS_KEY_LENGTH = 10;
    private static final int SECRET_ACCESS_KEY_LENGTH = 40;
    private Boolean access_key_validation;

    public PrivateKey getReconstructedPrivateKey(){
        return this.getPrivateKey;
    }
    public PublicKey getReconstructedPublicKey(){
        return this.getPublicKey;
    }
    public SecretKey getReconstructedSecretKey(){
        return this.getSecretKey;
    }
    public void setPrivateKey(PrivateKey privKey){
        this.getPrivateKey = privKey ;
    }
    public void setPublicKey(PublicKey pubKey){
        this.getPublicKey = pubKey;
    }
    public void setSecretKey(SecretKey secretKey){
        this.getSecretKey = secretKey;
    }
    public void setTestFlag(Boolean flag){
        this.getTestFlag = flag;
    }
    public void setPrivateKeyReconstructStatus(String status){
        this.getReconstructedPrivateKeyStatus = status;
    }
    public void setPublicKeyReconstructStatus(String status){
        this.getReconstructedPublicKeyStatus = status;
    }
    public void setSecretKeyReconstructStatus(String status){
        this.getReconstructedSecretKeyStatus = status;
    }
    public void access_key_validator(String accessKeyString){
        if(accessKeyString.matches("[A-Za-z0-9]+")){
            this.access_key_validation = true;
        }else{
            this.access_key_validation = false;
        }
    } 
    
    public String generateAccessKey(){
        SecureRandom pseudoRandomValue = new SecureRandom();
         StringBuilder access_key = new StringBuilder(ACCESS_KEY_LENGTH);
        
        for (int i=0; i<= ACCESS_KEY_LENGTH; i++){
            int randomInt = (pseudoRandomValue.nextInt(9));
            char randomLower = (char) (pseudoRandomValue.nextInt(25) + 97);
            char randomUpper = (char) (pseudoRandomValue.nextInt(25) + 65);
            
            String keyContent = "" + randomInt + randomLower + randomUpper;
            access_key_validator(keyContent);
            
            if(access_key_validation.equals(true)){
                access_key.append(keyContent);
            }
        }

        return access_key.toString();
    }
    public String generateSecretAccessKey(){
        SecureRandom pseudoRandom = new SecureRandom();
         byte[] byteLengthForPsRandom = new byte[SECRET_ACCESS_KEY_LENGTH];
         pseudoRandom.nextBytes(byteLengthForPsRandom);
        
        return Base64.getUrlEncoder().withoutPadding().encodeToString(byteLengthForPsRandom);
    }

    private byte[] encodeToBase64(byte[] data){
        return Base64.getEncoder().encode(data);
    }
    private byte[] decodeFromBase64(byte[] data){
        return Base64.getDecoder().decode(data);
    }

    private void streamOutToFile(String filepath, byte[] fileData){
        try{
            File outputPath = new File(filepath);
             FileOutputStream outPath = new FileOutputStream(outputPath);
             outPath.write(encodeToBase64(fileData));
             outPath.close();
        }catch(IOException e){e.getMessage();}
    }
    private byte[] streamFileToMemory(String filepath){
        try{
            File inputPath = new File(filepath);
             FileInputStream inPath = new FileInputStream(inputPath);   
             byte[] fileByteStream = inPath.readAllBytes();
             byte[] decodedByteStream = decodeFromBase64(fileByteStream);
             inPath.close();
            
            return decodedByteStream;
        }catch(FileNotFoundException e)
         {e.getMessage();return null;}catch(IOException f)
         {f.getMessage();return null;}

    }

    private void buildSymmetricAESKey(){
        try{
            KeyGenerator symKey = KeyGenerator.getInstance("aes");
            symKey.init(256);
           SecretKey genSymKey = symKey.generateKey();
            setSecretKey(genSymKey);
        }catch(NoSuchAlgorithmException e){e.getMessage();}
    }
    private void buildAsymmetricRSAKeyPair(){
        try{
            KeyPairGenerator selectInstanceStandard = KeyPairGenerator.getInstance("RSA");
             selectInstanceStandard.initialize(2048);
             KeyPair pubprivKeys = selectInstanceStandard.genKeyPair();
            setPrivateKey(pubprivKeys.getPrivate());
            setPublicKey(pubprivKeys.getPublic());
        }catch(NoSuchAlgorithmException e){e.getMessage();}
    }

    private void reconstructBinaryToSecretKey(byte[] binaryData){
        SecretKey reconstructedKey = new SecretKeySpec(binaryData, "AES");
        if(getTestFlag.equals(true) && reconstructedKey.equals(getSecretKey)){
            setSecretKeyReconstructStatus("reconstructed secret key matches original key");
        }else{setSecretKey(reconstructedKey);}
    }
    private void reconstructBinaryToPublicKey(byte[] binaryData){
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(binaryData);
             KeyFactory factory = KeyFactory.getInstance("RSA");
             PublicKey publicKeyRebuild = factory.generatePublic(keySpec);
             if(getTestFlag.equals(true) && publicKeyRebuild.equals(getPublicKey)){
                setPublicKeyReconstructStatus("reconstructed pubkey matches original key");
            }else{setPublicKey(publicKeyRebuild);}
            
        }catch(NoSuchAlgorithmException e){e.getMessage();}catch(InvalidKeySpecException f){f.getMessage();}
    }
    private void reconstructBinaryToPrivateKey(byte[] binaryData){
        try{
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(binaryData);
             KeyFactory factory = KeyFactory.getInstance("RSA");
             PrivateKey privateKeyRebuild = factory.generatePrivate(keySpec);
             if(getTestFlag.equals(true) && privateKeyRebuild.equals(getPrivateKey)){
                setPrivateKeyReconstructStatus("reconstructed privkey matches original key");
            }else{setPrivateKey(privateKeyRebuild);}
        }catch(NoSuchAlgorithmException e){e.getMessage();}catch(InvalidKeySpecException f){f.getMessage();}
    }

    private byte[] encryptDataAsymmetric(byte[] plainTextToEncrypt){
        try{
            Cipher getCipherInstance = Cipher.getInstance("RSA/ECB/PKCS1Padding");
             getCipherInstance.init(Cipher.ENCRYPT_MODE, getPublicKey);
             byte[] cipherTextRSA = getCipherInstance.doFinal(plainTextToEncrypt);
            return cipherTextRSA;
        }catch(NoSuchAlgorithmException e){e.getMessage();return null;}
        catch(NoSuchPaddingException f){f.getMessage();return null;}
        catch(InvalidKeyException g){g.getMessage();return null;}
        catch(IllegalBlockSizeException h){h.getMessage();return null;}
        catch(BadPaddingException i){i.getMessage();return null;}
  
    }
    private byte[] decryptDataAsymmetric(byte[] encryptedTextToDecrypt){
        try{
            Cipher getCipherInstance  = Cipher.getInstance("RSA/ECB/PKCS1Padding");
             getCipherInstance.init(Cipher.DECRYPT_MODE, getPrivateKey);
             byte[] plainText = getCipherInstance.doFinal(encryptedTextToDecrypt);
            return plainText;
        }catch(NoSuchAlgorithmException e){e.getMessage();return null;}
        catch(NoSuchPaddingException f){f.getMessage();return null;}
        catch(InvalidKeyException g){g.getMessage();return null;}
        catch(IllegalBlockSizeException h){h.getMessage();return null;}
        catch(BadPaddingException i){i.getMessage();return null;}
    }
    private byte[] encryptDataSymmetric(byte[] plainTextToEncrypt){
        try{
            Cipher encryptTextWithAES  = Cipher.getInstance("AES/ECB/PKCS5Padding");
             encryptTextWithAES.init(Cipher.ENCRYPT_MODE, getSecretKey);
             byte[] cipherText = encryptTextWithAES.doFinal(plainTextToEncrypt);
            return cipherText;
        }catch(NoSuchAlgorithmException e){e.getMessage();return null;}
        catch(NoSuchPaddingException f){f.getMessage();return null;}
        catch(InvalidKeyException g){g.getMessage();return null;}
        catch(IllegalBlockSizeException h){h.getMessage();return null;}
        catch(BadPaddingException i){i.getMessage();return null;}
    }
    private byte[] decryptDataSymmetric(byte[] encryptedTextToDecrypt){
        try{
            Cipher decryptTextWithAES  = Cipher.getInstance("AES/ECB/PKCS5Padding");
             decryptTextWithAES.init(Cipher.DECRYPT_MODE, getSecretKey);
             byte[] cipherText = decryptTextWithAES.doFinal(encryptedTextToDecrypt);
            return cipherText;
        }catch(NoSuchAlgorithmException e){e.getMessage();return null;}
        catch(NoSuchPaddingException f){f.getMessage();return null;}
        catch(InvalidKeyException g){g.getMessage();return null;}
        catch(IllegalBlockSizeException h){h.getMessage();return null;}
        catch(BadPaddingException i){i.getMessage();return null;}
    }

    public String controller(String baseDir){
        buildAsymmetricRSAKeyPair();
        buildSymmetricAESKey();
        streamOutToFile(baseDir + "aesplaintext.key", getSecretKey.getEncoded());
        streamOutToFile(baseDir + "privkey.key", getPrivateKey.getEncoded());
        streamOutToFile(baseDir + "pubkey.key", getPublicKey.getEncoded());

        reconstructBinaryToSecretKey(streamFileToMemory(baseDir + "aesplaintext.key"));
        reconstructBinaryToPrivateKey(streamFileToMemory(baseDir + "privkey.key"));
        reconstructBinaryToPublicKey(streamFileToMemory( baseDir + "pubkey.key"));

        streamOutToFile(baseDir + "encryptedAEStext.key", encryptDataAsymmetric(streamFileToMemory(baseDir + "aesplaintext.key"))); 
        streamOutToFile(baseDir + "decryptedaestextfromrsa.key", decryptDataAsymmetric(streamFileToMemory(baseDir + "encryptedAEStext.key")));

        byte[] textToEncryptAES = "this is my secret message".getBytes();
        streamOutToFile(baseDir + "cipherTextAES.txt", encryptDataSymmetric(textToEncryptAES)); 
        streamOutToFile(baseDir + "decryptedCipherTextUsingAES.txt", decryptDataSymmetric(streamFileToMemory(baseDir + "cipherTextAES.txt")));

        if(getTestFlag.equals(true)){return getReconstructedPrivateKeyStatus + "\n" + getReconstructedPublicKeyStatus + "\n" +getReconstructedSecretKeyStatus;}

        return null;
    }
}
