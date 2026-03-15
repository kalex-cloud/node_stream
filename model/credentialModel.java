package io.nodestream.identity.model;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.security.KeyFactory;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class credentialModel {
    // generate rsa key-pair 
    // get token
    // delete key-pair  
    // encrypt message
    // decrypt message
    
    // keystore password + infra
    // alias
    // key pair password 

    // create keystore per user account
    // keystore is encrypted with client's pub key
    // cipher-text is sent back to client, decrypted, encrypted with server's pub key, sent back to the server
    // that's used for iam policies

    public void keyStoreInfrastructure(){
        String masterPassword;
        String aliasKey;
        PrivateKey secretAccessKey;
        String keyStoreFileName;
        String keyStoreFileType; 
    }

    private PublicKey KeyPairPublicKey;
    private PrivateKey KeyPairPrivateKey;

    public void setPublicKey(PublicKey pubKey){
        this.KeyPairPublicKey = pubKey;
    }
    public void setPrivateKeyKey(PrivateKey privKey){
        this.KeyPairPrivateKey = privKey;
    }
    
    private Boolean access_key_validation;
    public void access_key_validator(String accessKeyString){
        if(accessKeyString.matches("[A-Za-z0-9]+")){
            this.access_key_validation = true;
        }else{
            this.access_key_validation = false;
        }
    } 

    private static final int ACCESS_KEY_LENGTH = 10;
    private static final int SECRET_ACCESS_KEY_LENGTH = 40;

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

    private void generateRSAKeyPairs(){
        try{
            KeyPairGenerator selectInstanceStandard = KeyPairGenerator.getInstance("rsa");
            selectInstanceStandard.initialize(512);
            
            KeyPair pubPrivKeys = selectInstanceStandard.genKeyPair();
            
            setPublicKey(pubPrivKeys.getPublic());
            setPrivateKeyKey(pubPrivKeys.getPrivate());

        }catch(NoSuchAlgorithmException e){
            e.getStackTrace();
        }
    }

    private void fileOutStream(byte[] keyByteStream, String filePath){
        File outputPath = new File(filePath);
    
        try
        {
            FileOutputStream fileStream = new FileOutputStream(outputPath);
        
            fileStream.write(keyByteStream);
            fileStream.close();
        }catch(FileNotFoundException e){
            e.getMessage();
        }catch(IOException f){
            f.getMessage();
        }
    }

    public void getRSAKeyPair(String tokenStoreDirectoryBasePath) {
        generateRSAKeyPairs();

        String privKeyFile = tokenStoreDirectoryBasePath + "/privkey.key";
        String pubKeyFile = tokenStoreDirectoryBasePath + "/pubkey.key" ; 
        
        fileOutStream(Base64.getEncoder().encodeToString(KeyPairPrivateKey.getEncoded()).getBytes(StandardCharsets.UTF_8), privKeyFile);
        //fileOutStream(KeyPairPrivateKey.getEncoded(), privKeyFile);
        //fileOutStream(KeyPairPublicKey.getEncoded(), pubKeyFile);
        fileOutStream(Base64.getEncoder().encodeToString(KeyPairPublicKey.getEncoded()).getBytes(), pubKeyFile);
    }
    // client/server == signer/verifier || initiator/responder
    public void generateAESTokenData(String filePathToPublicKey) throws Exception{

        SecretKey tokenAesEncryptionKey = generateAESSymmetricKey();

        byte[] rsaKeyBytes = transformKeyFileFormattingToKeyPair(filePathToPublicKey);
        PublicKey responderPublicKey = reconstructPublicKeyInfrastructure(rsaKeyBytes);

        //String aesKeyBits = new String(tokenAesEncryptionKey.getEncoded(), StandardCharsets.ISO_8859_1);
        //String encryptAESKey = encryptContentFromASYMKey(responderPublicKey,aesKeyBits);
        String encryptAESKey = encryptContentFromAsymKeyByteStream(responderPublicKey, tokenAesEncryptionKey.getEncoded());
        fileOutStream(stringToByteArrayConversion(encryptAESKey),"/home/kevin/Documents/rsa/encryptedAES.key");

    }
    
    private byte[] generateTokens(byte[] tokenEncryptKey, PublicKey responder ) throws Exception{
        Cipher cipherPad = Cipher.getInstance("AES");
         cipherPad.init(Cipher.ENCRYPT_MODE, responder);
            //cipherPad.init(Cipher.ENCRYPT_MODE, KeyPairPublicKey);
        return cipherPad.doFinal(tokenEncryptKey);
    }
    
    private SecretKey generateAESSymmetricKey() throws Exception {
        KeyGenerator symmetricKeyGeneration = KeyGenerator.getInstance("aes");
        symmetricKeyGeneration.init(256);

        SecretKey AesKeyContents =symmetricKeyGeneration.generateKey();
        return AesKeyContents;
    }
    
    private byte[] stringToByteArrayConversion(String message){
        return message.getBytes();
    }
    private String encodeSecretMessageFormatting(byte[] message){
        return Base64.getEncoder().encodeToString(message);
    }    
    private byte[] decodeSecretMessageFormatting(String message){
        return Base64.getDecoder().decode(message);
    }    

    private byte[] transformKeyFileFormattingToKeyPair(String pathToFile){
        try{

            byte[] fileData = Files.readAllBytes(Paths.get(pathToFile));
            String encodedKeyBytes = new String(fileData, StandardCharsets.UTF_8).replaceAll("\\s+", "");
            byte[] keyBytes = decodeSecretMessageFormatting(encodedKeyBytes);
        
            return keyBytes;
        }catch(FileNotFoundException e){e.getMessage();return null;}catch(IOException f){f.getMessage();return null;}
    }

    private byte[] decryptContentFromASYMKey(PrivateKey responder, byte[] contentToDecrypt){
        try
        {
            Cipher getCipherInstance = Cipher.getInstance("RSA/ECB/PKCS1Padding");
             getCipherInstance.init(Cipher.DECRYPT_MODE, responder);

            return getCipherInstance.doFinal(contentToDecrypt);
        }catch(NoSuchAlgorithmException e){e.getMessage();return null;}catch(NoSuchPaddingException f){f.getMessage();return null;}
        catch(InvalidKeyException g){g.getMessage();return null;}catch(IllegalBlockSizeException h){h.getMessage();return null;}
        catch(BadPaddingException i){i.getMessage();return null;}
    }

    private String encryptContentFromAsymKeyByteStream(PublicKey initiator, byte[] cipherStream){
        try
        {
            Cipher getCipherInstance = Cipher.getInstance("RSA");
             getCipherInstance.init(Cipher.ENCRYPT_MODE, initiator);
            
             return encodeSecretMessageFormatting(getCipherInstance.doFinal(cipherStream));  
        }catch(NoSuchAlgorithmException e){e.getMessage(); return null;}catch(NoSuchPaddingException f){f.getMessage();return null;}
        catch(InvalidKeyException g){g.getMessage();return null;}catch(IllegalBlockSizeException h){h.getMessage();return null;}
        catch(BadPaddingException i){i.getMessage();return null;}
    }
    private String encryptContentFromASYMKey(PublicKey initiator, String contentToEncrypt){
        try
        {
            Cipher getCipherInstance = Cipher.getInstance("RSA");
             getCipherInstance.init(Cipher.ENCRYPT_MODE, initiator);
            
             return encodeSecretMessageFormatting(getCipherInstance.doFinal(stringToByteArrayConversion(contentToEncrypt)));  
        }catch(NoSuchAlgorithmException e){e.getMessage(); return null;}catch(NoSuchPaddingException f){f.getMessage();return null;}
        catch(InvalidKeyException g){g.getMessage();return null;}catch(IllegalBlockSizeException h){h.getMessage();return null;}
        catch(BadPaddingException i){i.getMessage();return null;}
    }

    private PublicKey reconstructPublicKeyInfrastructure(byte[] binaryDataToReconstruct)throws Exception{
    
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(binaryDataToReconstruct);
        KeyFactory factory = KeyFactory.getInstance("RSA"); // or "EC" or "DSA" depending on your key type
        PublicKey publicKeyRebuild = factory.generatePublic(keySpec);
        
        return publicKeyRebuild;
    
    }

    private PrivateKey reconstructPrivateKeyInfrastructure(byte[] binaryDataToReconstruct) throws Exception{
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(binaryDataToReconstruct);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privateKeyRebuild = factory.generatePrivate(keySpec);

        return privateKeyRebuild;

    }

    public String encryptDataAsymmetric(String message) throws Exception{
        byte[] getBinaryDataConversionFromBase64 = transformKeyFileFormattingToKeyPair("/home/kevin/Documents/rsa/pubkey.key");
        PublicKey publicKey = reconstructPublicKeyInfrastructure(getBinaryDataConversionFromBase64);
        String encryptedText = encryptContentFromASYMKey(publicKey, message);
        
        return encryptedText;
    }

    public String decryptDataAsymmetric(String message) throws Exception{

        byte[] getBinaryDataConversionFromBase64 = transformKeyFileFormattingToKeyPair("/home/kevin/Documents/rsa/privkey.key");

        String encodedBinaryData = encodeSecretMessageFormatting(getBinaryDataConversionFromBase64);

        byte[] privateKeyBytes = decodeSecretMessageFormatting(encodedBinaryData);

        byte[] decryptedBytes = 
            decryptContentFromASYMKey(
             reconstructPrivateKeyInfrastructure(privateKeyBytes), 
              decodeSecretMessageFormatting(message));
                      
        String decryptedMessage = new String(decryptedBytes, "UTF-8");
        //System.out.println(decryptedMessage);

        return decryptedMessage;
    }
    
    private String encryptContentFromSymmetricKey(SecretKey aesPrivateKey, String contentToEncrypt){
        try
        {
            Cipher getCipherInstance = Cipher.getInstance("AES/ECB/PKCS5Padding");
             getCipherInstance.init(Cipher.ENCRYPT_MODE, aesPrivateKey);
            
             return encodeSecretMessageFormatting(getCipherInstance.doFinal(stringToByteArrayConversion(contentToEncrypt)));  
        }catch(NoSuchAlgorithmException e){e.getMessage(); return null;}catch(NoSuchPaddingException f){f.getMessage();return null;}
        catch(InvalidKeyException g){g.getMessage();return null;}catch(IllegalBlockSizeException h){h.getMessage();return null;}
        catch(BadPaddingException i){i.getMessage();return null;}
    }

    private String decryptContentFromSymmetricKey(SecretKey aesPrivateKey, String contentToDecrypt){
        try
        {
            Cipher getCipherInstance = Cipher.getInstance("AES/ECB/PKCS5Padding");
             getCipherInstance.init(Cipher.DECRYPT_MODE, aesPrivateKey);
            
             return encodeSecretMessageFormatting(getCipherInstance.doFinal(stringToByteArrayConversion(contentToDecrypt)));  
        }catch(NoSuchAlgorithmException e){e.getMessage(); return null;}catch(NoSuchPaddingException f){f.getMessage();return null;}
        catch(InvalidKeyException g){g.getMessage();return null;}catch(IllegalBlockSizeException h){h.getMessage();return null;}
        catch(BadPaddingException i){i.getMessage();return null;}
    }

    private SecretKey convertBinaryDataToKeyData(byte[] binaryDataPackage){
        SecretKey repackagedSecretKey = new SecretKeySpec(binaryDataPackage, "AES");
        return repackagedSecretKey;
    }

    private byte[] loadTokenData(String encryptedAesToken){
        try{
            String plainTextAesBinary = decryptDataAsymmetric(encryptedAesToken);
            byte[] plainTexAesBinaryConvertedToByteArray = stringToByteArrayConversion(plainTextAesBinary);

            return plainTexAesBinaryConvertedToByteArray;
        }catch(Exception e ){e.getMessage();return null;}
    }

    private SecretKey prepareEncryptDecrypt(String aesKey){
        byte [] plainTextAESConvertToBinary = loadTokenData(aesKey); 
        SecretKey privateKey = convertBinaryDataToKeyData(plainTextAESConvertToBinary);
        
        return privateKey;
    }

    public String encryptContentFromSymKey(String aesKey, String message)throws Exception{
        SecretKey preparedData = decryptAESToken(aesKey);
        byte[] decodeStringToByteArray = message.getBytes(StandardCharsets.UTF_8);

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(cipher.ENCRYPT_MODE, preparedData);
        byte[] ciphertextBytes = cipher.doFinal(decodeStringToByteArray);
        String base64CipherText = Base64.getEncoder().encodeToString(ciphertextBytes);

        //String encryptedContents = encryptContentFromSymmetricKey(preparedData, message);
        return base64CipherText;
    }

    public String decryptContentFromSymKey(String aesKey, String message)throws Exception{ 
        SecretKey preparedData = decryptAESToken(aesKey);
        //String decryptedContents = decryptContentFromSymmetricKey(preparedData, message);
        byte[] cipherTextBytes = Base64.getDecoder().decode(message);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, preparedData);

        byte[] plaintextBytes = cipher.doFinal(cipherTextBytes);
        String decryptedText = new String(plaintextBytes, StandardCharsets.UTF_8);
        return decryptedText;
    }


    private SecretKey decryptAESToken(String token)throws Exception{
        // decode from base64 to encrypted binary
        byte[] decodedEncryptedBinary = transformKeyFileFormattingToKeyPair(token);
        if (decodedEncryptedBinary == null) {
            throw new RuntimeException("Failed to read or decode the AES token file.");
        }
        // decrypt encrypted binary 
        byte[] getBinaryDataConversionFromBase64 = transformKeyFileFormattingToKeyPair("/home/kevin/Documents/rsa/privkey.key");
        PrivateKey reconstructKey = reconstructPrivateKeyInfrastructure(getBinaryDataConversionFromBase64);

        byte[] decryptedBinaryAES = decryptContentFromASYMKey(reconstructKey, decodedEncryptedBinary);
        if (decryptedBinaryAES == null) {
            throw new RuntimeException("Decryption of AES token failed. Likely wrong private key or corrupted token.");
        }
        System.out.println("Decrypted AES Key Length: " + decryptedBinaryAES.length + " bytes");

        // encrypt message with unecrypted aes binary
        SecretKey unencryptedBinaryAES = convertBinaryDataToKeyData(decryptedBinaryAES);
        //String hey = encryptContentFromSymmetricKey(unencryptedBinaryAES, "hello world!");
        return unencryptedBinaryAES;

    }
    
    
  


// public static byte[] decryptWithPrivateKey(String base64Encrypted, PrivateKey privateKey) throws Exception {
//     byte[] ciphertext = Base64.getDecoder().decode(base64Encrypted);
// 
//     Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
//     cipher.init(Cipher.DECRYPT_MODE, privateKey);
// 
//     return cipher.doFinal(ciphertext);
// }

}
