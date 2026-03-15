package io.nodestream.identity.model;

import javax.crypto.SecretKey;
import java.security.PrivateKey;

import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.io.IOException;
import java.io.InputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import java.util.List;
import java.util.ArrayList;

public class cryptoStore implements Serializable{
// purpose is for the secrets manager
// store encrypted data using the pub key
// send file over to be decrypted with user's priv key

    private List<Object> getObjectListExport = new ArrayList<>();
    private String getAlias;
    private byte[] getDataSet;
    private transient SecretKey getSecretKey;
    private transient PrivateKey getPrivateKey;
    private OutputStream getOutStream;
    private InputStream getInputStream;
    private String getFilePath;

    public List<Object> getObjectExported(){
        return this.getObjectListExport;
    }
    public void setObjectListExport(Object objectList){
         this.getObjectListExport.add(objectList);
    }
    public String getAliasExport(){
        return this.getAlias;
    }
    public void setAlias(String pass){ // some form of encrypted content
        this.getAlias = pass;
    }
    public void setDataSet(byte[] dataStorage){
        this.getDataSet = dataStorage;
    }
    public byte[] getData(){return this.getDataSet;}
    public void setSecretKey(SecretKey secKey){
        this.getSecretKey = secKey;
    }
    public void setPrivateKey(PrivateKey privKey){
        this.getPrivateKey = privKey;
    }
    public void setOutputStream(OutputStream outStream){
        this.getOutStream = outStream;
    }
    public void setInputStream(InputStream inStream){
        this.getInputStream =  inStream;
    }
    public void setFilePath(String inPath){
        this.getFilePath = inPath;
    }

    public cryptoStore(String alias, String filePath){ // just stores container/file name
        try{
            setAlias(alias);
             setFilePath(filePath);
             String aliasName = getAlias;
    
            List<Object> containerParameters = new ArrayList<>();
             containerParameters.add(aliasName);
            
            putEmptyContainer(containerParameters);
        }catch(Exception e){e.getMessage();}
    }
    public cryptoStore(PrivateKey privKey, String alias, String filePath){ // store just private key
        try{
            setAlias(alias);
             setFilePath(filePath);
             setPrivateKey(privKey);
             String aliasName = getAlias;
            
            List<Object> containerParameters = new ArrayList<>();
             containerParameters.add(aliasName);
             containerParameters.add(privKey);
            
             putPrivateKey(containerParameters);
        }catch(Exception e){e.getMessage();}
    }
    public cryptoStore(SecretKey secKey, String alias, String filePath){ // store just aes key
        try{
            setAlias(alias);
             setFilePath(filePath);
             setSecretKey(secKey);
             String aliasName = getAlias;
            
            List<Object> containerParameters = new ArrayList<>();
             containerParameters.add(aliasName);
             containerParameters.add(secKey);
            
             putSecretKey(containerParameters);
        }catch(Exception e){e.getMessage();}
    }
    public cryptoStore(String alias, byte[] data){ // store just encrypted data
        setAlias(alias);
        setDataSet(data);
    }

    private FileOutputStream fileOutputDefinition(String keyStore){
        try{
            File outPath = new File(keyStore);
             FileOutputStream outPathStream = new FileOutputStream(outPath);
             setOutputStream(outPathStream);
            return outPathStream;
        }catch(IOException e){e.getMessage();return null;}
    }
    private Object fileInputDefinition(String keyStore){
        try{
            File inPath = new File(keyStore);
             FileInputStream inPathStream = new FileInputStream(inPath);
            return inPathStream;
        }catch(IOException e){e.getMessage();return null;}
    }
    private ObjectOutputStream buildContainerOutStream(List<Object> containerParams)throws Exception{
        ObjectOutputStream container = new ObjectOutputStream(getOutStream);
        
        for(int x=0; x<containerParams.size(); x++){
            container.writeObject(containerParams.get(x));
        }
        return container;
    }
    private ObjectInputStream rebuildContainerFromInputStream(Object containerParams) throws Exception{
        ObjectInputStream container = new ObjectInputStream(getInputStream);
         container.defaultReadObject();
         //container.readObject();
        return container;
    }

    public void putEmptyContainer(List<Object> parameters)throws Exception{
        fileOutputDefinition(getFilePath);
        buildContainerOutStream(parameters);
    }
    private void putPrivateKey(List<Object> parameters)throws Exception{
        fileOutputDefinition(getFilePath);
        buildContainerOutStream(parameters);
    }
    public void putSecretKey(List<Object> parameters)throws Exception{
        fileOutputDefinition(getFilePath);
        buildContainerOutStream(parameters);
    }

    public void getEmptyContainer()throws Exception{
        ObjectInputStream container = rebuildContainerFromInputStream(fileInputDefinition(getAlias));
         setAlias((String) container.readObject());
    }
    public void getPrivateKey(){}
    public void getSecretKey(){}

   

    public void putEncryptedData()throws Exception{
        buildContainerOutStream(getDataSet);
    }
    public void getEncryptedData(){}

    public void testEverything(List<Object> mylist)throws Exception{
        fileOutputDefinition(getAlias);
        buildContainerOutStream(mylist);
//        File outPath = new File(getAlias);
//         FileOutputStream outPathStream = new FileOutputStream(outPath);
//
//        ObjectOutputStream container = new ObjectOutputStream(outPathStream);
//        ObjectOutputStream container = new ObjectOutputStream(fileOutputDefinition(getAlias));
//        for(int x=0; x<mylist.size();x++){
//            container.writeObject(mylist.get(x));
//        }
//        
//        container.close();
// ---

//        File inPath = new File(getAlias);
//        try(
//             FileInputStream inPathStream = new FileInputStream(inPath);
//             ObjectInputStream containerRebuild = new ObjectInputStream(inPathStream);
//            ){
//                while(true){
//                    try{
//                        Object addObject = containerRebuild.readObject();
//                        setObjectListExport(addObject);
//                    }catch(EOFException e){
//                        //containerRebuild.close();
//                        //inPathStream.close();
//                        break;
//                    }
//                }
//        }catch(Exception e){e.printStackTrace();}
//        
    }
}
