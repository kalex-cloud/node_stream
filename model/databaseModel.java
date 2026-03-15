package io.nodestream.identity.model;

import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Hashtable;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.sql.DataSource;
import org.postgresql.ds.PGSimpleDataSource;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.Buffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.Dictionary;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;

public class databaseModel {

    private static final String USERNAMECOLUMN = "UsernameColumn";
    private static final String ACCESSKEYCOLUMN = "AccessKeyColumn";
    private static final String RESOURCECOLUMN = "ResourceColumn";
    private static final String TOKENCOLUMN = "TokenColumn";
    private static final String TIMESTAMPCOLUMN = "TimeStampColumn";
    private static final String IDCOLUMN = "IdColumn";
    private static final String SECRETACCESSKEY = "SecretAccessKeyColumn";
    private static final String PERMISSIONLEVEL = "PermissionSetColumn";
    public static final Set<String> DATABASECOLUMNS(){
        Set<String> expectedKeys = Set.of(USERNAMECOLUMN,ACCESSKEYCOLUMN,RESOURCECOLUMN,TOKENCOLUMN,TIMESTAMPCOLUMN,IDCOLUMN,SECRETACCESSKEY,PERMISSIONLEVEL);
        return expectedKeys;
    }

    private Boolean pathValidation;
    public void pathValidator(String pathObject){
        if(pathObject.matches("^(/[^/\\u0000:*?\"<>|]+)+/?$")){
            this.pathValidation = true;
        }else{
            this.pathValidation = false;
        }
    }
    private Boolean permissionSetValidation;
    public void permissionsValidator(String permissionsFlag){
        String acceptedValues = "^(r|w|x|ro|wo|rw)$";

        boolean isValid = Pattern.compile(acceptedValues, Pattern.CASE_INSENSITIVE)
                                  .matcher(permissionsFlag)
                                  .matches();
        if(isValid == true){
            this.permissionSetValidation = true;
        }else{
            this.permissionSetValidation = false; 
        }
    }

    Map<String, Class<?>> rowValidatorTypeExpectation = Map.of(
        USERNAMECOLUMN, String.class,
        ACCESSKEYCOLUMN, String.class,
        RESOURCECOLUMN, String.class, 
        TOKENCOLUMN, String.class,        
        TIMESTAMPCOLUMN, String.class,
        IDCOLUMN, Integer.class,
        SECRETACCESSKEY, String.class,
        PERMISSIONLEVEL, String.class 
    );

    private String validatedJsonStringData;
    public void putValidatedJsonStringData(String validStringfiedJson){
        this.validatedJsonStringData = validStringfiedJson;
    }
    private String columnvalidation;
    public String columnvalidator(String decision){
        this.columnvalidation = decision;
        return columnvalidation;
    }

    private String rowValidation;
    public String rowValidator(String decision){
        this.rowValidation = decision;
        return rowValidation;
    }

    private Boolean RowValidator(Map<String,Object> valueView){
        for (String key: rowValidatorTypeExpectation.keySet()){
            Object value = valueView.get(key);
            Class<?> expected = rowValidatorTypeExpectation.get(key);
            if (!expected.isInstance(value)){
                rowValidator("false");
                return false;
            }
        }
        pathValidator(valueView.get(RESOURCECOLUMN).toString());
        if (! pathValidation.equals(true)){
            rowValidator("false");
            return false;
        }
        permissionsValidator(valueView.get(PERMISSIONLEVEL).toString());
        if(! permissionSetValidation.equals(true)){
            rowValidator("false");
            return false; 
        }
        return true; 
    }

    private Boolean ColumnValidator(Map<String,Object> keyView){
        Set<String> inputKeyView = new HashSet<>(keyView.keySet());
        Set<String> expectedKeyView = DATABASECOLUMNS();

        if(inputKeyView.equals(expectedKeyView)){
            columnvalidator("true");
            return true;
        }else{
            columnvalidator("false");
            return false;
        }
    }

    private Boolean IsPolicyValidated(Map<String,Object> validateKeyValue){
        if(ColumnValidator(validateKeyValue).equals(true)){
            if(RowValidator(validateKeyValue).equals(true)){
                rowValidator("true");
                return true;
            };
        }
        return false;
    }

    public String transformJSONDocumentFromFile(String filePath){
        try{
            ObjectMapper jsonPreprocessor = new ObjectMapper();
            Object jsonStoreInputFromFile = jsonPreprocessor.readValue(new File(filePath), Object.class);
            String stringifiedJsonOutput = jsonPreprocessor.writeValueAsString(jsonStoreInputFromFile);
            //validatedJsonStringData = stringifiedJsonOutput;
            return stringifiedJsonOutput;
        }catch( IOException e){
            return e.getMessage(); 
        }
    }

    private Map<String,Object> transformJSONStringToMap(String policyString) throws Exception{

        ObjectMapper jsonPreprocessor = new ObjectMapper();
        Map<String, Object> iterableJsonKeyValues = jsonPreprocessor.readValue(policyString, new TypeReference<Map<String,Object>>() {});
        return iterableJsonKeyValues;
    }

    public String readPolicyDocument(String objectStore){
        try{
            validatePolicyDocument(objectStore);
            if(columnvalidation.equals("true") && rowValidation.equals("true")){
                return validatedJsonStringData;
            }else{
                return "Row is: " + rowValidation + "Column is: " + columnvalidation;
            }

        }catch(Exception e){return e.getMessage();}
        

    }

    private void validatePolicyDocument(String iamPolicyDocument) throws Exception{
        validatedJsonStringData = iamPolicyDocument;
        Map<String, Object> data = transformJSONStringToMap(iamPolicyDocument);
        IsPolicyValidated(data);
    }

    public void writePolicyDocumentToDatabase(String policyDocument, String pathToPermissionsTemplate, String dbName) throws Exception{
        Map<String,Object> policy = transformJSONStringToMap(policyDocument);
        String editStatementFromPolicyDocument = transformMapToDatabaseQuery(policy, pathToPermissionsTemplate);
        
        DataSource dbDataSource = databasePrelimTest(dbName);
        addNewValuessToDatabase(dbDataSource, editStatementFromPolicyDocument);
    }

    private String utility;
    private ArrayList<String> backup;

    public String getUtility(){
        return utility;
    }

    public void setUtility(String utilityName){
        this.utility = utilityName; 
    }

    public ArrayList<String> getBackupArguments(String user_name, String database_name, String file_path, String file_type){
        this.backup.add(getUtility()); //0
        this.backup.add(user_name); //1
        this.backup.add(database_name); //2
        this.backup.add(file_path); //3
        this.backup.add(file_type); //4
        return backup; 
    }

    public static void processBuilderToDecrypt(SecretKey generatedAESKey, byte[] initVector, Cipher algoPadder){
        try{
            algoPadder.init( Cipher.DECRYPT_MODE, generatedAESKey, new IvParameterSpec( initVector ) ); // reuse the key and iv generated before
    
            // create stream
            CipherInputStream cipherInputStream = new CipherInputStream( new BufferedInputStream( new FileInputStream( "out.aes" ) ), algoPadder );
            ObjectInputStream inputStream = new ObjectInputStream( cipherInputStream );
            SealedObject sealedObject = (SealedObject) inputStream.readObject();
            String mystring = (String) sealedObject.getObject(algoPadder);


        }catch(IOException a){}
            catch(ClassNotFoundException b){}
            catch(IllegalBlockSizeException c){}
            catch(BadPaddingException d){}
            catch(InvalidAlgorithmParameterException e){}
            catch(InvalidKeyException f){}        

    }

    public static Map<String, Object> processBuilderToEncrypt(){
        String plainTextInput = "this is stuff to encrypt";
        String outputPATH = "./out{}.aes"; 

        Map<String, Object> encryptInfo = new HashMap<>();

        try{
            KeyGenerator keyGeneration = KeyGenerator.getInstance("AES");
             SecretKey symKey = keyGeneration.generateKey();
             encryptInfo.put("symKey", symKey);
             SecureRandom randomBitGenerator = new SecureRandom();
             byte [] IV = new byte [16];
             randomBitGenerator.nextBytes(IV);
             encryptInfo.put("IV", IV);

            Cipher algoPadder = Cipher.getInstance(symKey.getAlgorithm() + "/CBC/PKCS5Padding");
             algoPadder.init( Cipher.ENCRYPT_MODE, symKey, new IvParameterSpec( IV ) );
             SealedObject sealedInput = new SealedObject(plainTextInput, algoPadder);
             encryptInfo.put("cipher", algoPadder);

            FileOutputStream outputedEncryptedStream = new FileOutputStream(outputPATH); 
             BufferedOutputStream bufferEncryptedStream = new BufferedOutputStream(outputedEncryptedStream);
             CipherOutputStream cipherAppliedOnEncryptedStream = new CipherOutputStream(bufferEncryptedStream, algoPadder);
             
            ObjectOutputStream encryptedStreamObjectOutput = new ObjectOutputStream(cipherAppliedOnEncryptedStream);
             encryptedStreamObjectOutput.writeObject(sealedInput);
             encryptedStreamObjectOutput.close();

        }catch(NoSuchAlgorithmException e){}
        catch(NoSuchPaddingException f){}
        catch(InvalidAlgorithmParameterException g){}
        catch(InvalidKeyException h){}
        catch(IOException i){}
        catch(IllegalBlockSizeException j){}

        return encryptInfo;
    }

    public void backupDatabase(ArrayList<String> argList){ 
        // define processBuilderArguments 
        // pg_dump -Uffd --> static
        runDefinedProcess(
            defineProcess(new ArrayList<>(Arrays.asList(
                backup.get(0),"-U",backup.get(1),"-d",backup.get(2),"-F",backup.get(4),"-f",backup.get(3)
                    )
                )
            )
        ); 
    }
    public void restoreDatabase(ArrayList<String> argList){
        // define processBuilderArguments
        // psql -Udf --> static
        runDefinedProcess(
            defineProcess(new ArrayList<>(Arrays.asList(
                backup.get(0),"-U",backup.get(1),"-d",backup.get(2),"-f",backup.get(3)
                    )
                )
            )
        ); 
    }

    public static ProcessBuilder defineProcess(ArrayList<String> argumentList){
        ProcessBuilder builder = new ProcessBuilder(
            argumentList
        );
        return builder; 
    }

    public static void runDefinedProcess(ProcessBuilder builder){
        try {
            Process process = builder.start();

            BufferedReader errReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            String errLine;
            while ((errLine = errReader.readLine()) != null) {
                System.err.println(errLine);
            }

            BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream())); //new BufferedInputStream(new InputStreamReader(process.getInputStream()));
            String inputLine;
            while ((inputLine = inputReader.readLine()) != null){
                System.out.println(inputLine);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static DataSource databasePrelimTest(String selectedDatabase){
        String database = selectedDatabase;
        final String url = "jdbc:postgresql://localhost:888/"+database+"?user=postgres&password=mypassword";
        final PGSimpleDataSource dataSource = new PGSimpleDataSource();
        dataSource.setURL(url);

        return dataSource;
    }

    public static void setDefaultDBTemplate(DataSource instantiatedInstance, String query){
        try{
            Connection conn = instantiatedInstance.getConnection();

            PreparedStatement stmt = conn.prepareStatement(query);
    
            stmt.executeQuery();

        }catch(SQLException e){
            e.printStackTrace();   
        }
    }

    private String transformMapToDatabaseQuery(Map<String,Object> policy, String permissionsTemplate)throws Exception{
        
   		String content = new String(Files.readAllBytes(Paths.get(permissionsTemplate)));
        String modifiedContent = content.replace(
			"{UsernameColumn}", policy.get(USERNAMECOLUMN).toString()).replace(
				"{AccessKeyColumn}", policy.get(ACCESSKEYCOLUMN).toString()).replace(
					"{ResourceColumn}",policy.get(RESOURCECOLUMN).toString()).replace(
						"{TokenColumn}",policy.get(TOKENCOLUMN).toString()).replace(
							"{TimeStampColumn}",policy.get(TIMESTAMPCOLUMN).toString()).replace(
								"{SecretAccessKeyColumn}",policy.get(SECRETACCESSKEY).toString()).replace( 
                                    "{IdColumn}", String.valueOf(policy.get(IDCOLUMN)).replace(
                                        "{PermissionSetColumn}", policy.get(PERMISSIONLEVEL).toString()
                                    ));
                                    
        return modifiedContent;
    }

    public static void addNewValuessToDatabase(DataSource instantiatedInstace, String query){
        try{
            Connection conn = instantiatedInstace.getConnection();
            PreparedStatement stmt = conn.prepareStatement(query);

            stmt.executeUpdate();
        }catch(SQLException e){e.printStackTrace();};
    }
    public void editExistingKeysOnDatabase(){}

    public void queryKeysOnDatabase(){}

}
