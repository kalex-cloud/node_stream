package io.nodestream.identity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.nodestream.identity.model.databaseModel;
import io.nodestream.identity.model.credentialModel;
import io.nodestream.identity.model.RSAKeyPairPerform;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.sql.DataSource;

import io.nodestream.identity.model.plumbing;

@SpringBootApplication
public class IdentityApplication {
public static final Path SQL_QUERY_FILE_PATH = Paths.get("SqlFolder", "productQuery.sql");
	public static void main(String[] args) throws Exception{
		SpringApplication.run(IdentityApplication.class, args);

//		credentialModel gak = new credentialModel();
		//RSAKeyPairPerform gakk = new RSAKeyPairPerform();

		//String encryptedBase64 = gakk.encryptTokenDataAsymmetricKey();
		//String decryptedBase64 = gakk.decryptTokenDataAsymmetricKey(encryptedBase64);


		//String encryptText = gakk.encryptDataSymmetricKey("doesntmatterfornow", "asdf is fun");
		//System.out.println(gakk.encryptDataSymmetricKey("doesntmatterfornow", "oencryption is fun"));
		//System.out.println(gakk.decryptDataSymmetricKey(encryptText));

		//String encryptedTextRSA = gakk.encryptTokenDataAsymmetricKey();
		//gakk.decryptTokenDataAsymmetricKey(encryptedTextRSA);


		//System.out.println(gakk.testUsingSymmetricKeyAfterRSADecryption(decryptedBase64));

		//gak.getRSAKeyPair("/home/kevin/Documents/rsa/");
		//gak.generateAESTokenData("/home/kevin/Documents/rsa/pubkey.key");
		
		//gakk.generateAESSymmetricKey("/home/kevin/Documents/rsa");
        //gakk.generateRSAAsymmetricKeys("/home/kevin/Documents/rsa");	

		IdentityApplication test = new IdentityApplication();
		test.everything();
	
//
////		IdentityApplication getDatabase = new IdentityApplication();


//		getDatabase.createDatabase();
//		getDatabase.createTablesOnDatabase();

////		databaseModel iampolicy = new databaseModel();		
////		String policyObject = iampolicy.transformJSONDocumentFromFile("/home/kevin/Documents/code_base/nodeStream/nodeStreamIdentity/identity/src/main/resources/databaseOps/iam.json");
////		getDatabase.addNewRowDataOnTable(policyObject, permissionsTemplatePath, "nodestream_core", iampolicy);
//
		//System.out.println(iampolicy.readPolicyDocument(policyObject));


//String jsonString = "{\"UsernameColumn\":\"amIRunningnotfromFile\",\"AccessKeyColumn\":\"AKIAEXAMPLE1234567890\",\"ResourceColumn\":\"/home/kevin/Documents/code_base/nodestreamIdentity\",\"TokenColumn\":\"A234567890\",\"TimeStampColumn\":\"2025-04-24T18:02:25.123+00:00\",\"IdColumn\":134,\"SecretAccessKeyColumn\":\"AKIAEXAMPvAKIAEXAMPLE1234567890\"}";
//getDatabase.addNewRowDataOnTable(jsonString, permissionsTemplatePath, "nodestream_core", iampolicy);

//		System.out.println(iampolicy.readPolicyDocument(json));
}
	
	public void everything()throws Exception{
		plumbing test = new plumbing();
		test.theEverythingfunction();
	}




	public void keyGen()throws Exception{
		// all the asym key stuff
		credentialModel gak = new credentialModel();
		gak.getRSAKeyPair("/home/kevin/Documents/rsa/");
		String encryptedText = gak.encryptDataAsymmetric("This is my encrypted STRIjjjjjNG2");
		System.out.println("Here is the encrypted message: " + encryptedText);
		System.out.println("Here is the decrypted message: " + gak.decryptDataAsymmetric(encryptedText));

		// all the access key stuff
		String Accesskey = gak.generateAccessKey();
		String SecretAccessKey = gak.generateSecretAccessKey();
		System.out.println(Accesskey);
		System.out.println(SecretAccessKey);
	}
	public void createDatabase() throws Exception{
		DataSource dbDataSource = databaseModel.databasePrelimTest("postgres");
		String content = new String(Files.readAllBytes(Paths.get("/home/kevin/Documents/code_base/nodeStream/nodeStreamIdentity/identity/src/main/resources/databaseOps/create_database.sql")));
		databaseModel.setDefaultDBTemplate(dbDataSource, content);
	}
	public void createTablesOnDatabase() throws Exception{
		DataSource dbDataSource = databaseModel.databasePrelimTest("nodestream_core");
		String content = new String(Files.readAllBytes(Paths.get("/home/kevin/Documents/code_base/nodeStream/nodeStreamIdentity/identity/src/main/resources/databaseOps/create_tables.sql")));
		databaseModel.setDefaultDBTemplate(dbDataSource, content);
	}
	public void addNewRowDataOnTable(String policy, String pathToPermissionsTemplate, String databaseName, databaseModel db) throws Exception{
		db.writePolicyDocumentToDatabase(policy, pathToPermissionsTemplate, databaseName);
	}

	public void notes(){

//		ArrayList<String> CLIArguments = new ArrayList<>();
//		 CLIArguments.add("ping");
//		 CLIArguments.add("1.1.1.10000");
//		 CLIArguments.add("-c");
//		 CLIArguments.add("1");
//
//		ProcessBuilder definedProcess = databaseModel.defineProcess(CLIArguments);
//		databaseModel.runDefinedProcess(definedProcess);

//		DataSource dbDataSource = databaseModel.databasePrelimTest("nodestream_core");
//		String content = new String(Files.readAllBytes(Paths.get("/home/kevin/Documents/code_base/nodeStream/nodeStreamIdentity/identity/src/main/resources/databaseOps/add_permissions.sql")));
//		int x = 4;
//		String modifiedContent = content.replace(
//			"{UsernameColumn}","test1").replace(
//				"{AccessKeyColumn}","test2").replace(
//					"{ResourceColumn}","/home/kevin").replace(
//						"{TokenColumn}","test5").replace(
//							"{TimeStampColumn}","ssf").replace(
//								"{SecretAccessKeyColumn}","werqwer");
//		databaseModel.addNewValuessToDatabase(dbDataSource, modifiedContent);
		// writePolicyDocumentToDatabase(content);
	}
}
