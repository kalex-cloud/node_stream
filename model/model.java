package io.nodestream.identity.model;

public class model {

    public void generateTemporaryCredentials(String userKey, String userSecretKey){
        // validate credentials for authorization 
        // combine key and secret keys into a one-way hash
        // store hash in database (edit existing keys)
            // "userKey","userSecretKey","hash","timeStamp"
        // return temporary credentials 
    }
    public void validateAuthorization(){
        // queryKeysOnDatabase
        // transformDatabaseQuery
        // analyze key:value pairs for authorization
        // return yes||no
    }
    public void generateCredentialKeys(){
        // validateAuthorization of calling accouunt
        // if yes - add new keys; else return no
        // return key and secret keys
    }
    public void revokeCredentialKeys(){}
    public void editCredentialDocument(){
        // validate authorization of calling account
        // if yes - edit existing keys
        // return success
    }
    
    // generate credential keys - generate pub/priv keys
    // generate root keys pub/priv keys (*:*)
    // remove keys
    
    // edit credentials - add new row  
}

// 220 + 100 + 70 + 100