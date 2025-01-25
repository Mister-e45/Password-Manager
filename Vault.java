import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.*;


public class Vault {
    private DataBase database;
    private User logedUser;
    SecretKeySpec secretKey;


    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_LENGTH = 16;
    private static final int HASH_ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;



    public Vault(String filename) {
        database= new DataBase(filename);
        logedUser=null;
        secretKey=null;
    }
    //////////////////////////////////////////////////////////////////////////////////////
    
    
    
    public boolean logUser(String username, String password){
        // check is user exists then hash the password and compare with what is in the database
        byte[] keyBytes = Arrays.copyOf(password.getBytes(StandardCharsets.UTF_8), 16); // Clé de 128 bits (16 octets)
        secretKey = new SecretKeySpec(keyBytes, "AES");
     
        User user=database.getUserByUsername(username);
        if(user==null){
            return false;
        }
        
        byte[] salt = Base64.getDecoder().decode( user.getPasswordSalt() );
        
        try{
            String hashedpassword = hashPassword(password, salt);
            if (!hashedpassword.equals(database.getPasswordHash(username))){
                System.out.println("Le mot de passe de '" + username + "' est incorrect.");
                return false;
            }
        
            logedUser = user;
            return true;
        }catch(Exception e){
            System.out.println(e.getMessage());
        }
        return false;
        
    }
    
    
    
    public void addUser(String username, String password, boolean admin){
        byte[] salt = generateSalt();
        String string_salt= Base64.getEncoder().encodeToString(salt);
        String hashedPassword = null ;
        try{
        hashedPassword = hashPassword(password, salt);
        }catch(Exception e){
            System.out.println(e.getMessage());
        }
        User user = new User(username, hashedPassword,string_salt, admin);
        database.addUser(user);
    
    }    
    
    public User getUserByName(String username){
        return database.getUserByUsername(username);
    }
    
    
    
     public void deleteUser(String username){
        User user=database.getUserByUsername(username);
        database.deleteUser(user);
     }
      
     public void save(String filename){
        database.save(filename);
    }    
    
    
    
    
    public void load(String filename){
        database.load(filename);
    }    
    
    public boolean addLoggedUserInfo(String service,String username,String password){
        try{
            String encryptedUsername=encrypt(username);
            String encryptedPassword = encrypt(password);
            return database.addUserInfo(logedUser, service, encryptedUsername, encryptedPassword);
        }catch(Exception e){
            System.out.println(e.getMessage());
        }
        return false;
        
    }

    public boolean userExists(String username){
        return database.userExists(username);
    }

    public Collection<String> getLoggedUserServiceCollection(){
        return database.getServiceUserCollection(logedUser);
    }

    public String[] getLoggedUserServiceCredentials(String servicename){
        String[] credentials= database.getCredentials(logedUser.getUsername(), servicename);
        String plainPassword=null;
        String plainUsername=null;
        try{
            plainPassword= decrypt(credentials[1]);
            plainUsername= decrypt(credentials[0]);

        }catch(Exception e){
            System.out.println(e.getMessage());
        }
        String[] output = {plainUsername,plainPassword};
        return output;
    }

    public User getLoggedUser(){
        return logedUser;
    }
    
    
    
    private String encrypt(String data) throws Exception {
        
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(pad(data,16).getBytes(StandardCharsets.UTF_8));
    
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    
    public String decrypt(String encryptedData) throws Exception {
    
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
    
        byte[] decryptedBytes = cipher.doFinal(decodedData);
    
        return unpad(new String(decryptedBytes, StandardCharsets.UTF_8));
    }

    private String pad(String input,int multipleOf){ 
        int length=input.getBytes(StandardCharsets.UTF_8).length;

        int remainder=length%multipleOf;
        int padlength=0;
        if(remainder!=0){
            padlength=16-remainder;
        }
        
        StringBuilder res = new StringBuilder(input);
        for(int i=0; i< padlength; i++){
            res.append('\0');
        }

        return res.toString();
    }

    private String unpad(String input){ //l'utilisateur ne rentre que des caractère imprimable on peut donc retirer les zeros sans craindre qu'ils n'étaient dans le message
        StringBuilder res= new StringBuilder(input);
        while(res.charAt(res.length()-1)=='\0'){
            res.deleteCharAt(res.length()-1);
        }
        return res.toString();
    }
    
    private String hashPassword(String password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
        byte[] hash = factory.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(hash);
    }
    
    
    private byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

   

    public String generatePassword(int length) {
        String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!?@#$%^&*()_+-,:";
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            password.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }

        return password.toString();
    }

    
    ////////////////////////////////////////////////////////////////////////////////////////////
    
}
