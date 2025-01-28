import java.io.*;
import java.util.*;

public class DataBase {
    private Map<String, User> users;  // Liste des utilisateurs
    private Map<String, Map<String, String[]>> userPasswords;  // Stockage des mots de passe pour chaque utilisateur 
    private static final String FILE_NAME = "password_manager_data.txt";  // Fichier persistant

    public DataBase(String filename) {
        users = new HashMap<String,User>();
        userPasswords = new HashMap<String,Map<String,String[]>>();
        load(filename);  // Charger les utilisateurs depuis le fichier au démarrage
    }

    // Charger les utilisateurs depuis le fichier
    public void load(String filename) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            boolean isServiceSection = false;
    
            while ((line = reader.readLine()) != null) {
    
                if (line.equalsIgnoreCase("# Service Passwords")) {
                    isServiceSection = true;
                    continue;
                }

                if (line.trim().isEmpty() || line.startsWith("#")) continue;

                if (!isServiceSection) {
                    // Process user data
                    String[] data = line.split(" ; ");
                    if (data.length == 4) {
                        String username = data[0];
                        String masterPasswordHash = data[1];
                        String salt=data[2];
                        boolean is_admin=false;
                        if(data[3].equals("t")){
                            is_admin=true;
                        }
                        User user = new User(username, masterPasswordHash,salt, is_admin);
                        addUser(user);
                    } else {
                        System.err.println("Invalid user data format: " + line);
                    }
                } else {
                    // Process service passwords
                    String[] data = line.split(" ; ");
                    if (data.length == 4) {
                        String username = data[0];
                        String serviceName = data[1];
                        String infoIdService = data[2];
                        String encryptedPassword = data[3];
                        addUserInfo(username,serviceName,infoIdService,encryptedPassword);
                    } else {
                        System.err.println("Invalid service password format: " + line);
                    }
                }
            }
        } catch (IOException | NumberFormatException e) {
            System.err.println("Error while loading users: " + e.getMessage());
        }
    }
    
    // Sauvegarder tous les utilisateurs et mots de passe dans le fichier
    public void save(String filename) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
            // Save user data
            writer.write("# User Data");
            writer.newLine();
            for (User user : users.values()) {
                if(user.isAdmin()){
                    writer.write(user.getUsername() + " ; " + user.getPasswordHash()+" ; "+ user.getPasswordSalt() +" ; "+"t");
                }
                else{
                    writer.write(user.getUsername() + " ; " + user.getPasswordHash()+" ; "+ user.getPasswordSalt() +" ; "+"f");
                }
                writer.newLine();
            }
            writer.newLine();
    
            // Save service passwords
            writer.write("# Service Passwords");
            writer.newLine();
            for (Map.Entry<String, Map<String, String[]>> entry : userPasswords.entrySet()) {
                for(Map.Entry<String,String[]> userloginfos : entry.getValue().entrySet()){
                    writer.write(entry.getKey()+ " ; "+ userloginfos.getKey()+" ; "+userloginfos.getValue()[0]+" ; "+userloginfos.getValue()[1]);
                    writer.newLine();
                }
            }
        } catch (IOException e) {
            System.err.println("Error while saving users: " + e.getMessage());
        }
    }
    
    // Ajouter un utilisateur à la base de données
    public boolean addUser(User user) {
        if(!users.containsKey(user.getUsername())){
        users.put(user.getUsername(),user);
        userPasswords.put(user.username, new HashMap<String,String[]>());  // Créer un map vide pour les mots de passe
        return true;
        }
        return false;
    }

    public void deleteUser(User user){
        users.remove(user.getUsername());
        userPasswords.remove(user.getUsername());
    }
    public void deleteUser(String username){
        users.remove(username);
        userPasswords.remove(username);
    }
    public void deleteServiceCredentials(String userName,String servicename){
        Map<String, String[]> m= userPasswords.get(userName);
        m.remove(servicename);
        userPasswords.put(userName,m);
    }



    // Récupérer un utilisateur par son nom d'utilisateur
    public User getUserByUsername(String username) {
        return users.get(username);
    }

    public boolean userExists(String username){
        return users.containsKey(username);
    }

    // Ajouter un mot de passe pour un utilisateur donné
    public boolean addUserInfo(User user, String service, String logUsername, String encryptedPassword){
        Map<String, String[]> info = userPasswords.get(user.getUsername());
        if(info.containsKey(service)){
            return false;
        }
        if (encryptedPassword != null) {
            String[] logPair = {logUsername,encryptedPassword};
            info.put(service, logPair);
        }
        return true;
    }
    public void addUserInfo(String username, String service, String logUsername, String encryptedPassword){
        Map<String, String[]> info = userPasswords.get(username);
        if (encryptedPassword != null) {
            String[] logPair = {logUsername,encryptedPassword};
            info.put(service, logPair);
        }
        userPasswords.put(username, info);
    }

    public void deleteInfoUserService(User user,String service){
        Map<String, String[]> info = userPasswords.get(user.getUsername());
        info.remove(service);
    }

    // Récupérer les mots de passe d'un utilisateur
    public Map<String, String[]> getUserServicePasswordMap(String username) {
        return userPasswords.get(username);
    }

    // Obtenir tous les utilisateurs
    public Collection<User> getUserCollection() {
        return users.values();
    }

    public Collection<String> getUserNameCollection(){
        return userPasswords.keySet();
    }

    public Collection<String> getServiceUserCollection(User user){
        return userPasswords.get(user.getUsername()).keySet();
    }
    public Collection<String> getServiceUserCollection(String username){
        return userPasswords.get(username).keySet();
    }

    public String[] getCredentials(String username,String servicename){
        return userPasswords.get(username).get(servicename);
    }

    public String getPasswordHash(String username){
        return users.get(username).getPasswordHash();
    }

}