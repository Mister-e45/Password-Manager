import java.io.*;
import java.util.*;

public class DataBase {
    private ArrayList<User> users;  // Liste des utilisateurs
    private Map<String, Map<Integer, String>> userPasswords;  // Stockage des mots de passe pour chaque utilisateur

    private static final String FILE_NAME = "password_manager_data.txt";  // Fichier persistant

    public DataBase() {
        this.users = new ArrayList<>();
        this.userPasswords = new HashMap<>();
        loadUsers();  // Charger les utilisateurs depuis le fichier au démarrage
    }

    // Charger les utilisateurs depuis le fichier
    private void loadUsers() {
        try (BufferedReader reader = new BufferedReader(new FileReader(FILE_NAME))) {
            String line;
            boolean isServiceSection = false;
    
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty() || line.startsWith("#")) continue;
    
                if (line.equalsIgnoreCase("# Service Passwords")) {
                    isServiceSection = true;
                    continue;
                }
    
                if (!isServiceSection) {
                    // Process user data
                    String[] data = line.split(";");
                    if (data.length == 4) {
                        String username = data[0];
                        String masterPassword = data[1];
                        boolean isActive = Boolean.parseBoolean(data[2]);
                        int id = Integer.parseInt(data[3]);
                        User user = new User(id, masterPassword, false, username, isActive);
                        addUser(user);
                    } else {
                        System.err.println("Invalid user data format: " + line);
                    }
                } else {
                    // Process service passwords
                    String[] data = line.split(";");
                    if (data.length == 3) {
                        String username = data[0];
                        int serviceId = Integer.parseInt(data[1]);
                        String password = data[2];
                        addPasswordForUser(username, serviceId, password);
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
    public void saveUsers() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(FILE_NAME))) {
            // Save user data
            writer.write("# User Data");
            writer.newLine();
            for (User user : users) {
                writer.write(user.username + ";" + user.getPassword() + ";" + user.isActive() + ";" + user.id);
                writer.newLine();
            }
    
            // Save service passwords
            writer.write("# Service Passwords");
            writer.newLine();
            for (User user : users) {
                Map<Integer, String> passwords = userPasswords.get(user.username);
                if (passwords != null) {
                    for (Map.Entry<Integer, String> entry : passwords.entrySet()) {
                        writer.write(user.username + ";" + entry.getKey() + ";" + entry.getValue());
                        writer.newLine();
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("Error while saving users: " + e.getMessage());
        }
    }
    
    // Ajouter un utilisateur à la base de données
    public void addUser(User user) {
        users.add(user);
        userPasswords.put(user.username, new HashMap<>());  // Créer un map vide pour les mots de passe
    }

    // Récupérer un utilisateur par ID
    public User getUserById(int id) {
        for (User user : users) {
            if (user.id == id) {
                return user;
            }
        }
        return null;
    }

    // Récupérer un utilisateur par son nom d'utilisateur
    public User getUserByUsername(String username) {
        for (User user : users) {
            if (user.username.equals(username)) {
                return user;
            }
        }
        return null;
    }

    // Ajouter un mot de passe pour un utilisateur donné
    public void addPasswordForUser(String username, int serviceId, String password) {
        Map<Integer, String> passwords = userPasswords.get(username);
        if (passwords != null) {
            passwords.put(serviceId, password);
        }
    }

    // Récupérer les mots de passe d'un utilisateur
    public Map<Integer, String> getPasswordsForUser(String username) {
        return userPasswords.get(username);
    }

    // Obtenir tous les utilisateurs
    public ArrayList<User> getAllUsers() {
        return users;
    }
    // Obtenir tous les mots de passe des services pour tous les utilisateurs
    public Map<String, Map<Integer, String>> getAllPasswords() {
        return userPasswords;  // Retourne le map contenant tous les mots de passe des utilisateurs
    }
}