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

public class PasswordManager {

    private static final String FILE_NAME = "password_manager_data.txt";
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_LENGTH = 16;
    private static final int HASH_ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;

    private Map<String, String> userAccounts = new HashMap<>();
    private Map<String, Map<Integer, String>> userPasswords = new HashMap<>();

    private Vault vault;
    private DataBase database;
    private LogInfo logInfo;
    private UserInput inputManager;

    public PasswordManager() {
        this.vault = new Vault();
        this.database = new DataBase();
        this.logInfo = new LogInfo();
        this.inputManager = new UserInput();
        loadData();  // Charger les données dès le démarrage
    }

    public void start() {
        System.out.println("Bienvenue dans le gestionnaire de mots de passe !");
        
        while (true) {
            System.out.println("\nMenu:");
            System.out.println("1. Créer un compte");
            System.out.println("2. Se connecter");
            System.out.println("3. Quitter");
    
            int choice = getIntInput("Votre choix : ");
            switch (choice) {
                case 1:
                    createAccount();
                    break;
                case 2:
                    loginAndPerformActions();
                    break;
                case 3:
                    saveData();
                    System.out.println("Au revoir !");
                    return;
                default:
                    System.out.println("Choix invalide. Veuillez réessayer.");
            }
        }
    }

    private void createAccount() {
        String username = getStringInput("Entrez un nom d'utilisateur : ");
        while (username.trim().isEmpty()) {
            System.out.println("Le nom d'utilisateur ne peut pas être vide.");
            username = getStringInput("Entrez un nom d'utilisateur : ");
        }

        String masterPassword;
        do {
            masterPassword = getStringInput("Entrez un mot de passe maître (min. 16 caractères) : ");
            if (masterPassword.length() < 16) {
                System.out.println("Le mot de passe maître doit contenir au moins 16 caractères.");
            }
        } while (masterPassword.length() < 16);

        try {
            // Générer un sel
            byte[] salt = generateSalt();
            String hashedPassword = hashPassword(masterPassword, salt);
            userAccounts.put(username, hashedPassword + ":" + Base64.getEncoder().encodeToString(salt));
            System.out.println("Compte créé avec succès !");
        } catch (Exception e) {
            System.err.println("Erreur lors de la création du compte : " + e.getMessage());
        }
    }

    private void loginAndPerformActions() {
        String username = getStringInput("Entrez votre nom d'utilisateur : ");
        if (!userAccounts.containsKey(username)) {
            System.out.println("Utilisateur introuvable. Veuillez créer un compte d'abord.");
            return;
        }

        String masterPassword = getStringInput("Entrez votre mot de passe maître : ");
        String storedData = userAccounts.get(username);
        String[] parts = storedData.split(":");
        String hashedPassword = parts[0];
        byte[] salt = Base64.getDecoder().decode(parts[1]);

        try {
            if (!verifyPassword(masterPassword, hashedPassword, salt)) {
                System.out.println("Mot de passe maître incorrect.");
                return;
            }
        } catch (Exception e) {
            System.err.println("Erreur lors de la vérification du mot de passe : " + e.getMessage());
            return;
        }

        System.out.println("Connexion réussie !");
        while (true) {
            System.out.println("\nActions disponibles :");
            System.out.println("1. Ajouter un identifiant pour un service");
            System.out.println("2. Afficher les identifiants et mots de passe");
            System.out.println("3. Se déconnecter");

            int choice = getIntInput("Votre choix : ");
            switch (choice) {
                case 1:
                    addService(username, masterPassword);
                    break;
                case 2:
                    displayServices(username, masterPassword);
                    break;
                case 3:
                    System.out.println("Déconnexion réussie !");
                    return;
                default:
                    System.out.println("Choix invalide. Veuillez réessayer.");
            }
        }
    }

    private void addService(String username, String masterPassword) {
        String serviceName = getStringInput("Nom du service (par ex. Netflix, Amazon) : ");
        String servicePassword = getStringInput("Mot de passe pour " + serviceName + " : ");

        try {
            String encryptedPassword = encrypt(servicePassword, masterPassword);
            userPasswords.computeIfAbsent(username, k -> new HashMap<>()).put(userPasswords.size() + 1, encryptedPassword);
            System.out.println("Identifiant pour " + serviceName + " ajouté avec succès !");
        } catch (Exception e) {
            System.err.println("Erreur lors du chiffrement du mot de passe : " + e.getMessage());
        }
    }

    private void displayServices(String username, String masterPassword) {
        Map<Integer, String> passwords = userPasswords.get(username);
        if (passwords == null || passwords.isEmpty()) {
            System.out.println("Aucun service enregistré pour cet utilisateur.");
            return;
        }

        passwords.forEach((id, encryptedPassword) -> {
            try {
                String decryptedPassword = decrypt(encryptedPassword, masterPassword);
                System.out.println("Service ID: " + id + ", Mot de passe : " + decryptedPassword);
            } catch (Exception e) {
                System.err.println("Erreur lors du déchiffrement : " + e.getMessage());
            }
        });
    }

    private String hashPassword(String password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
        byte[] hash = factory.generateSecret(spec).getEncoded();
        return Base64.getEncoder().encodeToString(hash);
    }

    private boolean verifyPassword(String password, String hashedPassword, byte[] salt) throws Exception {
        String computedHash = hashPassword(password, salt);
        return computedHash.equals(hashedPassword);
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private String getStringInput(String prompt) {
        System.out.print(prompt);
        Scanner scanner = new Scanner(System.in);
        return scanner.nextLine();
    }

    private int getIntInput(String prompt) {
        System.out.print(prompt);
        Scanner scanner = new Scanner(System.in);
        return scanner.nextInt();
    }

    private void loadData() {
        File file = new File(FILE_NAME);
        if (!file.exists()) {
            System.out.println("Aucun fichier de données trouvé. Un nouveau fichier sera créé lors de la sauvegarde.");
            return;
        }
    
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            boolean isServiceSection = false;
    
            while ((line = reader.readLine()) != null) {
                // Ignorer les lignes de commentaires ou vides
                if (line.startsWith("#") || line.trim().isEmpty()) continue;
    
                if (line.equalsIgnoreCase("# Section des mots de passe des services")) {
                    isServiceSection = true;
                    continue;
                }
    
                if (!isServiceSection) {
                    // Chargement des utilisateurs
                    String[] data = line.split(";");
                    if (data.length == 3) {
                        String username = data[0];
                        int userId = Integer.parseInt(data[1]);
                        String password = data[2];
                        User user = new User(userId, password, false, username, true);
                        database.addUser(user);
                    } else {
                        System.err.println("Ligne utilisateur mal formée : " + line);
                    }
                } else {
                    // Chargement des services
                    String[] data = line.split(";");
                    if (data.length == 4) {
                        String username = data[0];
                        int serviceId = Integer.parseInt(data[1]);
                        String encryptedPassword = data[3];
    
                        User user = database.getUserByUsername(username);
                        if (user != null) {
                            database.addPasswordForUser(username, serviceId, encryptedPassword);
                        }
                    } else {
                        System.err.println("Ligne service mal formée : " + line);
                    }
                }
            }
        } catch (IOException | NumberFormatException e) {
            System.err.println("Erreur lors du chargement des données : " + e.getMessage());
        }
    }

    private void saveData() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(FILE_NAME, false))) {  // false pour écraser le fichier à chaque sauvegarde
            // Sauvegarde des utilisateurs
            writer.write("# Section des utilisateurs");
            writer.newLine();
            for (User user : database.getAllUsers()) {
                writer.write(user.getUsername() + ";" + user.getUserId() + ";" + user.getPassword());
                writer.newLine();
            }
            writer.newLine();
        
            // Sauvegarde des mots de passe des services
            writer.write("# Section des mots de passe des services");
            writer.newLine();
            for (Map.Entry<String, Map<Integer, String>> entry : database.getAllPasswords().entrySet()) {
                String username = entry.getKey();
                for (Map.Entry<Integer, String> passwordEntry : entry.getValue().entrySet()) {
                    writer.write(username + ";" + passwordEntry.getKey() + ";" + passwordEntry.getValue());
                    writer.newLine();
                }
            }
            writer.newLine();
        } catch (IOException e) {
            System.err.println("Erreur lors de la sauvegarde des données : " + e.getMessage());
        }
    }
    

    private String encrypt(String data, String password) throws Exception {
        byte[] keyBytes = Arrays.copyOf(password.getBytes(StandardCharsets.UTF_8), 16); // Clé de 128 bits (16 octets)
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
    
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    private String decrypt(String encrywiptedData, String password) throws Exception {
        byte[] keyBytes = Arrays.copyOf(password.getBytes(StandardCharsets.UTF_8), 16); // Clé de 128 bits (16 octets)
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");
    
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
    
        byte[] decryptedBytes = cipher.doFinal(decodedData);
    
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public static void main(String[] args) {
        PasswordManager pm = new PasswordManager();
        pm.start();
    }
}
