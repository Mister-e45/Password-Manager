import java.util.*;

public class PasswordManager {

    private static final String FILE_NAME = "password_manager_data.txt";
    


    private Vault vault;
    private LogInfo logInfo;
    private UserInput userinput;
    
    public PasswordManager(){
        vault = new Vault(FILE_NAME);
        userinput = new UserInput();
        logInfo = new LogInfo();
        
    }

    public void start() {
        System.out.println("Bienvenue dans PasswordManager !");
        
        while (true) {
            System.out.println("\nMenu:");
            System.out.println("1. Créer un compte");
            System.out.println("2. Se connecter");
            System.out.println("3. Quitter");
    
            String choice = userinput.getStringInput("Votre choix : ");
            switch (choice) {
                case "1":
                    createAccount();
                    break;
                case "2":
                    loginAndPerformActions();
                    break;
                case "3":
                    saveData();
                    System.out.println("Au revoir !");
                    return;
                default:
                    System.out.println("Choix invalide. Veuillez réessayer.");
            }
        }
    }

    private void createAccount() {
        String username = userinput.getStringInput("Entrez un nom d'utilisateur : ");
        while (username.trim().isEmpty() || vault.userExists(username)) {
            if (username.equals("R")){
                return;
            } 
            if (vault.userExists(username)) {
                System.out.println("Ce nom d'utilisateur existe déjà. Veuillez en choisir un autre ou retouner (R).");

            } else {
                System.out.println("Le nom d'utilisateur ne peut pas être vide.");
            }
            username = userinput.getStringInput("Entrez un nom d'utilisateur : ");
        }
        
        String masterPassword;

        masterPassword = userinput.getStringInput("Entrez un mot de passe maître (min. 16 caractères) : ");    
        while (masterPassword.length() < 16){
           
          
            System.out.println("Le mot de passe maître doit contenir au moins 16 caractères. Veuillez reéssayer ou quitter (Q)");
            masterPassword = userinput.getStringInput("Entrez un mot de passe maître (min. 16 caractères) :");

            if (masterPassword.equals("Q")){
                return;
            } 

            masterPassword = userinput.getStringInput("Entrez un mot de passe maître (min. 16 caractères) : ");
        } 
        
        // Détection du rôle utilisateur/administrateur
        boolean isAdmin = false;
        String roleChoice = userinput.getStringInput("Voulez-vous créer un compte administrateur ? (oui/non) : ").trim().toLowerCase();
    
        if (roleChoice.equals("oui")) {
            String adminCode = userinput.getStringInput("Entrez le code secret pour administrateur : ");
            if (!adminCode.equals("groupe hp")) {
                System.out.println("Code secret invalide. Création d'un compte utilisateur classique.");
            } else {
                isAdmin = true;
            }
        }
    
        try {
            vault.addUser(username, masterPassword, isAdmin);
            
            System.out.println("Compte créé avec succès !");
            System.out.println(vault.getUserByName(username).toString()); // Afficher les détails de l'utilisateur (sans mot de passe)
        } catch (Exception e) {
            System.err.println("Erreur lors de la création du compte : " + e.getMessage());
        }

    }
    

    private void loginAndPerformActions() {
        String username = userinput.getStringInput("Entrez votre nom d'utilisateur : ");
        if (!vault.userExists(username)) {
            System.out.println("Utilisateur introuvable. Veuillez créer un compte d'abord.");
            return;
        }
    
        String masterPassword = userinput.getStringInput("Entrez votre mot de passe maître : ");
        //String storedData = userAccounts.get(username);
    
        boolean success=vault.logUser(username, masterPassword);
    
        
        if (!success) {
            System.out.println("Mot de passe maître incorrect.");
            return;
        }
    
        System.out.println("Connexion réussie !");
        User loggedInUser = vault.getLoggedUser();
        
    
        while (true) {
            if (loggedInUser.isAdmin()) {
                showAdminMenu(); // Afficher le menu spécifique à l'administrateur
            } else {
                showUserMenu(); // Afficher le menu classique pour l'utilisateur
            }
    
            String choice = userinput.getStringInput("Votre choix : ");
            String serviceName=null;
            switch (choice) {
                case "1":
                    addService(username);
                    break;
                case "2":
                    displayServices(username);
                    break;

                case "3":
                    serviceName = userinput.getStringInput("Entrez le nom du service à afficher : ").trim();
                    displayServiceCredentials(username, serviceName);
                    break;
                
                case "4":
                    serviceName = userinput.getStringInput("Entrez le nom du service à afficher : ").trim();
                    vault.deleteLoggedUserService(serviceName);
                    break;

                case "5":
                    if (loggedInUser.isAdmin()) {
                        String userToDelete = userinput.getStringInput("Entrez le nom d'utilisateur à supprimer : ");
                        vault.deleteUser(userToDelete);
                    }
                    break;
                case "6":
                    if (loggedInUser.isAdmin()) {
                        Collection<String> UserList = vault.getAllUserNames(); // Afficher tout les utilisateurs 
                        for(String u: UserList) { 
                            System.err.println(u);
                        }
                    }
                    break; 
                   
                case "q":
                    System.out.println("Déconnexion réussie !");
                    return; 
                    
                default:
                    System.out.println("Choix invalide. Veuillez réessayer.");
            }
        }
    }
    
    // Afficher le menu pour les utilisateurs classiques
    private void showUserMenu() {
        System.out.println("\nActions disponibles :");
        System.out.println("1. Ajouter une information de connexion pour un service");
        System.out.println("2. Afficher les identifiants et mots de passe de tout les services");
        System.out.println("3. Afficher l'identifiant et le mot de passe d'un service en particulier");
        System.out.println("4. Supprimer un service en particulier");
        System.out.println("q. Se déconnecter");
    }
    
    // Afficher le menu pour les administrateurs
    private void showAdminMenu() {
        System.out.println("\nActions disponibles :");
        System.out.println("1. Ajouter une information de connexion pour un service");
        System.out.println("2. Afficher les identifiants et mots de passe de tout les services");
        System.out.println("3. Afficher l'identifiant et le mot de passe d'un service en particulier");
        System.out.println("4. Supprimer un service en particulier"); 
        System.out.println("5. Supprimer un utilisateur");
        System.out.println("6. Afficher tout les utilisateurs");
        System.out.println("q. Se déconnecter");
        
        
    }
    
    // Désactiver un utilisateur
    public void deactivateUser(String username) {
        
    }
    
    
    // Afficher les logs des actions
    public void displayLogs() {
        logInfo.displayLogs(); // LogInfo est l'objet gérant les logs des actions
    }
    


    private void addService(String username) {
        String serviceName = userinput.getStringInput("Nom du service (par ex. Netflix, Amazon) : ").trim();
        String serviceUsername = userinput.getStringInput("Nom d'utilisateur pour " + serviceName + " : ").trim();
        String choix = userinput.getStringInput("Générer ou saisir un mot de passe (G/S): ");
        String servicePassword;

        if (choix.equals("S")){
            servicePassword = userinput.getStringInput("Mot de passe pour " + serviceName + " : ").trim();

        }else{
            int length = Integer.valueOf(userinput.getStringInput("Longueur du mot de passe: ").trim());
            servicePassword = vault.generatePassword(length);
        }

        
        if (serviceName.isEmpty() || serviceUsername.isEmpty() || servicePassword.isEmpty()) {
            System.err.println("Tous les champs doivent être remplis !");
            return;
        }
    
        try {
            boolean succes= vault.addLoggedUserInfo(serviceName, serviceUsername, servicePassword);
            if (!succes) {
                System.err.println("Service non ajouté, peut être que ce service existe déjà pour cet utilisateur");
            } else {
                System.out.println("Identifiant pour " + serviceName + " ajouté avec succès !");
            }
        } catch (Exception e) {
            System.err.println("Erreur lors du chiffrement du mot de passe : " + e.getMessage());
        }
    }
    
    

    private void displayServices(String username) {
        Collection<String> serviceCollection=vault.getLoggedUserServiceCollection();
        if (serviceCollection.isEmpty()) {
            System.out.println("Aucun service enregistré pour cet utilisateur.");
            return;
        }
    
        System.out.println("Services enregistrés pour l'utilisateur : " + username);
        serviceCollection.forEach(serviceName -> {
            try {
                String[] credentials = vault.getLoggedUserServiceCredentials(serviceName);
    
                System.out.println("Service : " + serviceName);
                System.out.println("  Nom d'utilisateur : " + credentials[0]);
                System.out.println("  Mot de passe : " + credentials[1]);
            } catch (Exception e) {
                System.err.println("Erreur lors du déchiffrement pour le service " + serviceName + " : " + e.getMessage());
            }
        });
    }
    


    private void displayServiceCredentials(String username, String serviceName) {
        // Vérifier si l'utilisateur existe
        
        Collection<String> services = vault.getLoggedUserServiceCollection();
        if (services.isEmpty()) {
            System.out.println("Aucun service enregistré pour cet utilisateur.");
            return;
        }
    
        // Vérifier si le service existe pour cet utilisateur
    
        if (!services.contains(serviceName)) {
            System.out.println("Le service '" + serviceName + "' n'existe pas pour cet utilisateur.");
            return;
        }
    
        // Déchiffrer et afficher les informations du service
        try {
            String[] credentials = vault.getLoggedUserServiceCredentials(serviceName);
    
            System.out.println("Informations pour le service : " + serviceName);
            System.out.println("  Nom d'utilisateur : " + credentials[0]);
            System.out.println("  Mot de passe : " + credentials[1]);
        } catch (Exception e) {
            System.err.println("Erreur lors du déchiffrement : " + e.getMessage());
        }
    }
    

    
    private void saveData() {
        vault.save(FILE_NAME);
    }
    

    public static void main(String[] args) {
        PasswordManager pm = new PasswordManager();
        pm.start();
    }
}
