public class User {
    public int id;            // Identifiant unique de l'utilisateur
    public String username;   // Nom d'utilisateur
    private String password;  // Mot de passe (privé)
    public boolean isAdmin;   // Indique si l'utilisateur est un administrateur
    public boolean isActive;


    // Constructeur
    public User(int id, String password, boolean isAdmin, String username, boolean isActive) {
        this.id = id;
        this.password = password;
        this.isAdmin = isAdmin;
        this.username = username;
        this.isActive = isActive;
    }
    

    // Getter pour le mot de passe (au cas où cela serait nécessaire)
    public String getPassword() {
        return password;
    }

    // Setter pour mettre à jour le mot de passe
    public void setPassword(String newPassword) {
        this.password = newPassword;
    }
    

    // Méthode pour récupérer l'identifiant de l'utilisateur
    public int getUserId() {
        return id;
    }

    // Méthode pour récupérer le nom d'utilisateur
    public String getUsername() {
        return username;
    }

    public boolean isActive() {
        return isActive; // Retourne si l'utilisateur est actif
    }

    // Affichage des informations de l'utilisateur (sauf le mot de passe)
    @Override
    public String toString() {
        return "ID: " + id + ", Nom: " + username + ", Admin: " + isAdmin;
    }
}