public class User {
    public String username;   // Nom d'utilisateur
    private String passwordHash;  // Mot de passe (privé)
    public boolean isAdmin;   // Indique si l'utilisateur est un administrateur
    


    // Constructeur
    public User( String username_,String password_hash, boolean isAdmin_) {
        passwordHash = password_hash;
        isAdmin = isAdmin_;
        username = username_;
        
    }
    

    // Getter pour le hashé du mot de passe (au cas où cela serait nécessaire)
    public String getPasswordHash() {
        return passwordHash;
    }

    // Setter pour mettre à jour le mot de passe
    public void setPasswordHash(String newPasswordHash) { // recuperer le hashe du mot de passe
        passwordHash = newPasswordHash;
    }
    
/* 
    // Méthode pour récupérer l'identifiant de l'utilisateur
    public int getUserId() {
        return id;
    }
*/
    // Méthode pour récupérer le nom d'utilisateur
    public String getUsername() {
        return username;
    }

    public boolean isAdmin(){
        return isAdmin;
    }

    // Affichage des informations de l'utilisateur (sauf le mot de passe)
    @Override
    public String toString() {
        return "Nom: " + username + ", Admin: " + isAdmin;
    }
}