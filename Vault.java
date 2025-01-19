import java.util.HashMap;
import java.util.Set;

public class Vault {
    private HashMap<Integer, String> passwordStore;
    private int nextServiceId; // This will ensure unique IDs for each service

    public Vault() {
        this.passwordStore = new HashMap<>();
        this.nextServiceId = 1; // Start with ID 1
    }

    // Stocker un mot de passe pour un service
    public void storePassword(String encryptedPassword) {
        int serviceId = nextServiceId++; // Generate a unique service ID
        passwordStore.put(serviceId, encryptedPassword);
    }

    // Récupérer le mot de passe d'un service
    public String getPassword(int serviceId) {
        return passwordStore.getOrDefault(serviceId, null);
    }

    // Supprimer un mot de passe pour un service
    public void deletePassword(int serviceId) {
        passwordStore.remove(serviceId);
    }

    // Obtenir tous les identifiants de services enregistrés
    public Set<Integer> getAllServiceIds() {
        return passwordStore.keySet(); // Retourne l'ensemble des clés (serviceIds)
    }

    // Get the next service ID (for adding a new service)
    public int getNextServiceId() {
        return nextServiceId;
    }
}