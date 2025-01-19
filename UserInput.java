import java.util.Scanner;

public class UserInput {
    private Scanner scanner;

    // Constructeur
    public UserInput() {
        this.scanner = new Scanner(System.in);
    }

    // Méthode pour obtenir une chaîne de caractères de l'utilisateur
    public String getStringInput(String prompt) {
        System.out.print(prompt);
        return scanner.nextLine();
    }

    // Méthode pour obtenir un entier de l'utilisateur
    public int getIntInput(String prompt) {
        System.out.print(prompt);
        while (!scanner.hasNextInt()) {
            System.out.println("Veuillez entrer un entier valide.");
            scanner.next(); // Nettoyer l'entrée non valide
        }
        return scanner.nextInt();
    }

    // Méthode pour obtenir une valeur booléenne (true/false)
    public boolean getBooleanInput(String prompt) {
        System.out.print(prompt + " (true/false): ");
        while (!scanner.hasNextBoolean()) {
            System.out.println("Veuillez entrer true ou false.");
            scanner.next(); // Nettoyer l'entrée non valide
        }
        return scanner.nextBoolean();
    }
}