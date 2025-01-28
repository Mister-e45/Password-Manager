import java.util.Scanner;

public class UserInput {
    private Scanner scanner;

    // Constructeur
    public UserInput() {
        scanner = new Scanner(System.in);
    }

    public String getStringInput(String prompt) {
        System.out.print(prompt);
        return scanner.nextLine();
    }

    public int getIntInput(String prompt) {
        System.out.print(prompt);
        return scanner.nextInt();
    }
}