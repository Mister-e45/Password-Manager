import javax.xml.crypto.Data;

public class Vault{

    Vault(){
        dataBase = new DataBase();
    }

    public boolean open(String userName,String mdp){
        /*on lit dans le fichier contenant les comptes utilisateurs ... */
        return false;
    }

    public LogInfo getLogin(String account){
        LogInfo logs = new LogInfo();
        /* on fait des choses */
        return logs;
    }

    public boolean close(){

    }
    

    DataBase dataBase;
    String currentAuthUSer;
    boolean authenticated;

}