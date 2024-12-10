import java.util.*;
import java.security.*;

public class DataBase{

    DataBase(){
        users = new TreeMap<String,User>();
        information = new TreeMap<String,TreeMap<String,LogInfo>>();
    }

    public void addUser(String userName, String mdp){
        User user= new User();
        users.put(userName,user);
    }

    public void save(String filePath,byte[] key){
        
    }

    public void load(String filePath,byte[] key){

    }

    public void addInfo(String userName,LogInfo info){
        information.get(userName).put(userName,info);
    }

TreeMap<String,User> users;
TreeMap<String,TreeMap<String,LogInfo> > information;

}