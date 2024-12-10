public class User {
    
    boolean isAdmin=false;
    String Username;
    int id;
    String mdp;

    public User(int identifier, String pwd, boolean isAd, String nom){
        identifier=id;
        pwd=mdp;
        isAd=isAdmin;
        nom=Username;
    }
    

    public void Update(int new_id, String new_mdp, String new_Username, boolean status) {
        if (id!=new_id){
            id=new_id;
        } 
        if (mdp!=new_mdp){
            id=new_id;
        } 
        if (isAdmin!=status){
            isAdmin = true;
        } 
        if (Username!=new_Username){
            Username=new_Username;
        }
      
    }
 

};