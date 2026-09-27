public with sharing class Safe {
    public static List<Account> find(String name) {
        return [SELECT Id FROM Account WHERE Name = :name WITH SECURITY_ENFORCED];
    }
}
