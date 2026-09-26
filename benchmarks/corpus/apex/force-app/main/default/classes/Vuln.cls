public class Vuln {
    public static List<Account> find(String name) {
        return Database.query('SELECT Id FROM Account WHERE Name = \'' + name + '\'');
    }
    public static void del(Id i) {
        delete [SELECT Id FROM Contact WHERE Id = :i];
    }
    public PageReference go() {
        return new PageReference(ApexPages.currentPage().getParameters().get('url'));
    }
    public static String hash(String s) {
        Blob key = Blob.valueOf('hardcodedkey1234');
        return EncodingUtil.base64Encode(Crypto.encryptWithManagedIV('AES128', key, Blob.valueOf(s)));
    }
}
