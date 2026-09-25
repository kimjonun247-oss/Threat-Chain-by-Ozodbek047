// Sun'iy namuna: Apex qamrovini (PMD) ko'rsatish uchun qasddan zaif yozilgan.
// Ishga tushirish yoki deploy qilish uchun emas. Tafsilot: samples/chain-demo/README.md
public class AccountController {
    // ApexOpenRedirect: foydalanuvchi bergan manzilga tekshiruvsiz yo'naltirish
    public PageReference goNext() {
        String target = ApexPages.currentPage().getParameters().get('next');
        return new PageReference(target);
    }

    // ApexSOQLInjection: tekshirilmagan qiymat dinamik so'rovga qo'shiladi
    public List<Account> findByName(String name) {
        return Database.query('SELECT Id FROM Account WHERE Name = \'' + name + '\'');
    }
    // ApexSharingViolations: sharing modeli e'lon qilinmagan (klass sarlavhasi)
}
