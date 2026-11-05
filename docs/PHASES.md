# Faz Planı

Her faz sonunda onay alınmadan sonraki faza geçilmez.

| Faz | Kapsam | Risk | Durum |
|---|---|---|---|
| 1 | MSSQL envanter okuma, ortam eşleme (DEV/TEST/QA/PROD), dinamik grup, keşif raporu. Hedeflere bağlanmaz. | Yok (salt okunur) | Tamamlandı (63 satır, Type değerleri doğrulandı). Sunucu filtresi tırnak hatası düzeltildi |
| 2 | SSH (uxsqlteam, become yok) + `mysql -u root` bağlantı testi; durum raporu. Değişiklik yapmaz. | Düşük | Tamamlandı: TEST 23/23 OK (gbapgt08 socket fallback), 2 SKIPPED |
| 3 | User var mı / şifre aynı mı (hash karşılaştırma) / yetki farkı + native password audit. Değişiklik yapmaz. | Düşük | Tamamlandı: TEST 23 sunucu, 17 hesap DIFFERENT / 6 NOT_EXISTS, 141 native hesap |
| 4 | CREATE USER / GRANT / ALTER USER (update), check mode, read_only / port / şifre politikası korumaları, doğrulama. | Orta-Yüksek | AAP'de check + run çalıştı; run gbadbt01'de ERROR 1819 (şifre politikası) -> ön kontrol eklendi, tekrar test bekleniyor |
| 5 | Konsolide rapor: job çıktısı + AAP artifact yeterli (kullanıcı kararı, ayrıca CSV/HTML/e-posta yok). | — | Kapsam dışı (şimdilik) |

## Mimari kararlar

1. **Envanter: aynı job içinde `add_host`** (onaylandı). Survey'deki ortam seçimi
   doğrudan filtre; ayrı Inventory Source/sync yok.
2. **Hedeflere SSH ile bağlanılır** (onaylandı; AAP → 3316 kapalı).
   `ansible_host = ListeningIP`, SSH portu 22. MySQL'e sunucu üzerinde lokal bağlanılır.
3. **Bağlantı adresi yalnızca `ListeningIP`** (onaylandı; farklı domainler var,
   DNS'e bağımlı olmamak için). IP boşsa kayıt "ListeningIP boş" nedeniyle elenir.
4. **Hedef kriteri `isActive=1` ve `DeleteDate IS NULL`.** Pasifler raporda görünür.
5. **Default MySQL portu 3316** (`ListeningPort` boşsa).
6. **Şifreler survey'de `password` tipiyle** (MSSQL şifresi Faz 1, MySQL root şifresi Faz 2).
   AAP bu alanları şifreli saklar ve job çıktısında `$encrypted$` gösterir.
   Alternatif: AAP Credential (merkezi yönetim, tek yerden rotasyon) – şimdilik tercih edilmedi.
7. **dzdo/become kullanılmaz** (Faz 2). `dzdo su - mysql -c` politika gereği çalışmıyor;
   `uxsqlteam` ile doğrudan `mysql` client çalıştırılır.
8. **MySQL bağlantısı `auto`**: önce TCP `127.0.0.1:<ListeningPort>`, 1045/2002/2003/2013
   hatasında socket. Neden: MySQL 8'de root çoğunlukla yalnız `'root'@'localhost'`;
   `skip_name_resolve=ON` ise TCP 127.0.0.1 girişi 1045 alır. Socket'e düşülen
   sunucular rapordaki `warning_servers` listesinde görünür.
9. **Root şifresi option file ile**: komut satırı/`MYSQL_PWD` yerine 0600 geçici dosya.
   `MYSQL_PWD` ve Ansible `environment:` uzak komut satırına önek olarak eklenir ve
   `ps` / `-vvv` çıktısında görünebilir.
10. **Faz 3/4 kararları (kullanıcıdan):**
    - `superuser` = `ALL PRIVILEGES ON *.*` **GRANT OPTION'sız** (default).
      Ayrı seçenek `superuser_with_grant` = `... WITH GRANT OPTION`.
    - Kullanıcı var ve şifre farklıysa davranış survey'den seçilir: `report` / `update`.
    - Root sunucularda `'root'@'localhost'`; TCP 127.0.0.1 girişi gbarkt02'de başarılı
      (127.0.0.1 -> localhost çözümleniyor). `auto` mod korunur; çözümlenmeyen
      sunucularda socket'e düşer.
11. **Koleksiyon sürümü**: EE ansible-core 2.16.18 -> `community.general <12`.
    `community.mysql` kaldırıldı (hedeflerde PyMySQL gerekmesin diye mysql CLI kullanılıyor).
12. **Şifre kontrolü: hash karşılaştırma (A, onaylandı).** Hedef şifre sunucuya gitmez.
    Unicode şifrelerde hash, hesabın oluşturulduğu client karakter setine bağlıdır;
    karşılaştırma UTF-8 ile yapılır (latin1 client ile oluşturulmuş Türkçe karakterli
    şifreler `DIFFERENT` görünebilir).
13. **Yetki setleri onaylandı**; `dml`'e LOCK TABLES + CREATE TEMPORARY TABLES eklendi
    (öneri), EXECUTE eklenmedi.
14. **Host default `%`** (survey'den değiştirilebilir). Her host ayrı MySQL hesabıdır.
15. **`ALL` tespiti:** MySQL 8 `SHOW GRANTS` ALL'u statik yetki listesine açar; sürüme
    göre değişen SUPER/REPLICATION hariç çekirdek liste mevcutsa ALL kabul edilir.
    Dinamik yetkiler (BACKUP_ADMIN vb.) karşılaştırmaya dahil edilmez.
16. **Faz 4 yetki geri almaz (REVOKE yok, onaylandı)**; sadece eksikler eklenir, fazlalar raporlanır.
17. **`update` = `ALTER USER ... IDENTIFIED WITH caching_sha2_password`** (onaylandı): native
    hesaplar şifre güncellenirken dönüştürülür.
18. **PROD için ek onay alanı yok** (onaylandı). Güvenlik ağı: AAP Check mode.
19. **Yeni hesaplar açıkça `caching_sha2_password`** ile oluşturulur (sunucu default'u
    `mysql_native_password`'e ayarlanmış olsa bile).
20. **read_only/super_read_only sunuculara yazılmaz**: InnoDB Cluster secondary'leri
    (gbapgaq0x, gbapgq0x) ve replikalar. Primary'deki değişiklik replike olur.
21. **Port uyuşmazlığında yazılmaz**: socket fallback başka instance'a gitmiş olabilir.
22. **Tek mysql çağrısı, stdin, her ifade bir satır**: ilk hatada durur, satır no =
    ifade sırası -> APPLIED / FAILED / NOT_RUN kesin.
23. **Native audit kategorileri**: CLUSTER_ROUTER_İÇ_HESAP (MySQL Shell/Router ile),
    ROOT (planlı bakım), UYGULAMA_SERVİS (client uyumluluğu doğrulanıp). Faz 4 yalnızca
    hedef kullanıcının hesaplarını dönüştürür; audit listesine dokunmaz.
24. **Şifre politikası ön kontrolü** (gbadbt01 ERROR 1819 sonrası): `SHOW GLOBAL VARIABLES
    LIKE 'validate%password%'` okunur, kurallar AAP içinde uygulanır (şifre sunucuya gitmez;
    `VALIDATE_PASSWORD_STRENGTH()` bu yüzden kullanılmadı). MySQL 8.0.46 ile 60/60 doğrulandı.
    `check_user_name` yalnızca oturum kullanıcısıyla (root) karşılaştırır.
25. **Şifresi aynı native hesap**: `update` modunda yalnızca hedef kullanıcı için
    `ALTER USER ... IDENTIFIED WITH caching_sha2_password BY <aynı şifre>`. Diğer native
    hesaplar kapsam dışı (kullanıcı kararı).
26. **Host başına tek task (action plugin `mysql_host_run`)**: log sadeliği ve dayanıklılık.
    Ansible'da bir play'deki tüm host'lar fail olursa sonraki play (rapor) çalışmaz; plugin
    hiçbir koşulda fail/unreachable döndürmez, her hata sonuca yazılır. Mantık değişmedi
    (aynı filtreler), yalnızca orkestrasyon taşındı. Hedefte Python gerekmez.
27. **Dosya transferi yerine SSH stdin**: sftp/scp bağımlılığı ve uyarıları yok.
28. **SSH hata metni**: no_log, ssh eklentisinin hata metnini maskeler; yalnızca şifre içermeyen
    ilk bağlantı denemesinde no_log geçici kapatılır.
29. **Rapor**: kategoriler + aynı sonucu alan sunucuların gruplanması; ayrıntı artifact'ta.
    Lab: 5 sunucuda log 548 -> 114 satır (çoğu rapor).
