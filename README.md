# MySQL_RO_User_Deployment

AAP (Ansible Automation Platform 2.4 / Controller 4.5.x) üzerinden, envanteri MSSQL
`PGARSQLTEM01,1453 / MysqlInventory.dbo.My_ServerInventory` tablosunda tutulan tüm
aktif MySQL sunucularında kullanıcı oluşturma / kontrol / raporlama otomasyonu.

Faz planı ve mimari kararlar: [docs/PHASES.md](docs/PHASES.md)

## Bağlantı modeli

```
AAP (EE container) ──pymssql──► PGARSQLTEM01,1453 (MysqlInventory)   # envanter okuma
AAP (EE container) ──SSH:22 (uxsqlteam)──► MySQL sunucusu (ListeningIP)
                                └─ mysql --defaults-extra-file=<0600 geçici dosya> -u root
                                     -h 127.0.0.1 -P <ListeningPort>   (auto: hata olursa socket)
```

## Yapı

```
inventory_read.yml        FAZ 1: envanter keşfi
connectivity_check.yml    FAZ 2: bağlantı testi                    (değişiklik yapmaz)
user_check.yml            FAZ 3: kullanıcı/şifre/yetki kontrolü     (değişiklik yapmaz)
user_deploy.yml           FAZ 4: oluştur / yetki ver / şifre güncelle (+ Check modu)

roles/mysql_inventory/    MSSQL okuma, ortam eşleme, add_host
roles/mysql_host/         host başına TEK task: action_plugins/mysql_host_run.py
roles/mysql_report/       SONUÇ RAPORU + job artifact
roles/mysql_connectivity/filter_plugins/mysqlconn.py   bağlantı sınıflandırma
roles/mysql_user_check/filter_plugins/mysqluser.py     hash, yetki, politika, SQL planı
roles/mysql_user_apply/filter_plugins/mysqlapply.py    uygulama sonucu ayrıştırma
aap/surveys/              survey spec'leri
tests/                    pytest (104 test) + lab fixture'ları
```

## Çıktı ve dayanıklılık

- **Host başına tek satır:** `ok: [sunucu]` (değişiklik yok) veya `changed: [sunucu]`.
  Tüm adımlar (SSH, client, bağlantı, kontrol, uygulama, doğrulama) tek task'ta.
- **Bir sunucu diğerlerini durdurmaz:** SSH erişilemezliği, kimlik hatası, SQL hatası,
  işlem sırasında bağlantı kopması ve beklenmeyen hatalar yakalanır ve rapora yazılır;
  host hiçbir zaman fail/unreachable olmaz. Tüm sunucular hata verse bile rapor çıkar.
- **SONUÇ RAPORU** (job sonunda): sunucular sonuçlarına göre gruplanır, aynı sonucu
  alanlar tek satırda toplanır:

| Bölüm | Anlamı | Job'ı FAILED yapar |
|---|---|---|
| HATA | Bağlanılamadı / SQL hatası / işlem yarıda kaldı | Evet |
| YAPILAMADI | Şifre politikası, port uyuşmazlığı - aksiyon gerekiyor | Evet |
| DEĞİŞİKLİK YAPILDI | Ne yapıldığı + doğrulama sonucu | |
| PLANLANAN | Check modunda yapılacaklar | |
| İŞLEM GEREKİYOR | Faz 3'te tespit edilen eksikler | |
| ŞİFRE FARKLI | `report` seçildiği için değiştirilmedi | |
| REPLİKA / SECONDARY | read_only; primary'den replike olur | |
| UYGUN | İşlem gerekmedi | |
| ATLANDI | Envanterde pasif vb. | |
| DİKKAT | Fazla yetki, ek hesaplar, socket fallback, native password audit özeti | |

- Ayrıntılar AAP job'ında **Details > Artifacts**: `mysqlreport_hosts` (sunucu bazlı),
  `mysqlreport_apply` (ifade bazlı, şifre maskeli), `mysqlreport_native` (native hesap listesi).
- Job, rapor basıldıktan sonra HATA/YAPILAMADI varsa FAILED olur
  (`mysqlreport_fail_on_error: false` ile kapatılabilir).

## EE (Execution Environment) nedir?

AAP 2.x playbook'ları doğrudan controller üzerinde değil, bir **container image**
içinde çalıştırır. Bu image'a Execution Environment denir; içinde ansible-core,
koleksiyonlar ve Python kütüphaneleri bulunur. MSSQL'e bağlanmak için gereken
`pymssql` kütüphanesi varsayılan EE'lerde yok, bu yüzden özel bir EE gerekiyor.

Kontrol: AAP'de **Administration > Execution Environments** altında mevcut EE'leri
görebilirsiniz. Ekibinizde zaten `pymssql` içeren bir EE varsa onu kullanın.

## Faz 1 – AAP kurulumu

1. **Execution Environment**: `execution-environment/` ile build edip kurumunuzun
   registry'sine (Private Automation Hub vb.) push edin; AAP'de EE olarak tanımlayın.
2. **Project**: bu repo, branch `main`, *Update Revision on Launch* açık.
3. **Inventory**: `localhost` hostu içeren bir inventory (veya Source olarak
   `inventory/localhost.yml`).
4. **Job Template**: `MySQL - Inventory Read`
   - Playbook: `inventory_read.yml`
   - Execution Environment: 1. adımdaki EE
   - Credentials: Faz 1'de gerekmiyor (MSSQL şifresi survey'den gelir)
5. **Survey**: `aap/surveys/inventory_read_survey.json` içindeki 4 soru
   (ortam multiselect, sunucu filtresi, MSSQL kullanıcısı, MSSQL şifresi – *password* tipi).
   Survey'i **Enable** etmeyi unutmayın.
6. Çalıştırın. Çıktıda `mysqlinv_summary` (okunan satır, bulunan Type değerleri,
   ortam başına hedef sayısı), `mysqlinv_skipped` (elenenler + neden) ve hedef listesi görünür.

## Faz 2 – Bağlantı testi (değişiklik yapmaz)

Job Template: `MySQL - Connectivity Check`
- Playbook: `connectivity_check.yml`
- Execution Environment: Faz 1 ile aynı
- Credentials: **SSH:uxsqlteam** (Machine). Credential'da *Privilege Escalation* alanı
  dolu olsa bile playbook `become: false` ile çalışır; dzdo kullanılmaz.
- Survey: `aap/surveys/connectivity_check_survey.json` (7 soru)
- Önerilen ilk çalıştırma: TEST + tek sunucu filtresi.

Her sunucu için adımlar ve durum kodları:

| Adım | Başarısızlıkta durum |
|---|---|
| SSH (`raw: echo`) | `SSH_UNREACHABLE` / `SSH_AUTH_FAIL` |
| Komut çalıştırma (python) | `HOST_ERROR` |
| mysql client bulma (login shell PATH + bilinen yollar) | `MYSQL_CLIENT_NOT_FOUND` |
| `SELECT VERSION(), @@hostname, @@port, CURRENT_USER()` | `MYSQL_AUTH_FAIL` (1045) / `MYSQL_UNREACHABLE` (2002/2003/2013) / `MYSQL_ERROR` |
| Hepsi başarılı | `OK` (socket'e düşüldüyse veya port uyuşmuyorsa `warning_servers` listesinde) |

Envanterde elenenler (`isActive=0` vb.) `SKIPPED` olarak tabloda yer alır.
`OK`/`SKIPPED` dışında durum varsa rapor basıldıktan sonra job **FAILED** olur
(`mysqlreport_fail_on_error: false` ile kapatılabilir).

Güvenlik: root şifresi komut satırında geçmez (`ps` ile görünmez). Sunucuda
`/tmp` altında 0600 izinli geçici bir option file oluşturulur, iş bitince her
durumda (hata olsa da) silinir. İlgili task `no_log: true`.

## Faz 3 – Kullanıcı kontrolü ve audit (değişiklik yapmaz)

Job Template: `MySQL - User Check`
- Playbook: `user_check.yml`, Credential: **SSH:uxsqlteam**, EE: Faz 1 ile aynı
- Survey: `aap/surveys/user_check_survey.json` (12 soru)

Yetki setleri (hepsi `*.*`, çoklu seçimde birleşim):

| Set | Yetkiler |
|---|---|
| readonly | SELECT, SHOW VIEW |
| dml | SELECT, INSERT, UPDATE, DELETE, LOCK TABLES, CREATE TEMPORARY TABLES |
| ddl | CREATE, ALTER, DROP, INDEX, REFERENCES, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, TRIGGER, EVENT |
| superuser | ALL PRIVILEGES |
| superuser_with_grant | ALL PRIVILEGES WITH GRANT OPTION |

**Şifre kontrolü:** hedef kullanıcının şifresi MySQL sunucularına gönderilmez.
`mysql.user`'dan `plugin` ve `HEX(authentication_string)` okunur; survey'deki
şifre aynı algoritma + salt ile AAP içinde hash'lenip karşılaştırılır
(`mysql_native_password`: SHA1(SHA1); `caching_sha2_password`: SHA-256 crypt, 5000 tur).
Algoritma gerçek MySQL 8.0.46 hash'leriyle doğrulanmıştır (`tests/fixtures/mysql8_hash_vectors.json`).

Hesap durumları (her `'user'@'host'` için):

| Durum | Anlamı | Planlanan işlem (Faz 4) |
|---|---|---|
| `NOT_EXISTS` | Hesap yok | CREATE USER + GRANT |
| `EXISTS_PASSWORD_MATCH` | Var, şifre aynı | Eksik yetki varsa GRANT |
| `EXISTS_PASSWORD_DIFFERENT` | Var, şifre farklı | `report`: yok / `update`: ALTER USER |
| `UNSUPPORTED_PLUGIN` | auth_socket vb., şifre kontrol edilemez | — |
| `EXTRA_ACCOUNT` | Aynı kullanıcı, survey'de olmayan host | Bilgi |
| `SKIPPED_CONNECTION` / `QUERY_ERROR` | Bağlantı/sorgu sorunu | — |

İşaretler: `NATIVE_PASSWORD_DÜZELTİLMELİ`, `ACCOUNT_LOCKED`, `PASSWORD_EXPIRED`,
`MEVCUT_GRANT_OPTION` (istenmediği halde var; Faz 4 yetki geri almaz).

**Audit:** her sunucudaki tüm `mysql_native_password` hesapları ayrı tabloda
"düzeltilmeli" olarak listelenir (8.4'te bu plugin varsayılan olarak kapalıdır).

## Faz 4 – Dağıtım (değişiklik yapar)

Job Template: `MySQL - User Deploy`
- Playbook: `user_deploy.yml`, Credential: **SSH:uxsqlteam**, EE: aynı
- Survey: `aap/surveys/user_deploy_survey.json` (Faz 3 ile aynı 12 soru)
- **Job Type → Prompt on launch** işaretleyin. Önce **Check**, sonra **Run**.

| Kural | Davranış |
|---|---|
| Check mode | Hiçbir SQL çalışmaz; plan (şifre maskeli) ve beklenen sonuç raporlanır |
| Yeni hesap | `CREATE USER ... IDENTIFIED WITH caching_sha2_password` + `GRANT ... ON *.*` |
| Şifre farklı + `update` | `ALTER USER ... IDENTIFIED WITH caching_sha2_password` (native hesap dönüştürülür) |
| Şifre farklı + `report` | İşlem yok, `ŞİFRE_FARKLI_SADECE_RAPOR` |
| Eksik yetki | Sadece eksikler `GRANT` edilir |
| Fazla yetki | **REVOKE yok**; `extra` sütununda ve `FAZLA_YETKİ` işaretiyle raporlanır |
| `read_only` / `super_read_only` | Yazılmaz (`SKIPPED_READ_ONLY`); primary'den replike olur, doğrulama replikayı da kontrol eder |
| Envanter portu ≠ `@@port` | Yazılmaz (`SKIPPED_PORT_MISMATCH`): socket başka instance'a bağlanmış olabilir |
| Şifre aynı + native + `update` | `ALTER USER ... IDENTIFIED WITH caching_sha2_password` (aynı şifre, yalnızca plugin dönüşümü; sadece hedef kullanıcı) |
| Şifre politikası (`validate_password`) | Sunucu politikası okunur, şifre AAP içinde (sunucuya gönderilmeden) değerlendirilir; uymuyorsa şifre içeren ifadeler ve yeni hesabın GRANT'ı **çalıştırılmaz** (`SKIPPED_PASSWORD_POLICY`), nedenler raporlanır, job FAILED. Check modunda da yakalanır |
| SQL hatası | İlk hatada durur; ifade bazlı `APPLIED` / `FAILED` / `NOT_RUN`, job FAILED |
| Doğrulama | Uygulamadan sonra Faz 3 kontrolü tekrar çalışır, `post` sütununa yazılır |

Güvenlik: şifreler komut satırına hiç yazılmaz (`ps`'te görünmez). Admin şifresi SSH
stdin ile 0600 geçici option file'a yazılır ve iş sonunda silinir; hedef şifreyi içeren
SQL mysql'e doğrudan SSH stdin ile verilir. Hedefte Python ve sftp/scp gerekmez.
Raporda SQL `'********'` ile maskelidir.
MySQL binlog/general log'a `CREATE/ALTER USER` şifreleri hash'li yazılır.

**InnoDB Cluster / replikasyon:** Primary üzerindeki değişiklik secondary'lere replike
olur. Survey'de tüm üyeler seçilse bile yalnızca yazılabilir üye (primary) değiştirilir.

## Sorun giderme

- **Socket ile bağlantı `MYSQL_UNREACHABLE` (ERROR 2002 ... (13))**: `uxsqlteam`
  socket dizinine (örn. `/var/run/mysqld`) erişemiyor; dizin izni 755 olmalı veya TCP girişi açılmalı.
- **`ERROR 1819: Your password does not satisfy the current policy requirements`**:
  sunucuda `validate_password` etkin. Artık Faz 3 ve Faz 4 check modu bunu önceden
  `ŞİFRE_POLİTİKASI_UYGUN_DEĞİL` olarak gösterir; `planned` sütunundaki
  `[ENGELLENDİ: ...]` metni eksik kuralı (uzunluk, büyük/küçük harf, rakam, özel karakter) söyler.
  STRONG politikadaki sözlük kontrolü yerelde yapılamaz.
- **Hedef sayısı 0 / "Seçilen kriterlere uyan hedef sunucu yok"**: Sunucu filtresi
  alanına tırnak (`""`) yazmayın, boş bırakın. Envanterde olmayan adlar
  `server_filter_not_found` alanında listelenir.
- **`the role 'mysql_inventory' was not found`**: Playbook'lar repo kökünde
  tutulur; Ansible rolleri playbook'un yanındaki `roles/` klasöründe arar. Bu düzen
  AAP'nin `ansible.cfg`'yi okuyup okumamasından bağımsız çalışır.

## Ortam eşlemesi

`Type` kolonu → survey ortamı (`roles/mysql_inventory/defaults/main.yml`,
`mysqlinv_env_type_map`), büyük/küçük harf duyarsız:

| Type | Ortam |
|---|---|
| Dev | DEV |
| Test | TEST |
| QA | QA |
| Production | PROD |

Eşlenmeyen değerler raporda `unmapped_type_values` olarak listelenir.

## Yerel test

```bash
python3 -m pytest -q tests/
ansible-playbook inventory_read.yml \
  -e '{"target_environments":["TEST","PROD"]}' \
  -e mysqlinv_mock_file=$PWD/tests/fixtures/inventory_sample.json
```

Faz 2 lab testi: `tests/fixtures/phase2_lab.json` 127.0.0.x adresleriyle SSH/MySQL
senaryolarını içerir (lokal sshd + MySQL/MariaDB 3316 gerekir).
