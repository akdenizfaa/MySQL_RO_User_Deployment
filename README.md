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
ansible.cfg
collections/requirements.yml          # AAP project sync bunu otomatik kurar
execution-environment/                # ansible-builder tanımı (pymssql)
inventory/localhost.yml               # sadece controller; hedefler runtime'da eklenir
inventory_read.yml                    # FAZ 1: envanter keşfi
connectivity_check.yml                # FAZ 2: SSH + MySQL bağlantı testi ve rapor
roles/mysql_inventory/                # MSSQL okuma + ortam eşleme + add_host
  filter_plugins/mysqlinv.py
roles/mysql_connectivity/             # host başına SSH/client/MySQL testi
  filter_plugins/mysqlconn.py         # durum sınıflandırma + option file üretimi
roles/mysql_report/                   # konsolide tablo + özet + set_stats
  filter_plugins/mysqlreport.py
aap/surveys/                          # Survey spec (JSON)
tests/                                # pytest + mock envanter
```

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

## Sorun giderme

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
