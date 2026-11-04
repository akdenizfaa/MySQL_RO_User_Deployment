# MySQL_RO_User_Deployment

AAP (Ansible Automation Platform 2.4 / Controller 4.5.x) üzerinden, envanteri MSSQL
`PGARSQLTEM01,1453 / MysqlInventory.dbo.My_ServerInventory` tablosunda tutulan tüm
aktif MySQL sunucularında kullanıcı oluşturma / kontrol / raporlama otomasyonu.

Faz planı ve mimari kararlar: [docs/PHASES.md](docs/PHASES.md)

## Bağlantı modeli

```
AAP (EE container) ──pymssql──► PGARSQLTEM01,1453 (MysqlInventory)   # envanter okuma
AAP (EE container) ──SSH:22──► MySQL sunucusu (ListeningIP)
                                └─ dzdo su - mysql
                                    └─ mysql -u root (lokal, port 3316)   # Faz 2+
```

## Yapı

```
ansible.cfg
collections/requirements.yml          # AAP project sync bunu otomatik kurar
execution-environment/                # ansible-builder tanımı (pymssql)
inventory/localhost.yml               # sadece controller; hedefler runtime'da eklenir
playbooks/inventory_read.yml          # FAZ 1 giriş noktası
roles/mysql_inventory/                # MSSQL okuma + ortam eşleme + add_host
  filter_plugins/mysqlinv.py          # normalize/seçim mantığı (unit-test'li)
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
   - Playbook: `playbooks/inventory_read.yml`
   - Execution Environment: 1. adımdaki EE
   - Credentials: Faz 1'de gerekmiyor (MSSQL şifresi survey'den gelir)
5. **Survey**: `aap/surveys/inventory_read_survey.json` içindeki 4 soru
   (ortam multiselect, sunucu filtresi, MSSQL kullanıcısı, MSSQL şifresi – *password* tipi).
   Survey'i **Enable** etmeyi unutmayın.
6. Çalıştırın. Çıktıda `mysqlinv_summary` (okunan satır, bulunan Type değerleri,
   ortam başına hedef sayısı), `mysqlinv_skipped` (elenenler + neden) ve hedef listesi görünür.

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
ansible-playbook playbooks/inventory_read.yml \
  -e '{"target_environments":["TEST","PROD"]}' \
  -e mysqlinv_mock_file=$PWD/tests/fixtures/inventory_sample.json
```
