# MySQL_RO_User_Deployment

AAP (Ansible Automation Platform) üzerinden, envanteri MSSQL
`MysqlInventory.dbo.My_ServerInventory` tablosunda tutulan tüm aktif MySQL
sunucularında kullanıcı oluşturma / kontrol / raporlama otomasyonu.

Faz planı ve mimari kararlar: [docs/PHASES.md](docs/PHASES.md)

## Yapı

```
ansible.cfg
collections/requirements.yml          # AAP project sync bunu otomatik kurar
execution-environment/                # ansible-builder tanımı (pymssql + PyMySQL)
inventory/localhost.yml               # sadece controller; hedefler runtime'da eklenir
playbooks/inventory_read.yml          # FAZ 1 giriş noktası
roles/mysql_inventory/                # MSSQL okuma + ortam eşleme + add_host
  filter_plugins/mysqlinv.py          # normalize/seçim mantığı (unit-test'li)
aap/credential_types/                 # Custom Credential Type tanımları
aap/surveys/                          # Survey spec (JSON)
tests/                                # pytest + mock envanter
```

## Faz 1 – AAP kurulumu

1. **Execution Environment**: `execution-environment/` ile build edip registry'ye push edin,
   AAP'de EE olarak tanımlayın. (Kurumsal EE'nizde `pymssql` varsa bu adım atlanabilir.)
2. **Credential Type**: `aap/credential_types/mssql_inventory.yml` → "MSSQL Inventory".
3. **Credential**: bu tipten bir credential oluşturun (salt okunur MSSQL hesabı).
4. **Project**: bu repo (branch `main`), *Update revision on launch* açık.
5. **Job Template**: `MySQL - Inventory Read`
   - Inventory: `localhost` içeren herhangi bir inventory (veya `inventory/localhost.yml` source)
   - Playbook: `playbooks/inventory_read.yml`
   - Credentials: MSSQL Inventory
   - Survey: `aap/surveys/inventory_read_survey.json` içeriği
6. Çalıştırın; job çıktısında `mysqlinv_summary`, `mysqlinv_skipped`, hedef listesi görünür.

## Ortam eşlemesi

`Type` kolonu → survey ortamı, `roles/mysql_inventory/defaults/main.yml` içindeki
`mysqlinv_env_type_map` ile yapılır (büyük/küçük harf duyarsız). Eşlenmeyen
değerler raporda `unmapped_type_values` olarak listelenir.

## Yerel test

```bash
python3 -m pytest -q tests/
ansible-playbook playbooks/inventory_read.yml \
  -e '{"target_environments":["TEST","PROD"]}' \
  -e mysqlinv_mock_file=$PWD/tests/fixtures/inventory_sample.json
```
