# Faz Planı

Her faz sonunda onay alınmadan sonraki faza geçilmez.

| Faz | Kapsam | Risk | Durum |
|---|---|---|---|
| 1 | MSSQL envanter okuma, ortam eşleme (DEV/TEST/QA/PROD), dinamik grup, keşif raporu. Hedeflere bağlanmaz. | Yok (salt okunur) | **Revize edildi – AAP testi bekleniyor** |
| 2 | SSH + `dzdo su - mysql` + `mysql -u root` bağlantı testi; durum raporu (OK / SSH_UNREACHABLE / BECOME_FAIL / MYSQL_AUTH_FAIL / ERROR). Değişiklik yapmaz. | Düşük | Bekliyor |
| 3 | User var mı / şifre aynı mı kontrolü (check-only). Yetki setleri (readonly, DML, DDL, superuser) ve çoklu host (subnet) desteği. | Düşük | Bekliyor |
| 4 | Gerçek CREATE USER / GRANT, `apply_mode` (report_only / create_missing / enforce), PROD için ek onay koruması. | Orta-Yüksek | Bekliyor |
| 5 | Konsolide rapor (sunucu bazlı + özet; CSV/HTML artifact), son Job Template + Survey. | Düşük | Bekliyor |

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
