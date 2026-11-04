# Faz Planı

Her faz sonunda onay alınmadan sonraki faza geçilmez.

| Faz | Kapsam | Risk | Durum |
|---|---|---|---|
| 1 | MSSQL envanter okuma, ortam eşleme (DEV/TEST/QA/PROD), dinamik grup, keşif raporu. MySQL'e bağlanmaz. | Yok (salt okunur) | **Tamamlandı – onay bekliyor** |
| 2 | MySQL bağlantı testi (TCP + login), admin credential type, bağlantı durum raporu (OK / UNREACHABLE / AUTH_FAIL / ERROR). Değişiklik yapmaz. | Düşük | Bekliyor |
| 3 | User var mı / şifre aynı mı kontrolü (check-only, dry-run). Yetki seti tanımları (readonly, DML, DDL, superuser) ve MySQL sürümüne göre grant listesi. | Düşük | Bekliyor |
| 4 | Gerçek user create / grant uygulaması, `apply_mode` (report_only / create_missing / enforce), PROD için ek onay koruması. | Orta-Yüksek | Bekliyor |
| 5 | Konsolide rapor (sunucu bazlı tablo + özet; HTML/CSV artifact), AAP Job Template + Survey'in son hali, isteğe bağlı workflow. | Düşük | Bekliyor |

## Kritik mimari kararlar (Faz 1)

1. **Envanter: add_host (runtime) — dinamik envanter plugin'i yerine.**
   Survey'deki ortam seçimi aynı job içinde filtre olarak kullanılabiliyor; ayrı
   Inventory Source + sync gerektirmiyor. Alternatif: AAP Inventory Source olarak
   script/plugin — her job öncesi sync ister, survey ile süzmek zorlaşır.
2. **MySQL'e EE içinden, MySQL protokolüyle bağlanılır (SSH yok).**
   Hedef sunuculara `ansible_connection: local` atanır; modüller `login_host`
   ile uzaktaki MySQL'e gider. SSH anahtarı/sudo gerekmez. Ön koşul: AAP execution
   node'larından MySQL portlarına (3306/3316) ağ erişimi ve yetkili bir MySQL admin hesabı.
3. **Bağlantı adresi default `ListeningIP`.** Bazı satırlarda Fqdn NULL veya kısa ad
   (`gbkmdp01`, `roarkp02`). `mysqlinv_connect_via: fqdn` ile değiştirilebilir;
   Fqdn geçersizse IP'ye düşer.
4. **isActive filtresi Ansible'da.** Pasif sunucular raporda `isActive=0` olarak görünür.
5. **Secret'lar env injector ile.** Credential'lar extra_vars'a yazılmaz.
