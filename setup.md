# Server Side Control Setup

## 1. Bu kurulumda sen ne yapacaksın?

Yeni sistemde senin manuel olarak yapman gerekenler kısa haliyle şunlar:

1. Ubuntu sunucuda root erişimiyle bağlanmak
2. Alan adı ve DNS kaydını hazırlamak
3. Repo'yu sunucuya çekmek
4. Tek komutla kurulum scriptini çalıştırmak
5. Installer sorularını cevaplamak
6. MySQL root parolasını installer'a girmek
7. Panel açıldıktan sonra ilk kullanıcı/site/deploy işlemlerini panelden yapmak

Kurulum scripti geri kalan büyük kısmı otomatik yapar.

## 2. Hedef ortam

Önerilen ortam:
- Ubuntu 24.04 LTS
- Root erişimi
- Domain veya sabit IP
- Açık portlar: `80`, `443`, panel için kullanacağın port

## 3. Script neleri otomatik yapıyor?

`sudo ./scripts/install.sh` çalıştığında script şunları otomatik yapar:

1. Eksik Ubuntu paketlerini kurar
2. Kurulu olan paketleri atlar
3. Go yüklü değilse veya sürümü eskiyse kurar/günceller
4. PM2 kurulu değilse kurar
5. Panel binary, installer binary ve helper binary derler
6. `server-side-control` sistem kullanıcısını oluşturur
7. `systemd` unit kurar
8. `sudoers` helper kuralını kurar
9. MySQL servisini ayağa kaldırır
10. Installer sorularını sorar
11. Verdiğin MySQL root bilgisiyle panel veritabanını ve panel DB kullanıcısını oluşturur
12. MySQL admin bilgisini root-only dosyada saklar
13. Panel servisini başlatır
14. Repo yolu ve branch bilgisini update icin kaydeder

## 4. Script hangi paketleri kurar?

Eksikse otomatik kurulan paketler:

```bash
git
curl
ca-certificates
build-essential
nginx
mysql-server
certbot
python3-certbot-nginx
sudo
nodejs
npm
```

Opsiyonel olarak bulursa kurmaya çalıştığı PHP paketleri:

```bash
php8.2-fpm
php8.3-fpm
```

Ek davranış:
- `go` varsa ve sürüm `1.22+` ise atlanır
- `pm2` varsa atlanır
- apt paketi kuruluysa tekrar kurulmaz

## 5. MySQL artık nasıl hazırlanıyor?

Yeni akışta panel için MySQL veritabanını ve panel DB kullanıcısını sen manuel oluşturmuyorsun.

Installer senden şunları ister:

- MySQL root host
- MySQL root port
- MySQL root user
- MySQL root password
- panel database adı
- panel database user adı
- panel database password

Installer sonra şunları otomatik yapar:

1. MySQL'e root/admin olarak bağlanır
2. Panel veritabanını oluşturur
3. Panel MySQL kullanıcısını oluşturur/günceller
4. Yetkileri verir
5. Panel tablolarını migrate eder
6. Panel DSN bilgisini env dosyasına yazar
7. MySQL admin erişimini root-only dosyada saklar

İstersen daha sonra panel içindeki `Databases` ekranından bu MySQL admin parolasını yeniden üretebilir veya yeni bir parola ile değiştirebilirsin.

Saklanan dosya:

```text
/etc/server-side-control/mysql-admin.cnf
```

Bu dosya `600` izinle yazılır ve sadece root okuyabilir.

## 6. Repo'yu sunucuya çek

```bash
cd /opt
git clone <REPO_URL> server-side-control
cd /opt/server-side-control
```

## 7. Kurulumu başlat

Asıl kurulum komutu:

```bash
sudo ./scripts/install.sh
```

Bu komut eksik olanları kurar, kurulu olanları atlar.

## 8. Installer sana ne soracak?

Installer şu bilgileri ister ve her sorunun altında kısa bir açıklama gösterir:

- panel listen address: panel uygulamasinin hangi IP/port uzerinde dinleyecegi
- panel base URL: tarayicidan erisilecek tam panel adresi
- MySQL root host: MySQL servisinin host bilgisi
- MySQL root port: MySQL port bilgisi
- MySQL root user: veritabani ve kullanici olusturmak icin admin hesap
- MySQL root password: bu admin hesabin parolasi
- MySQL admin defaults file yolu: root-only MySQL admin bilgi dosyasi
- panel MySQL database adı: panelin kendi tablolarinin tutulacagi veritabani
- panel MySQL user adı: panel uygulamasinin kullanacagi MySQL kullanicisi
- panel MySQL user password: panel MySQL kullanicisinin parolasi
- bootstrap kullanıcı adı: panel icin ilk giris kullanicisi
- bootstrap parolası: bootstrap kullanicisinin parolasi
- PAM service adı: Ubuntu kullanicilariyla giris icin PAM servis adi
- nginx binary yolu: nginx komutunun yolu veya adi
- nginx `sites-available` dizini: vhost dosyalarinin yazilacagi dizin
- nginx `sites-enabled` dizini: aktif site linklerinin bulundugu dizin
- certbot binary yolu: TLS islemleri icin certbot komutu
- helper binary yolu: root gerektiren islemleri yapan helper binary yolu

Varsayılan env dosyası:

```text
/etc/server-side-control/panel.env
```

## 9. Kurulum bittiğinde ne kontrol etmelisin?

```bash
systemctl status server-side-control
systemctl status nginx
curl -i http://127.0.0.1:8080/healthz
ls -l /usr/local/bin/server-side-control-helper
ls -l /etc/server-side-control/mysql-admin.cnf
visudo -cf /etc/sudoers.d/server-side-control-helper
go version
pm2 -v
```

## 10. İlk giriş

Tarayıcıdan aç:

```text
http://SUNUCU_IP:8080
```

Giriş seçenekleri:
- installer sırasında verdiğin bootstrap kullanıcı/parolası
- Ubuntu üzerindeki PAM kullanıcı hesabı

## 11. TLS nasıl açılır?

Önce panelde `Sites` ekranından siteyi oluştur.

Sonra aynı ekrandaki TLS bölümünden:
- domain
- email
- redirect seçeneği
girerek sertifika iste.

Arka planda şu akış çalışır:

1. `certbot --nginx`
2. sertifika yerleştirme
3. `nginx -t`
4. reload

Ön şart:
- domain DNS kaydı bu sunucuya bakmalı
- port `80` dışarı açık olmalı

## 12. Güvenlik modeli

Panel servisi root olarak çalışmaz.

Mimari:
- web panel: `server-side-control` system user
- yetkili işlemler: root helper binary
- helper erişimi: `/etc/sudoers.d/server-side-control-helper`

Bu model sayesinde web uygulaması root haklarıyla sürekli çalışmaz.

## 13. Önemli dosya yolları

- env dosyası: `/etc/server-side-control/panel.env`
- install state dosyası: `/etc/server-side-control/install-state.env`
- MySQL admin dosyası: `/etc/server-side-control/mysql-admin.cnf`
- panel binary: `/usr/local/bin/server-side-control`
- helper binary: `/usr/local/bin/server-side-control-helper`
- installer binary: `/usr/local/bin/server-side-control-installer`
- updater binary/script: `/usr/local/bin/server-side-control-update`
- systemd unit: `/etc/systemd/system/server-side-control.service`
- sudoers kuralı: `/etc/sudoers.d/server-side-control-helper`

## 14. Update nasil yapacaksin?

Ilk kurulumdan sonra yeni versiyon geldiginde paneli yeniden bastan kurman gerekmez.

Sunucuda su komutu calistirman yeterli:

```bash
sudo /usr/local/bin/server-side-control-update
```

Bu script sunucuda sunlari yapar:

1. Ilk kurulumda kaydedilen repo yolunu okur
2. Repo icinde `git fetch` yapar
3. Kaydedilen branch icin `git pull --ff-only` yapar
4. `install.sh` scriptini tekrar calistirir
5. Mevcut `/etc/server-side-control/panel.env` dosyasini korur
6. Installer sorularini tekrar sormaz
7. Binary dosyalarini yeniden build eder
8. Servisi restart eder

Not:
- Sunucudaki repo klasorunde local degisiklik varsa update scripti durur
- Bu sayede el ile yapilan degisiklikler yanlislikla ezilmez
- Guncelleme repo tabanli oldugu icin sunucuda `.git` klasoru durmalidir

## 15. Kurulumdan sonra önerilen ilk sıra

1. Panel login test et
2. `Users` ekranından deploy kullanıcısı oluştur
3. `Databases` ekranından uygulama DB/user aç
4. Gerekirse `Databases` ekranından MySQL admin parolasını döndür
5. `Sites` ekranından vhost oluştur
6. TLS aç
7. `Deploys` ekranından repo deploy et
8. `Processes` ekranından PM2 süreçlerini kontrol et
9. `Logs` ekranından audit kayıtlarını kontrol et

## 16. Sorun giderme

MySQL bağlanmıyorsa:
- root bilgilerini installer'da doğru girdiğini kontrol et
- panel DSN'yi kontrol et
- `mysql --defaults-extra-file=/etc/server-side-control/mysql-admin.cnf -e 'SHOW DATABASES;'` ile admin erişimini test et
- `mysql -h 127.0.0.1 -u server_side_control -p` ile panel kullanıcısını test et

Script paket kurmuyorsa:
- `apt-get update` çalışıyor mu kontrol et
- sunucunun internete çıkabildiğini kontrol et
- apt source list bozuk mu kontrol et

Update script calismiyorsa:
- `/etc/server-side-control/install-state.env` dosyasi var mi kontrol et
- sunucudaki repo klasorunde `.git` dizini duruyor mu kontrol et
- repo icinde local degisiklik var mi kontrol et
- `git -C /opt/server-side-control status` ile durumu incele

Helper çalışmıyorsa:
- `visudo -cf /etc/sudoers.d/server-side-control-helper`
- helper binary path doğru mu kontrol et
- servis kullanıcısının `sudo -n /usr/local/bin/server-side-control-helper` çağrısını yapabildiğini doğrula

TLS başarısız olursa:
- domain DNS kaydı doğru mu kontrol et
- port `80` açık mı kontrol et
- `certbot certificates` ile sertifikaları kontrol et

PM2 görünmüyorsa:
- uygulama gerçekten ilgili Linux kullanıcısı altında mı çalışıyor kontrol et
- `sudo -u <user> pm2 list` ile manuel test yap
