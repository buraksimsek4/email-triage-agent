# Milestones — Email Phishing Triage Agent

Toplam süre: yaklaşık 4–5 hafta (günde 2–3 saat). Her milestone sonunda çalışan, test edilmiş ve commit'lenmiş bir şey olmalı.

## Büyük resim ve sıralama mantığı

Üç prensip sıralamayı belirliyor:

1. **Önce mailbox'a bağımlı olmadan geliştir.** Analizörlerin çoğunu `.eml` dosyaları üzerinde yazacağız. Graph/webhook kısmı en sinir bozucu (auth, tünel, abonelik yenileme) olduğu için sona yakın bırakıldı. Böylece takılırsan bile projenin %80'i hazır olur.
2. **Önce ölç, sonra geliştir (eval-first).** Değerlendirme altyapısını erken kuruyoruz. Her yeni analizör "doğruluğu ne kadar artırdı?" sorusuyla eklenir. Bu, ablation tablosunu bedavaya verir.
3. **Deterministik önce, LLM sonra.** LLM pahalı ve yanılabilir. Önce kuralla yakalanabilenleri yakalıyoruz, LLM'i anlam gerektiren yerde kullanıyoruz.

| # | Milestone | Süre | Çıktı |
|---|---|---|---|
| M0 | Temeller ve ortam | 1 gün | Repo, venv, hesaplar |
| M1 | E-posta nedir? Parse + kaynak soyutlaması | 2 gün | `.eml` → yapılandırılmış model |
| M2 | Header analizörü | 3 gün | SPF/DKIM/DMARC + spoofing sinyalleri |
| M3 | Veri seti + eval harness | 3–4 gün | İlk baseline metrikleri |
| M4 | Body ve URL analizörü (deterministik) | 3 gün | Link/HTML sinyalleri, reputation |
| M5 | LLM verdict + şema | 3–4 gün | Yapılandırılmış karar, fusion |
| M6 | Attachment analizi + sandbox | 4 gün | Docker içinde statik analiz |
| M7 | Görsel + QR analizi | 2 gün | Vision LLM + quishing |
| M8 | Agent orkestrasyonu | 3 gün | Tool-use agent vs sabit pipeline |
| M9 | Gerçek mailbox: Graph + webhook | 4 gün | Event-driven akış |
| M10 | Aksiyonlar, audit log, dashboard | 3 gün | Etiketle/karantina, kayıt |
| M11 | Güvenlik sertleştirme | 2–3 gün | Injection testleri, threat model |
| M12 | Sonuçlar, README, demo | 3 gün | Yayınlanabilir portföy |

---

## M0 — Temeller ve ortam

**Amaç:** Hiçbir şey yazmadan önce zemini hazırlamak.

**Öğreneceğin kavramlar**
- Python proje yapısı (`pyproject.toml`), sanal ortam, `.env` ile secret yönetimi
- Neden `.gitignore`'a `.env`, `eval/dataset` içindeki kişisel veri ve `*.pyc` girer

**Görevler**
1. Python 3.12, Git, Docker Desktop kurulu mu kontrol et.
2. `email-triage-agent/` içinde `git init`, `.gitignore`, `pyproject.toml`, `.env.example`, `Makefile`.
3. Anthropic API anahtarı al, `.env`'e koy (sohbete yapıştırma).
4. VirusTotal ücretsiz hesap aç, API anahtarını `.env`'e koy.
5. **Test mailbox'ı**: Microsoft 365 Developer Program başvurusu yap (onay günler sürebilir, hemen başvur) ve yedek olarak yeni bir ücretsiz Outlook.com hesabı aç. Ana hesabını kullanma.
6. GitHub'da özel (private) repo aç, ilk commit'i at.

**Bitti sayılır:** `make test` boş bir testi geçiyor, `make lint` temiz, repo GitHub'da.

**Tuzaklar:** API anahtarını yanlışlıkla commit etmek (ilk commit'ten önce `git status` kontrol et). Developer tenant başvurusunu geciktirmek.

---

## M1 — E-posta nedir? Parse ve kaynak soyutlaması

**Amaç:** Bir `.eml` dosyasını güvenilir şekilde yapılandırılmış bir modele çevirmek.

**Öğreneceğin kavramlar**
- **E-posta anatomisi:** envelope vs header vs body. Header'lar `Received`, `From`, `Reply-To`, `Return-Path`, `Message-ID`, `Authentication-Results`.
- **MIME:** `multipart/alternative` (text + html), `multipart/mixed` (ek), `Content-Type`, `Content-Transfer-Encoding` (base64, quoted-printable), charset sorunları.
- Neden e-postayı parse etmek göründüğünden zor (kötü biçimlenmiş mailler, iç içe multipart).

**Görevler**
1. `schemas.py`: `ParsedEmail` pydantic modeli (headers, text_body, html_body, urls, attachments[], inline_images[]).
2. `EmailSource` arayüzü ve `EmlFileSource` implementasyonu (stdlib `email`, `policy=default`).
3. Ekleri **diske çalıştırılabilir olarak değil**, bayt olarak çıkar ve SHA-256 hash'ini hesapla.
4. Birkaç kendi yazdığın `.eml` fixture'ı (düz metin, HTML, ekli, iç içe multipart, kötü encoding) ve birim testleri.

**Bitti sayılır:** 5+ farklı fixture doğru parse ediliyor, testler geçiyor; bozuk bir mail uygulamayı çökertmiyor (hata sinyali üretiyor).

**Tuzaklar:** Charset hataları, HTML-only mailler, `Content-Disposition: inline` ekleri.

---

## M2 — Header analizörü

**Amaç:** Deterministik, açıklanabilir header sinyalleri üretmek. LLM yok.

**Öğreneceğin kavramlar**
- **SPF** (hangi IP bu domain adına mail atabilir), **DKIM** (imza), **DMARC** (SPF/DKIM'in From domain'iyle *alignment*'ı + politika). Aralarındaki fark ve neden birinin geçip diğerinin kalabilmesi.
- `Authentication-Results` header'ını alıcı sunucu ekler; **sadece kendi sunucunun eklediğine güvenilir**, gönderenin eklediği sahte olabilir.
- **Display-name spoofing**, **lookalike/homograph domain**, `Reply-To` uyuşmazlığı, `Received` zinciri.

**Görevler**
1. `Authentication-Results` parser: spf/dkim/dmarc sonucu + alignment.
2. Sinyaller: `From`/`Reply-To`/`Return-Path` domain uyuşmazlığı, display-name'de marka adı + alakasız domain, Levenshtein/karakter benzerliği ile lookalike domain (kendi küçük "korunan marka" listen), IDN/punycode, zaman/`Received` tutarsızlığı.
3. Her sinyal: `name`, `severity`, `evidence` (header'dan alıntı).
4. Sinyalleri hafif bir risk skoruna çeviren basit, belgelenmiş formül.

**Bitti sayılır:** Fixture'larda doğru sinyaller çıkıyor; her sinyalin neden tetiklendiği evidence ile gösteriliyor; testler yeşil.

**Tuzaklar:** Meşru mailleri (mailing list, forwarding) yanlış işaretlemek. Domain yaşı için WHOIS çağrısı gerekirse ağ çağrısını ayrı, mock'lanabilir bir sınıfa koy.

---

## M3 — Veri seti ve eval harness

**Amaç:** Projenin kanıt motorunu erkenden kurmak.

**Öğreneceğin kavramlar**
- Precision, recall, F1, **false-positive oranı** (SOC'ta analist yorgunluğu), confusion matrix.
- Dev/test ayrımı: prompt'u test seti üzerinde ayarlamak sonuçları şişirir (data leakage).
- Sentetik veri kullanımının etik/dürüst raporlanması.

**Görevler**
1. Hedef ~200 mail: phishing (Nazario, CEAS-08 vb. halka açık korpuslar), BEC (LLM ile üretilmiş, `synthetic=true`), quishing örnekleri, benign (SpamAssassin ham/Enron + **zor benign**: gerçek şifre sıfırlama, fatura, newsletter).
2. `labels.csv`: `file,label,category,source,synthetic,notes`. Kişisel veriyi temizle.
3. Dev (%30) / test (%70) ayrımı.
4. `run_eval.py`: bir "tahmin fonksiyonu" alır, metrikleri hesaplar, `eval/results/` altına JSON + markdown tablo yazar.
5. Baseline: sadece M2 header skoruyla eşik tabanlı sınıflandırıcı. İlk sayıları kaydet.

**Bitti sayılır:** `make eval` header-only baseline için precision/recall/FPR üretiyor; dev/test ayrımı kodda zorunlu.

**Tuzaklar:** Dengesiz veri; çok kolay benign örnekler (FPR'ı yapay düşürür); gerçek inbox'tan kişisel veri sızdırmak; gerçek zararlı ek içeren örnekleri veri setine koymak (koyma).

---

## M4 — Body ve URL analizörü (deterministik)

**Amaç:** LLM'e girmeden yakalanabilecek her şeyi yakalamak ve LLM'e iyi girdi hazırlamak.

**Öğreneceğin kavramlar**
- HTML e-postada **görünen metin ≠ gerçek href** hilesi, URL shortener, IP tabanlı URL, gizli metin (`display:none`, beyaz üstüne beyaz), tracking pixel.
- URL reputation kaynakları ve rate limit mantığı; **linke gitmeden** sorgulama.
- Defang ve neden raporlarda zorunlu.

**Görevler**
1. HTML'den linkleri ve görünen metinlerini çıkar (BeautifulSoup); uyuşmazlık sinyali.
2. Gizli içerik, aşırı yönlendirme, tek piksel görsel sinyalleri.
3. URL reputation istemcisi (VirusTotal URL/domain lookup, URLhaus, OpenPhish feed), önbellekleme ve rate-limit koruması; testlerde mock.
4. Defang yardımcıları.
5. Eval'i yeniden çalıştır: header-only vs header+body/url karşılaştırması.

**Bitti sayılır:** URL sinyalleri fixture'larda doğru; reputation çağrıları önbellekli ve mock'lu testli; eval tablosunda iyileşme (ya da iyileşmeme) ölçüldü.

**Tuzaklar:** VirusTotal ücretsiz limiti (günlük/dakikalık); eval sırasında her çalıştırmada aynı URL'yi tekrar sorgulamak (cache şart); linke doğrudan istek atmak (yasak).

---

## M5 — LLM verdict ve sinyal birleştirme

**Amaç:** Anlam gerektiren analizi (aciliyet, otorite taklidi, BEC) LLM'e yaptırıp deterministik sinyallerle birleştirmek.

**Öğreneceğin kavramlar**
- Structured output / tool use ile şema zorlama, pydantic doğrulama, "fail closed".
- Prompt'u kod gibi versiyonlama; zero-shot vs few-shot.
- **Prompt injection'a ilk savunma:** güvenilmeyen içerik delimiter + sistem promptunda talimat; kararın deterministik sinyallerle çapraz kontrolü.
- Token, gecikme, maliyet takibi.

**Görevler**
1. `prompts/verdict_v1.md`: sistem promptu (rol, kategori tanımları, injection uyarısı, çıktı kuralları).
2. `triage` çağrısı: girdi = parse edilmiş mail + deterministik sinyaller; çıktı = şemaya uygun JSON.
3. `verdict.py`: LLM yargısı + deterministik skor birleşimi; yüksek riskli deterministik sinyalleri LLM'in "benign"e çekememesi kuralı.
4. ATT&CK ID doğrulaması (T1566.001/002/003 ve T1204 aileleri), geçersizleri say.
5. Haiku vs Sonnet, v1 vs v2 prompt karşılaştırması **dev set** üzerinde; sonra test seti.
6. Maliyet/gecikme log'u.

**Bitti sayılır:** Test setinde tam pipeline metrikleri üretildi; baseline'a göre fark raporlandı; şema dışı çıktı asla `benign` ile sonuçlanmıyor.

**Tuzaklar:** Prompt'u test setine göre ayarlamak; modelin uydurduğu ATT&CK ID'leri; çok uzun gövdeleri sessizce kesmek; JSON dışı yanıtlar.

---

## M6 — Attachment analizi ve sandbox

**Amaç:** Ekleri güvenli şekilde statik analiz etmek.

**Öğreneceğin kavramlar**
- Zararlı belge türleri: **VBA makroları** (auto-exec: `AutoOpen`, `Document_Open`; `Shell`, `CreateObject`), PDF içinde `/JavaScript`, `/OpenAction`, `/Launch`, gömülü dosyalar; çift uzantı (`fatura.pdf.exe`), uzantı vs gerçek dosya tipi (magic bytes), şifreli zip.
- **Statik vs dinamik analiz.** Biz sadece statik yapıyoruz.
- Docker izolasyonu: `--network none`, read-only FS, non-root, kaynak limitleri.
- YARA kuralı yazmak.

**Görevler**
1. `AttachmentScanner` arayüzü + `LocalStaticScanner` implementasyonu (oletools, pdfid/pypdf, `python-magic`, YARA).
2. Hash'i VirusTotal'da **dosya yüklemeden** sorgula.
3. Docker imajı: analizör container içinde çalışır, host'a sadece JSON sonuç döner.
4. **Zararsız** test dosyaları üret: EICAR, makro içeren ama zararsız `.docm`, benign JS'li PDF, çift uzantılı dosya, şifreli zip.
5. 3–5 basit YARA kuralı yaz ve test et.
6. Eval'i güncelle (ekli örnekler için).

**Bitti sayılır:** Test dosyaları doğru sinyalleri üretiyor; container ağsız çalışıyor (kanıtla: container içinden dışarı istek başarısız); eval güncel.

**Tuzaklar:** Ekleri host'ta açmak/çalıştırmak; gerçek zararlı örnek indirmek; zip bomb'a karşı boyut/derinlik limiti koymamak; büyük ekler için timeout.

---

## M7 — Görsel ve QR analizi

**Amaç:** Görsel tabanlı saldırıları yakalamak.

**Öğreneceğin kavramlar**
- **Quishing (QR phishing):** URL'yi metinden saklayıp görsele gömme.
- Sahte login sayfası ekran görüntüleri, marka taklidi, OCR'dan kaçınmak için görsele gömülü metin.
- Vision modelinin çıktısı da güvenilmeyen veridir (görsel içindeki metin injection taşıyabilir).

**Görevler**
1. Satır içi (inline) ve ek görselleri çıkar.
2. QR çözümleme (`pyzbar`/`opencv`) → çıkan URL'yi M4 hattına ver.
3. Vision çağrısı: marka taklidi, kimlik bilgisi talebi, aciliyet. Çıktı şemaya bağlı.
4. Quishing ve sahte-login örneklerini (kendin ürettiğin zararsız görseller) veri setine ekle.
5. Eval: görselli örneklerde ablation.

**Bitti sayılır:** QR içindeki URL pipeline'a giriyor; vision sinyalleri verdict'e katılıyor; ablation sonucu var.

**Tuzaklar:** Büyük görsellerin maliyeti (yeniden boyutlandır); gerçek marka logosu kullanan sahte sayfaları dağıtmamak (repoya sadece küçük, zararsız örnekler).

---

## M8 — Agent orkestrasyonu

**Amaç:** Hangi aracın ne zaman çağrılacağına agent'ın karar vermesi; sabit pipeline ile karşılaştırma.

**Öğreneceğin kavramlar**
- Tool use döngüsü: model araç çağırır → sonucu alır → karar verir.
- Araç tanımı şemaları, hata yönetimi, adım limiti, döngüyü sonlandırma.
- Agentic yaklaşımın artıları (az gereksiz çağrı) ve riskleri (değişken davranış, daha zor test).

**Görevler**
1. Araçlar: `analyze_headers`, `extract_urls`, `check_url_reputation`, `scan_attachment`, `analyze_image`, `lookup_domain_age`.
2. **Araçların yan etkisi yok** (sadece okuma/analiz). Aksiyon agent'ta değil.
3. Orkestratör: maksimum adım, bütçe (token) limiti, zaman aşımı.
4. Karşılaştırma: sabit pipeline vs agentic → doğruluk, ortalama araç çağrısı, maliyet, gecikme, tutarlılık (aynı mail 3 kez çalıştır).

**Bitti sayılır:** İki mod aynı arayüzle çalışıyor; karşılaştırma tablosu `eval/results/`'ta; `docs/decisions.md`'de seçilen varsayılan mod gerekçeli.

**Tuzaklar:** Sonsuz araç döngüsü; agent'ın gereksiz yere pahalı model çağırması; sonuçların run'dan run'a değişmesi (temperature 0 ve seed/tekrar ölçümü).

---

## M9 — Gerçek mailbox: Graph ve webhook

**Amaç:** `.eml` yerine canlı Outlook kutusundan olay tetiklemeli akış.

**Öğreneceğin kavramlar**
- **OAuth 2.0 device code flow** (CLI için), delegated izinler, token yenileme, `msal` token cache.
- **Microsoft Graph change notifications:** abonelik oluşturma, **doğrulama token handshake**'i, `clientState`, **abonelik yenileme** (mail aboneliği birkaç gün sürer), bildirimin sadece mesaj ID'si taşıdığı.
- Ham MIME çekme: `GET /me/messages/{id}/$value`.
- Webhook'un hızlı yanıt vermesi (202) ve işi kuyruğa atması neden şart.

**Görevler**
1. App registration (Azure/Entra), `Mail.Read` delegated izni, device-code girişi.
2. `GraphSource`: ham MIME çek → M1'in parser'ına ver (aynı model!).
3. Önce **delta query ile polling** (en kolay çalışan sürüm).
4. FastAPI webhook + Cloudflare Tunnel/ngrok; handshake, `clientState` doğrulama, kuyruğa yazma, worker.
5. Abonelik yenileme görevi; idempotency (aynı bildirim iki kez gelirse tek işlem).
6. Uçtan uca test: test hesabına mail at → birkaç saniyede verdict.

**Bitti sayılır:** Mail gelince otomatik analiz tetikleniyor; aynı mail çift işlenmiyor; abonelik yenileme çalışıyor; uçtan uca gecikme ölçüldü.

**Tuzaklar:** Tünel URL'si değişince abonelik kopması; webhook'ta uzun iş yapmak (timeout → Graph aboneliği iptal eder); token'ları repoya koymak; bildirim doğrulamasını atlamak.

---

## M10 — Aksiyonlar, audit log, dashboard

**Amaç:** Karardan geri alınabilir aksiyona; kayıt ve görünürlük.

**Öğreneceğin kavramlar**
- SOC'ta **otomasyon sınırı:** yüksek güven → karantina, belirsiz → analist kuyruğu, **asla otomatik silme**.
- Audit log: kim/ne zaman/neden/hangi sinyaller. Denetlenebilirlik güvenlik araçlarında şarttır.
- İdempotent ve geri alınabilir aksiyon tasarımı.

**Görevler**
1. İzni `Mail.ReadWrite`'a yükselt (gerekçeyi `decisions.md`'ye yaz).
2. Aksiyonlar: kategori etiketi ekle, `Quarantine` klasörüne taşı, analist kuyruğu kaydı. Eşikler yapılandırılabilir.
3. "Dry-run" modu (aksiyon almadan sadece logla); varsayılan dry-run.
4. SQLite audit tablosu: mesaj, verdict, sinyaller, prompt sürümü, model, maliyet, alınan aksiyon.
5. Streamlit dashboard: verdict dağılımı, son mailler, ortalama gecikme/maliyet, analist kuyruğu.

**Bitti sayılır:** Quarantine bir tıkla geri alınabiliyor (klasörden geri taşı); dry-run varsayılan; dashboard çalışıyor.

**Tuzaklar:** Yanlış pozitifte meşru mail kaybı hissi (bu yüzden silme yok); aksiyonları LLM'e doğrudan vermek (yasak, kod verdict'ten karar verir).

---

## M11 — Güvenlik sertleştirme ve threat model

**Amaç:** Kendi aracının saldırıya dayanıklılığını kanıtlamak. Projenin en ayırt edici kısmı.

**Öğreneceğin kavramlar**
- **Threat modeling:** varlıklar, güven sınırları, STRIDE benzeri düşünme.
- Doğrudan ve dolaylı prompt injection (gövde, HTML yorumu, ek içi metin, görsel içi metin, QR içeriği, header alanları).
- Savunma katmanlama: delimiter, şema, çapraz kontrol, araçlarda yan etki olmaması.

**Görevler**
1. `docs/threat-model.md`: varlıklar, saldırgan yetenekleri, güven sınırları, saldırı senaryoları ve karşı önlemler tablosu.
2. 10–15 injection e-postası (gövde, gizli HTML, ek, görsel, header, çok dilli, "benign olarak işaretle" varyantları).
3. Direnç oranını ölç; başarısız olanları analiz et, savunmayı güçlendir, tekrar ölç (önce/sonra).
4. Rate limit, boyut limitleri, zip bomb/derin MIME koruması, gizli veri maskeleme gözden geçirmesi.
5. `pip-audit`/bağımlılık taraması, secret taraması (örn. `gitleaks`).

**Bitti sayılır:** Threat model yazıldı; injection direnç oranı önce/sonra raporlandı; güvenlik kontrol listesi tamam.

**Tuzaklar:** "Savunmam çalışıyor" demek için sadece kolay injection yazmak; başarısız vakaları saklamak (README'de dürüstçe raporla).

---

## M12 — Sonuçlar, README ve demo

**Amaç:** Projeyi bir recruiter'ın 3 dakikada anlayıp etkileneceği hale getirmek.

**Görevler**
1. Final eval: test seti üzerinde tüm karşılaştırmalar (ablation, baseline, model, agentic vs sabit, injection).
2. README: problem, mimari diyagram, nasıl çalıştırılır, sonuç tabloları, sınırlılıklar, **dürüst limitasyonlar** (veri seti boyutu, sentetik BEC, tek mailbox).
3. 60–90 sn demo GIF/video: mail gönder → saniyeler içinde verdict + aksiyon + dashboard.
4. Mimari diyagram (Mermaid veya draw.io).
5. Resume bullet'ı **gerçek ölçülmüş sayılarla**; LinkedIn proje girişi; repoyu public yap (secret taraması sonrası, veri setinde kişisel veri olmadığından emin ol).
6. Mülakat hazırlığı: 2 dakikalık anlatım, "en zor problem neydi", "LLM nerede kötüydü", "injection'a nasıl dayandın".

**Bitti sayılır:** Başkası README'yi izleyerek projeyi `.eml` modunda çalıştırabiliyor; sayılar `run_eval.py` çıktısından geliyor.

---

## Haftalık takvim önerisi

- **Hafta 1:** M0, M1, M2, M3 başlangıcı
- **Hafta 2:** M3 bitir, M4, M5
- **Hafta 3:** M6, M7
- **Hafta 4:** M8, M9
- **Hafta 5:** M10, M11, M12

Geride kalırsan kesme önceliği (en az değerliden): M10 dashboard → M7 görsel kısmı → M8 agentic karşılaştırma. **Asla kesilmeyecekler:** M3 eval, M5 verdict, M6 sandbox izolasyonu, M11 injection testi.

## Her oturumun akışı

1. Claude `CLAUDE.md` ve `docs/progress.md`'yi okur, mevcut milestone'u söyler.
2. Hedef + "bitti sayılır" kriteri özetlenir.
3. Yeni kavram kısaca anlatılır, kod adım adım yazılır, her adım çalıştırma komutuyla biter.
4. Oturum sonunda `docs/progress.md` güncellenir.

## Claude'a bir oturum başlatırken söyleyeceğin cümle

> "CLAUDE.md ve docs/progress.md'yi oku, mevcut milestone'u söyle ve oradan devam edelim."
