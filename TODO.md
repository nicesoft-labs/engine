# ✅ TODO.md — План полного внедрения GOST Provider для OpenSSL 3.0

## 📌 Цель

Расширить экспериментальный GOST Provider до полноценной поддержки TLS и OpenVPN:

- Полный KEYMGMT (создание, генерация, импорт/экспорт GOST-ключей)
- ENCODER/DECODER (PEM/DER)
- SIGNATURE (цифровая подпись)
- ASYM_CIPHER (ключевой обмен, шифрование)
- Интеграция с TLS handshake
- Проверка с OpenVPN
- Актуальная документация и готовые примеры

---

## 🗂️ Этапы

### 1️⃣ Этап 1 — Реализовать KEYMGMT

- [ ] **Файл:** `gost_prov_keymgmt.c`
- [ ] Определить `GOST_KEYMGMT_CTX` и реализовать:
  - `newctx`
  - `freectx`
  - `gen_init`
  - `gen`
  - `load`
  - `get_params`
  - `export`
  - `import`
- [ ] Использовать `gost_ec_keygen` и `gost_ec_compute_public` из `gost_ec_sign.c`
- [ ] Зарегистрировать алгоритмы `gost2001`, `gost2012_256`, `gost2012_512`
- [ ] Добавить `OSSL_OP_KEYMGMT` в `gost_operation()` в `gost_prov.c`
- [ ] Обновить `CMakeLists.txt`
- [ ] Добавить тест `test_keymgmt.c`:
  - Генерация ключа через провайдер
  - Экспорт/импорт структуры ключа
  - Проверка параметров ключа

---

### 2️⃣ Этап 2 — Реализовать ENCODER/DECODER

- [ ] **Файлы:** `gost_prov_encoder.c`, `gost_prov_decoder.c`
- [ ] Использовать ASN.1 схемы из `gost_asn1.c`
- [ ] Реализовать `OSSL_FUNC_encoder_*` и `OSSL_FUNC_decoder_*`
- [ ] Зарегистрировать `OSSL_OP_ENCODER` и `OSSL_OP_DECODER` в `gost_operation()`
- [ ] Обновить `CMakeLists.txt`
- [ ] Добавить тест `test_encoder_decoder.c`:
  - Генерация ключа
  - Экспорт PEM/DER
  - Импорт обратно
  - Проверка совпадения ключей

---

### 3️⃣ Этап 3 — Реализовать SIGNATURE

- [ ] **Файл:** `gost_prov_signature.c`
- [ ] Определить `GOST_SIGNATURE_CTX` и реализовать `OSSL_FUNC_signature_*`
- [ ] Использовать `gost_ec_sign` и `gost_ec_verify` из `gost_ec_sign.c`
- [ ] Зарегистрировать `OSSL_OP_SIGNATURE` в `gost_operation()`
- [ ] Обновить `CMakeLists.txt`
- [ ] Добавить `test_signature.c`:
  - Генерация ключа через KEYMGMT
  - Подпись случайного сообщения
  - Проверка подписи
  - Проверка отказа при изменении данных

---

### 4️⃣ Этап 4 — Реализовать ASYM_CIPHER

- [ ] **Файл:** `gost_prov_asymcipher.c`
- [ ] Определить `GOST_ASYM_CIPHER_CTX` и реализовать `OSSL_FUNC_asym_cipher_*`
- [ ] Использовать `pkey_gost_encrypt`, `pkey_gost_decrypt`, `VKO_compute_key`, `gost_kexp15`, `gost_kimp15` из `gost_ec_keyx.c`
- [ ] Зарегистрировать `OSSL_OP_ASYM_CIPHER` в `gost_operation()`
- [ ] Обновить `CMakeLists.txt`
- [ ] Добавить `test_asymcipher.c`:
  - Зашифровать случайный ключ
  - Расшифровать и сравнить с исходным

---

### 5️⃣ Этап 5 — Интеграция с TLS Handshake

- [ ] **Файл:** `test_tls.c`
- [ ] Добавить режим использования провайдера
- [ ] Сгенерировать self-signed GOST сертификат
- [ ] Проверить `openssl s_server` и `openssl s_client` с новым ключом и подписью
- [ ] Обновить конфигурацию `provider.cnf` при необходимости

---

### 6️⃣ Этап 6 — Проверка OpenVPN

- [ ] Скомпилировать OpenVPN с поддержкой OpenSSL 3.0
- [ ] Сгенерировать ключи и сертификаты через провайдер
- [ ] Настроить сервер и клиент OpenVPN
- [ ] Выполнить handshake и передачу данных
- [ ] Документировать рабочую конфигурацию и параметры

---

### 7️⃣ Этап 7 — Документация и примеры

- [ ] Обновить `README.prov.md`:
  - Как подключить провайдер
  - Генерация ключей и сертификатов
  - Экспорт/импорт
  - Примеры команд

- [ ] Обновить `README.gost`:
  - Как использовать Provider вместо Engine
  - Особенности и ограничения

- [ ] Примеры команд:

  ```bash
  openssl genpkey -provider gostprov -algorithm gost2012_256
  openssl pkey -in key.pem -text
  openssl req -new -x509 -key key.pem -out cert.pem
