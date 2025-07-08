# engine

A reference implementation of the Russian GOST crypto algorithms for OpenSSL

Compatibility: OpenSSL 3.0

License: same as the corresponding version of OpenSSL.

Mailing list: http://www.wagner.pp.ru/list-archives/openssl-gost/

Some useful links: https://www.altlinux.org/OSS-GOST-Crypto

DO NOT TRY BUILDING MASTER BRANCH AGAINST openssl 1.1.1! Use 1_1_1 branch instead!

# provider

A reference implementation in the same spirit as the engine, specified
above.

This is currently work in progress, with only a subset of all intended
functionality implemented: symmetric ciphers, hashes and MACs.

For more information, see [README.prov.md](README.prov.md)

## Загрузка и поиск провайдеров OpenSSL

По умолчанию OpenSSL 3.x ищет скомпилированные модули-провайдеры (shared libraries) в системном каталоге (обычно `/usr/lib/x86_64-linux-gnu/ossl-modules`) или в тех путях, что прописаны в конфиге `openssl.cnf`.

### Локальная сборка

Если вы собираете и тестируете `gostprov` прямо в дереве сборки, то после `cmake && cmake --build .`:

```bash
# Указываем, где искать модули-провайдеры:
export OPENSSL_MODULES=$(pwd)/bin
# (При необходимости) указываем кастомный конфиг:
export OPENSSL_CONF=$(pwd)/test/openssl.cnf
ctest
