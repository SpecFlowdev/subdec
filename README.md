<div align="center">

# subdec

**Достаёт JSON из VPN-подписок — в один шаг.**

base64 · списки ссылок · готовый JSON · Happ · без зависимостей

[**Открыть веб-версию →**](https://specflowdev.github.io/subdec/)

</div>

---

## Возможности

| Формат | Поддержка |
|---|---|
| Обычный и urlsafe base64, в том числе без `=` и вложенный | ✅ |
| Списки `vless://` `vmess://` `trojan://` `ss://` `hysteria2://` `hy2://` `tuic://` | ✅ разбираются в поля |
| Готовый JSON (Xray / sing-box и т. п.) | ✅ |
| `happ://add/…` | ✅ |
| `happ://crypt/`, `crypt2`, `crypt3` (RSA-4096) | ✅ **с вашим приватным ключом** |
| `happ://crypt5` | ❌ не поддерживается |
| `http(s)://` URL подписки | ✅ в CLI (скачивает сам), в вебе — вставьте содержимое |

Цепочка форматов определяется автоматически: `happ:crypt3 → base64 → links` и т. д. Все шаги показываются в выводе.

## Быстрый старт (CLI)

Нужен только Python 3.8+.

```bash
git clone https://github.com/SpecFlowdev/subdec && cd subdec

python3 subdec.py "https://example.com/sub/TOKEN"      # URL подписки
python3 subdec.py sub.txt                              # файл
echo "dmxlc3M6Ly8..." | python3 subdec.py -            # stdin
python3 subdec.py "happ://add/https://example.com/sub" # happ-ссылка
```

### Пример вывода

```json
{
  "steps": ["http-fetch", "base64", "links"],
  "links": ["vless://…@example.com:443?security=reality#Node"],
  "configs": [
    {
      "protocol": "vless",
      "name": "Node",
      "host": "example.com",
      "port": 443,
      "user": "11111111-2222-3333-4444-555555555555",
      "params": { "security": "reality" }
    }
  ],
  "json": null
}
```

### Опции

| Флаг | Описание |
|---|---|
| `-k, --key FILE` | PEM-ключ для `happ://crypt*` |
| `-o, --output FILE` | записать результат в файл |
| `--only configs\|links\|json` | вывести только одну часть |
| `--ua UA` | User-Agent при скачивании (по умолч. `Happ/1.0`) |
| `-H "Имя: значение"` | доп. заголовок, можно повторять |
| `--no-fetch` | не ходить в сеть |
| `--compact` | JSON в одну строку |

Из ответа сервера сохраняются полезные заголовки (`profile-title`, `subscription-userinfo` и т. п.) в поле `headers`.

## Happ и шифрование

Ссылки `happ://crypt`, `crypt2`, `crypt3` зашифрованы RSA-4096 (PKCS#1 v1.5). Приватные ключи встроены в клиент Happ и **не входят в этот проект** — subdec их не содержит и не добывает.

Если у вас есть собственный приватный ключ (например, вы генерируете такие ссылки сами), передайте его:

```bash
python3 subdec.py "happ://crypt3/…" --key my_private.pem
```

Поддерживаются PEM в форматах PKCS#1 (`BEGIN RSA PRIVATE KEY`) и PKCS#8 (`BEGIN PRIVATE KEY`) без пароля. Без ключа утилита сообщит, что ссылка зашифрована, и покажет определённый формат. Для `crypt5` и вопросов о доступе обращайтесь к владельцу подписки или в поддержку Happ.

## Веб-версия

[`docs/index.html`](docs/index.html) — одна страница без сборки и внешних запросов. Декодирование (включая RSA) идёт локально в браузере, данные никуда не отправляются. Ключ из поля тоже остаётся на вашем устройстве.

## Тесты

```bash
python3 -m unittest discover -s tests -v
```

RSA-тесты используют `openssl` и пропускаются, если его нет.

## Ответственность

Используйте инструмент только со своими подписками и данными, на которые у вас есть права. Подписки содержат личные токены — не публикуйте их в issue и логах.

## Лицензия

[MIT](LICENSE)
