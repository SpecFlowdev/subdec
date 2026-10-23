#!/usr/bin/env python3
"""subdec — достаёт JSON из VPN-подписок.

Понимает: URL подписки, base64 (обычный/urlsafe/вложенный), списки ссылок
(vless, vmess, trojan, ss, hysteria2, tuic), готовый JSON, happ://add/ и
happ://crypt*/ (RSA, нужен ваш приватный ключ). Только стандартная библиотека.
"""
import argparse
import base64
import binascii
import json
import re
import sys
import urllib.request
from urllib.parse import parse_qsl, unquote, urlsplit

__version__ = "1.0.0"
SCHEMES = ("vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic", "wireguard")


class DecodeError(Exception):
    pass


# ---------- base64 ----------

def b64decode_loose(text):
    """Декодирует base64 / urlsafe без паддинга. Возвращает bytes или None."""
    s = re.sub(r"\s+", "", text)
    if not s or not re.fullmatch(r"[A-Za-z0-9+/_\-]+={0,2}", s):
        return None
    s = s.rstrip("=").replace("-", "+").replace("_", "/")
    if len(s) % 4 == 1:
        return None
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def as_text(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(c.isprintable() or c in "\r\n\t" for c in text)
    return text if text and printable / len(text) > 0.95 else None


# ---------- минимальный RSA PKCS#1 v1.5 (без зависимостей) ----------

def _der(data, pos=0):
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, data[pos:pos + length], pos + length


def _der_seq(data):
    tag, body, _ = _der(data)
    if tag != 0x30:
        raise DecodeError("ключ: ожидалась ASN.1 SEQUENCE")
    items, pos = [], 0
    while pos < len(body):
        t, v, pos = _der(body, pos)
        items.append((t, v))
    return items


def load_rsa_key(pem):
    """Возвращает (n, d) из PEM PKCS#1 или PKCS#8 приватного ключа."""
    m = re.search(r"-----BEGIN ([A-Z ]*PRIVATE KEY)-----(.+?)-----END", pem, re.S)
    if not m:
        raise DecodeError("ключ: PEM приватный ключ не найден")
    if m.group(1) == "ENCRYPTED PRIVATE KEY":
        raise DecodeError("ключ: зашифрованные ключи не поддерживаются")
    der = base64.b64decode(re.sub(r"\s+", "", m.group(2)))
    items = _der_seq(der)
    if m.group(1) == "PRIVATE KEY":  # PKCS#8: version, algId, OCTET STRING
        der = items[2][1]
        items = _der_seq(der)
    ints = [int.from_bytes(v, "big") for t, v in items if t == 0x02]
    if len(ints) < 4:
        raise DecodeError("ключ: это не RSA-ключ")
    return ints[1], ints[3]  # n, d


def rsa_decrypt(data, key_pem):
    n, d = load_rsa_key(key_pem)
    k = (n.bit_length() + 7) // 8
    if len(data) % k:
        raise DecodeError(f"шифртекст ({len(data)} байт) не кратен размеру ключа ({k})")
    out = b""
    for i in range(0, len(data), k):
        em = pow(int.from_bytes(data[i:i + k], "big"), d, n).to_bytes(k, "big")
        if em[:2] != b"\x00\x02" or b"\x00" not in em[2:]:
            raise DecodeError("RSA: неверный ключ или паддинг")
        out += em[em.index(b"\x00", 2) + 1:]
    return out


# ---------- разбор ссылок ----------

def parse_link(link):
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        raw = b64decode_loose(link[8:].split("#")[0])
        text = as_text(raw) if raw else None
        if text:
            try:
                return {"protocol": "vmess", **json.loads(text)}
            except json.JSONDecodeError:
                pass
        return {"protocol": "vmess", "raw": link}
    if scheme == "ss":
        return _parse_ss(link)
    u = urlsplit(link)
    out = {"protocol": scheme, "name": unquote(u.fragment) or None,
           "host": u.hostname, "port": u.port}
    if u.username:
        out["user"] = unquote(u.username)
    if u.password:
        out["password"] = unquote(u.password)
    out["params"] = dict(parse_qsl(u.query))
    return {k: v for k, v in out.items() if v not in (None, {})}


def _parse_ss(link):
    body, _, frag = link[5:].partition("#")
    body, _, query = body.partition("?")
    out = {"protocol": "ss", "name": unquote(frag) or None}
    if "@" not in body:
        raw = b64decode_loose(body)
        body = as_text(raw) if raw else body
    cred, _, hostport = body.rpartition("@")
    if ":" not in cred:
        raw = b64decode_loose(unquote(cred))
        cred = as_text(raw) if raw else cred
    method, _, password = cred.partition(":")
    host, _, port = hostport.rpartition(":")
    out.update(method=method, password=password, host=host.strip("[]"),
               port=int(port) if port.isdigit() else None)
    if query:
        out["params"] = dict(parse_qsl(query))
    return {k: v for k, v in out.items() if v is not None}


# ---------- основной разбор ----------

def fetch(url, ua="Happ/1.0", headers=None, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": ua, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(), dict(r.headers)


def decode(text, *, key_pem=None, do_fetch=True, ua="Happ/1.0", headers=None,
           _steps=None, _depth=0):
    """Возвращает {'steps': [...], 'links': [...], 'configs': [...], 'json': ...}."""
    steps = _steps if _steps is not None else []
    if _depth > 8:
        raise DecodeError("слишком глубокая вложенность")
    text = text.strip().lstrip("﻿")
    if not text:
        raise DecodeError("пустой ввод")
    rec = lambda t: decode(t, key_pem=key_pem, do_fetch=do_fetch, ua=ua,
                           headers=headers, _steps=steps, _depth=_depth + 1)

    m = re.match(r"happ://(crypt\d*)/(.+)", text, re.S | re.I)
    if m:
        steps.append(f"happ:{m.group(1).lower()}")
        if not key_pem:
            raise DecodeError(
                f"{m.group(1)}: ссылка зашифрована RSA. Нужен ваш приватный ключ "
                "(--key key.pem); публичных ключей нет.")
        raw = b64decode_loose(unquote(m.group(2)))
        if raw is None:
            raise DecodeError("crypt: не удалось декодировать base64")
        return rec(rsa_decrypt(raw, key_pem).decode("utf-8", "replace"))

    m = re.match(r"happ://add/(.+)", text, re.S | re.I)
    if m:
        steps.append("happ:add")
        return rec(unquote(m.group(1)))

    if re.match(r"https?://\S+$", text):
        if not do_fetch:
            raise DecodeError("это URL; уберите --no-fetch, чтобы скачать подписку")
        steps.append("http-fetch")
        body, hdrs = fetch(text, ua, headers)
        res = rec(body.decode("utf-8", "replace"))
        res["headers"] = {k: v for k, v in hdrs.items() if k.lower().startswith(
            ("profile-", "subscription-", "content-disposition", "routing", "announce"))}
        return res

    if text[0] in "{[":
        try:
            data = json.loads(text)
            steps.append("json")
            return {"steps": steps, "links": [], "configs": [], "json": data}
        except json.JSONDecodeError:
            pass

    lines = [l.strip() for l in text.splitlines() if l.strip()]
    links = [l for l in lines if l.split("://", 1)[0].lower() in SCHEMES and "://" in l]
    if links:
        steps.append("links")
        return {"steps": steps, "links": links,
                "configs": [parse_link(l) for l in links], "json": None}

    raw = b64decode_loose(text)
    inner = as_text(raw) if raw else None
    if inner:
        steps.append("base64")
        return rec(inner)

    raise DecodeError("формат не распознан")


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="subdec", description="Достаёт JSON из VPN-подписок (URL, base64, Happ).")
    p.add_argument("source", nargs="?", help="URL, строка, путь к файлу или '-' для stdin")
    p.add_argument("-k", "--key", help="PEM приватный RSA-ключ для happ://crypt*")
    p.add_argument("-o", "--output", help="записать результат в файл")
    p.add_argument("--only", choices=["configs", "links", "json"],
                   help="вывести только выбранную часть")
    p.add_argument("--no-fetch", action="store_true", help="не скачивать http(s) URL")
    p.add_argument("--ua", default="Happ/1.0", help="User-Agent (по умолч. Happ/1.0)")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="доп. заголовок 'Имя: значение' (можно несколько)")
    p.add_argument("--compact", action="store_true", help="JSON в одну строку")
    p.add_argument("-V", "--version", action="version", version=__version__)
    a = p.parse_args(argv)

    src = a.source
    if src in (None, "-"):
        if src is None and sys.stdin.isatty():
            p.error("укажите источник или передайте данные через stdin")
        src = sys.stdin.read()
    elif not re.match(r"[a-z]+://", src, re.I):
        try:
            with open(src, encoding="utf-8") as f:
                src = f.read()
        except OSError:
            pass  # считаем строкой (например, голый base64)

    try:
        key = open(a.key, encoding="utf-8").read() if a.key else None
        headers = dict(h.split(":", 1) for h in a.header)
        headers = {k.strip(): v.strip() for k, v in headers.items()}
        res = decode(src, key_pem=key, do_fetch=not a.no_fetch, ua=a.ua, headers=headers)
    except (DecodeError, OSError, ValueError) as e:
        print(f"subdec: ошибка: {e}", file=sys.stderr)
        return 1

    out = res[a.only] if a.only else res
    text = json.dumps(out, ensure_ascii=False, indent=None if a.compact else 2)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
