import base64, json, os, shutil, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import subdec

VLESS = "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sni=a.com#My%20Node"
VMESS_OBJ = {"v": "2", "ps": "vm", "add": "1.2.3.4", "port": "443", "id": "abc"}
VMESS = "vmess://" + base64.b64encode(json.dumps(VMESS_OBJ).encode()).decode()
SS = "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:pw").decode().rstrip("=") + "@h.com:8388#ss1"
B64 = base64.b64encode("\n".join([VLESS, VMESS, SS]).encode()).decode()


class Decode(unittest.TestCase):
    def test_links(self):
        r = subdec.decode("\n".join([VLESS, VMESS, SS]))
        self.assertEqual([c["protocol"] for c in r["configs"]], ["vless", "vmess", "ss"])
        self.assertEqual(r["configs"][0]["name"], "My Node")
        self.assertEqual(r["configs"][0]["params"]["sni"], "a.com")
        self.assertEqual(r["configs"][1]["add"], "1.2.3.4")
        self.assertEqual(r["configs"][2]["method"], "aes-256-gcm")

    def test_base64_and_nested(self):
        r = subdec.decode(B64)
        self.assertEqual(r["steps"], ["base64", "links"])
        nested = base64.urlsafe_b64encode(B64.encode()).decode().rstrip("=")
        self.assertEqual(len(subdec.decode(nested)["configs"]), 3)

    def test_json(self):
        self.assertEqual(subdec.decode('{"a": 1}')["json"], {"a": 1})
        enc = base64.b64encode(b'{"outbounds": []}').decode()
        self.assertEqual(subdec.decode(enc)["json"], {"outbounds": []})

    def test_happ_add(self):
        self.assertEqual(len(subdec.decode("happ://add/" + B64)["configs"]), 3)

    def test_crypt_without_key(self):
        with self.assertRaises(subdec.DecodeError):
            subdec.decode("happ://crypt3/AAAA")

    def test_garbage(self):
        with self.assertRaises(subdec.DecodeError):
            subdec.decode("hello world!")


@unittest.skipUnless(shutil.which("openssl"), "нужен openssl")
class Rsa(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            key, msg, enc = (os.path.join(d, n) for n in ("k.pem", "m", "e"))
            for fmt in ("traditional", "pkcs8"):
                args = ["openssl", "genrsa", "-out", key, "2048"]
                subprocess.run(args, check=True, capture_output=True)
                if fmt == "traditional":
                    subprocess.run(["openssl", "rsa", "-in", key, "-traditional", "-out", key],
                                   check=True, capture_output=True)
                open(msg, "w").write(VLESS)
                subprocess.run(["openssl", "pkeyutl", "-encrypt", "-inkey", key, "-in", msg,
                                "-out", enc, "-pkeyopt", "rsa_padding_mode:pkcs1"],
                               check=True, capture_output=True)
                link = "happ://crypt3/" + base64.b64encode(open(enc, "rb").read()).decode()
                r = subdec.decode(link, key_pem=open(key).read())
                self.assertEqual(r["configs"][0]["host"], "example.com")
                self.assertEqual(r["steps"][0], "happ:crypt3")

    def test_wrong_key(self):
        with tempfile.TemporaryDirectory() as d:
            k1, k2, msg, enc = (os.path.join(d, n) for n in ("a", "b", "m", "e"))
            for k in (k1, k2):
                subprocess.run(["openssl", "genrsa", "-out", k, "2048"], check=True, capture_output=True)
            open(msg, "w").write("x")
            subprocess.run(["openssl", "pkeyutl", "-encrypt", "-inkey", k1, "-in", msg, "-out", enc,
                            "-pkeyopt", "rsa_padding_mode:pkcs1"], check=True, capture_output=True)
            link = "happ://crypt2/" + base64.b64encode(open(enc, "rb").read()).decode()
            with self.assertRaises(subdec.DecodeError):
                subdec.decode(link, key_pem=open(k2).read())


if __name__ == "__main__":
    unittest.main()
