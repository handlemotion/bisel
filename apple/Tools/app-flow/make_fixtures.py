import json, zipfile, sys, os
out = sys.argv[1]
def item(uuid, cat, title, **kw):
    d = {"uuid": uuid, "favIndex": 0, "createdAt": 1700000000, "updatedAt": 1710000000, "state": kw.pop("state", "active"),
         "categoryUuid": cat, "details": kw.pop("details", {}), "overview": {"title": title, "subtitle": "", "url": kw.pop("url", ""), "urls": kw.pop("urls", []), "tags": kw.pop("tags", []), "ps": 0}}
    return d
items = [
  item("a1", "001", "Acme Mail (FAKE)", url="https://mail.acme-fake.test", urls=[{"label":"website","url":"https://mail.acme-fake.test"}], tags=["work"],
       details={"loginFields":[{"value":"fake.user@acme-fake.test","name":"username","fieldType":"T","designation":"username"},{"value":"FAKE-pass-1","name":"password","fieldType":"P","designation":"password"}],
                "notesPlain":"fake login note",
                "sections":[{"title":"","name":"","fields":[{"title":"one-time password","id":"TOTP_1","value":{"totp":"otpauth://totp/Acme:fake?secret=JBSWY3DPEHPK3PXP&issuer=Acme&digits=6&period=30"}}]}]}),
  item("a2", "005", "Fake Wifi Password", details={"password":"FAKE-wifi-pass"}),
  item("a3", "003", "Fake Secure Note", details={"notesPlain":"line one\nline two (FAKE)"}),
  item("a4", "112", "Fake API Credential", url="https://api.fake.test", details={"sections":[{"title":"","name":"","fields":[{"title":"credential","id":"credential","value":{"concealed":"FAKE-sk_test_000"}},{"title":"hostname","id":"host","value":{"string":"api.fake.test"}}]}]}),
  item("a5", "001", "Old Archived Login", state="archived", details={"loginFields":[{"value":"x","designation":"username"}]}),
  item("a6", "001", "Passkey Site (FAKE)", url="https://passkey-fake.test",
       details={"loginFields":[{"value":"pk.user@fake.test","designation":"username"}],
                "sections":[{"title":"","name":"","fields":[{"title":"Passkey","id":"passkey","value":{"passkey":{"credentialId":"FAKECRED123","rpId":"passkey-fake.test","userHandle":"FAKEHANDLE","privateKey":"FAKE-PRIVATE-KEY-BLOB","counter":7}}}]}]}),
]
data = {"accounts":[{"attrs":{"accountName":"Fake","name":"Fake"},"vaults":[{"attrs":{"uuid":"v1","name":"Personal"},"items":items}]}]}
with zipfile.ZipFile(os.path.join(out, "fake-export.1pux"), "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("export.attributes", json.dumps({"version":3,"description":"1Password Unencrypted Export","createdAt":1710000000}))
    z.writestr("export.data", json.dumps(data))
open(os.path.join(out, "fake-logins.csv"), "w").write(
 'Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n'
 'CSV Shop (FAKE),https://shop.csv-fake.test,csv.user@fake.test,"FAKE,comma;pass",otpauth://totp/Shop:u?secret=GEZDGNBVGY3TQOJQ&issuer=Shop,0,0,"shopping;fake","multi\nline note"\n'
 'CSV Bank (FAKE),https://bank.csv-fake.test,bank.user,FAKE-bank-pass,,0,0,,\n'
 'CSV Note (FAKE),,,,,0,0,,only a note body\n')
# hostile archives (must be refused)
good = json.dumps(data)
with zipfile.ZipFile(os.path.join(out, "evil-dotdot.1pux"), "w") as z:
    z.writestr("export.data", good); z.writestr("../evil.txt", "x")
with zipfile.ZipFile(os.path.join(out, "evil-symlink.1pux"), "w") as z:
    z.writestr("export.data", good)
    info = zipfile.ZipInfo("link"); info.create_system = 3; info.external_attr = (0o120777 << 16)
    z.writestr(info, "/etc/passwd")
print("ok")
