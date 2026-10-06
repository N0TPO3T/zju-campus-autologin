"""ZJU SRun authentication. Standard-library-only; never logs out an online host."""
import argparse
import base64
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parent
DATA_DIR = (Path(os.environ['LOCALAPPDATA']) / 'ZjuCampusAutoLogin'
            if os.environ.get('LOCALAPPDATA')
            else Path.home() / '.local' / 'share' / 'ZjuCampusAutoLogin')
HOST = 'net.zju.edu.cn'
ALPHABET = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'
MASK = 0xffffffff


class CampusError(Exception):
    pass


def ensure_data_dir():
    """Protect the per-user directory before writing credentials or logs."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if os.name == 'nt':
            # Modify only the DACL: touching audit/owner sections can require
            # privileges unavailable to a normal scheduled-task user token.
            script = """
$ErrorActionPreference = 'Stop'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$path = $env:ZJU_AUTOLOGIN_DATA_DIR
$acl = [System.IO.Directory]::GetAccessControl(
    $path, [System.Security.AccessControl.AccessControlSections]::Access)
$acl.SetAccessRuleProtection($true, $false)
# Keep the explicit rules of both identities that may run this tool: the
# interactive user and SYSTEM. Only broad built-in groups are removed, so the
# user-session run and the session-independent run cannot strip each other.
$broad = @('S-1-1-0', 'S-1-5-7', 'S-1-5-11', 'S-1-5-32-545')
foreach ($rule in @($acl.GetAccessRules(
    $true, $false, [System.Security.Principal.SecurityIdentifier]))) {
    if ($broad -contains $rule.IdentityReference.Value) {
        $acl.RemoveAccessRuleSpecific($rule)
    }
}
foreach ($identity in @($sid, $system)) {
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $identity, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
[System.IO.Directory]::SetAccessControl($path, $acl)
"""
            environment = os.environ.copy()
            environment['ZJU_AUTOLOGIN_DATA_DIR'] = str(DATA_DIR)
            subprocess.run(
                ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                env=environment, check=True, capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            DATA_DIR.chmod(0o700)
    except (OSError, subprocess.SubprocessError):
        raise CampusError('Cannot protect the local application data directory') from None
    return DATA_DIR


def load_config():
    """Merge source defaults with the optional per-user runtime configuration."""
    try:
        config = json.loads((ROOT / 'config.example.json').read_text(encoding='utf-8'))
        if not isinstance(config, dict):
            raise ValueError
        override_path = DATA_DIR / 'config.json'
        if override_path.exists():
            override = json.loads(override_path.read_text(encoding='utf-8'))
            if not isinstance(override, dict):
                raise ValueError
            config.update(override)
        for key in ('campus_dns', 'bootstrap_ipv4'):
            addresses = config[key]
            if not isinstance(addresses, list) or not addresses:
                raise ValueError
            for address in addresses:
                if not isinstance(address, str):
                    raise ValueError
                ipaddress.IPv4Address(address)
        port = config['local_socks_port']
        if port is not None and (type(port) is not int or not 1 <= port <= 65535):
            raise ValueError
        acid = config['ac_id']
        if not isinstance(acid, str) or re.fullmatch(r'[0-9]+', acid) is None:
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        raise CampusError('Invalid or unreadable local configuration; check config.json') from None
    return config


def xencode(text, key):
    # Match the portal's JavaScript UTF-16 code units, including non-ASCII passwords.
    def words(value, include_length):
        raw = value.encode('utf-16-le', errors='surrogatepass')
        units = list(struct.unpack('<' + 'H' * (len(raw) // 2), raw))
        result = []
        for pos in range(0, len(units), 4):
            word = 0
            for offset, unit in enumerate(units[pos:pos + 4]):
                word |= unit << (8 * offset)
            result.append(word & MASK)
        if include_length:
            result.append(len(units))
        return result
    if not text:
        return b''
    v, k = words(text, True), words(key, False)
    k += [0] * max(0, 4 - len(k))
    n, z, total = len(v) - 1, v[-1], 0
    for _ in range(6 + 52 // len(v)):
        total = (total + 0x9e3779b9) & MASK
        e = (total >> 2) & 3
        for p in range(n + 1):
            y = v[p + 1] if p < n else v[0]
            m = (z >> 5) ^ ((y << 2) & MASK)
            m += (y >> 3) ^ ((z << 4) & MASK) ^ (total ^ y)
            m += k[(p & 3) ^ e] ^ z
            z = v[p] = (v[p] + m) & MASK
    return struct.pack('<' + 'I' * len(v), *v)


def login_params(username, password, ip, acid, token):
    text = json.dumps(dict(username=username, password=password, ip=ip,
                           acid=acid, enc_ver='srun_bx1'), ensure_ascii=False, separators=(',', ':'))
    encoded = base64.b64encode(xencode(text, token)).decode('ascii')
    info = '{SRBX1}' + encoded.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', ALPHABET))
    digest = hmac.new(token.encode('utf-8'), password.encode('utf-8'), hashlib.md5).hexdigest()
    checksum = hashlib.sha1(''.join(token + value for value in
        [username, digest, acid, ip, '200', '1', info]).encode('utf-8')).hexdigest()
    return dict(action='login', username=username, password='{MD5}' + digest,
                info=info, chksum=checksum, ac_id=acid, ip=ip, n='200', type='1',
                double_stack='0', os='Windows', name='Windows')


class Blob(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]


def protect(data, decrypt=False, machine=False):
    if os.name != 'nt':
        raise CampusError('Windows is required for credential encryption/decryption')
    buffer = ctypes.create_string_buffer(data)
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    target = Blob()
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    fn = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                   ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    fn.restype = wintypes.BOOL
    # CRYPTPROTECT_UI_FORBIDDEN, plus CRYPTPROTECT_LOCAL_MACHINE for the
    # session-independent task.
    flags = 1 | (4 if machine else 0)
    if not fn(ctypes.byref(source), None, None, None, None, flags, ctypes.byref(target)):
        raise CampusError('Windows credential encryption/decryption failed')
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel.LocalFree(target.pbData)


# User scope for interactive runs; machine scope for the SYSTEM task, which
# cannot read data protected for a user profile.
CREDENTIAL_STORES = (('credentials.dat', False), ('credentials.system.dat', True))


def save_credentials(username, password):
    if not isinstance(username, str) or not isinstance(password, str) or not username.strip() or not password:
        raise CampusError('Username and password are required')
    data = json.dumps(dict(username=username.strip(), password=password)).encode('utf-8')
    directory = ensure_data_dir()
    blobs = {name: protect(data, machine=machine) for name, machine in CREDENTIAL_STORES}
    try:
        for name, blob in blobs.items():
            (directory / (name + '.tmp')).write_bytes(blob)
        for name in blobs:
            (directory / (name + '.tmp')).replace(directory / name)
    except OSError:
        raise CampusError('Cannot save encrypted credentials') from None
    finally:
        for name in blobs:
            try:
                (directory / (name + '.tmp')).unlink(missing_ok=True)
            except OSError:
                raise CampusError('Cannot remove temporary encrypted credentials') from None


def load_credentials():
    unusable = False
    for name, machine in CREDENTIAL_STORES:
        file = DATA_DIR / name
        if not file.exists():
            continue
        unusable = True
        try:
            encrypted = file.read_bytes()
        except OSError:
            raise CampusError('Cannot read encrypted credentials') from None
        try:
            credentials = json.loads(protect(encrypted, decrypt=True, machine=machine))
            if (not isinstance(credentials, dict)
                    or not isinstance(credentials.get('username'), str)
                    or not credentials['username'].strip()
                    or not isinstance(credentials.get('password'), str)
                    or not credentials['password']):
                raise ValueError
        except (CampusError, ValueError, TypeError):
            continue
        logging.info('Credentials loaded from %s', name)
        return credentials
    if unusable:
        raise CampusError('Stored credentials are invalid; run Setup.cmd locally')
    raise CampusError('Credentials not configured; run Setup.cmd locally')


def recv_exact(sock, size):
    result = b''
    while len(result) < size:
        block = sock.recv(size - len(result))
        if not block:
            raise CampusError('DNS connection closed')
        result += block
    return result


def dns_address(server, proxy_port=None):
    # SOCKS CONNECT makes the existing core query campus DNS directly, avoiding TUN DNS hijacking.
    target = ('127.0.0.1', proxy_port) if proxy_port else (server, 53)
    with socket.create_connection(target, timeout=3) as sock:
        if proxy_port:
            sock.sendall(b'\x05\x01\x00')
            if recv_exact(sock, 2) != b'\x05\x00':
                raise CampusError('Local SOCKS authentication unavailable')
            sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(server) + struct.pack('!H', 53))
            response = recv_exact(sock, 4)
            if response[1] != 0:
                raise CampusError('Local SOCKS DNS connection failed')
            size = {1: 4, 4: 16}.get(response[3])
            if response[3] == 3:
                size = recv_exact(sock, 1)[0]
            if size is None:
                raise CampusError('Invalid SOCKS response')
            recv_exact(sock, size + 2)
        query = struct.pack('!6H', 0x5a4a, 0x100, 1, 0, 0, 0)
        query += b''.join(bytes([len(x)]) + x.encode('ascii') for x in HOST.split('.'))
        query += b'\x00\x00\x01\x00\x01'
        sock.sendall(struct.pack('!H', len(query)) + query)
        reply = recv_exact(sock, struct.unpack('!H', recv_exact(sock, 2))[0])
    ident, flags, questions, answers, _, _ = struct.unpack_from('!6H', reply)
    if ident != 0x5a4a or flags & 0xf or not flags & 0x8000:
        raise CampusError('Campus DNS returned an error')
    def skip_name(pos):
        while reply[pos]:
            if reply[pos] & 0xc0 == 0xc0:
                return pos + 2
            pos += 1 + reply[pos]
        return pos + 1
    pos = 12
    for _ in range(questions):
        pos = skip_name(pos) + 4
    for _ in range(answers):
        pos = skip_name(pos)
        kind, cls, _, size = struct.unpack_from('!HHIH', reply, pos)
        pos += 10
        if kind == 1 and cls == 1 and size == 4:
            address = socket.inet_ntoa(reply[pos:pos + size])
            if ipaddress.ip_address(address) not in ipaddress.ip_network('198.18.0.0/15'):
                return address
        pos += size
    raise CampusError('Campus DNS returned no real IPv4 address')


class PortalConnection(http.client.HTTPSConnection):
    def __init__(self, address):
        super().__init__(HOST, timeout=15, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
        except Exception:
            raw.close()
            raise


class Portal:
    def __init__(self, address):
        self.address = address

    def get(self, path, params=None, jsonp=False):
        params = dict(params or {})
        if jsonp:
            params.update(callback='campusCheck', _=str(time.time_ns() // 1000000))
        if params:
            path += '?' + urlencode(params)
        connection = PortalConnection(self.address)
        try:
            connection.request('GET', path, headers={'User-Agent': 'ZJU-CampusAutoLogin/1.0'})
            response = connection.getresponse()
            if response.status != 200:
                raise CampusError('Portal HTTP status ' + str(response.status))
            data = response.read(1048577)
            if len(data) > 1048576:
                raise CampusError('Portal response too large')
            text = data.decode('utf-8')
        finally:
            connection.close()
        if jsonp:
            match = re.fullmatch(r'campusCheck\((.*)\);?\s*', text, re.S)
            if not match:
                raise CampusError('Unexpected portal JSONP response')
            return json.loads(match.group(1))
        return text

    def status(self):
        result = self.get('/cgi-bin/rad_user_info', jsonp=True)
        if result.get('error') == 'ok':
            return True, result
        if result.get('error') == 'not_online_error':
            return False, result
        raise CampusError('Unrecognized authentication state; no login attempted')


def select_portal(config):
    addresses = []
    for server in config['campus_dns']:
        for port in (config.get('local_socks_port'), None):
            try:
                address = dns_address(server, port)
                if address not in addresses:
                    addresses.append(address)
                break
            except (OSError, CampusError, ValueError, IndexError, struct.error):
                pass
        if addresses:
            break
    # Bootstrap remains certificate-validated and is only used if fresh resolution is unavailable.
    addresses.extend(x for x in config['bootstrap_ipv4'] if x not in addresses)
    for address in addresses:
        portal = Portal(address)
        try:
            online, state = portal.status()
            return portal, online, state
        except (OSError, CampusError, ValueError, http.client.HTTPException):
            continue
    raise CampusError('Cannot query authentication server; no login attempted')


def run(check_only=False):
    config = load_config()
    portal, online, state = select_portal(config)
    if online:
        logging.info('ONLINE: authentication valid; no login sent')
        return 0
    if check_only:
        logging.info('OFFLINE: check-only mode; no login sent')
        return 2
    credentials = load_credentials()
    page = portal.get('/srun_portal_pc', {'ac_id': config['ac_id'], 'theme': 'zju'})
    match = re.search(r'\bip\s*:\s*"([0-9.]+)"', page)
    acid_match = re.search(r'\bacid\s*:\s*"(\d+)"', page)
    if not match or not acid_match:
        raise CampusError('Cannot read current client IP / access controller')
    ip, acid = match.group(1), acid_match.group(1)
    ipaddress.IPv4Address(ip)
    captcha = json.loads(portal.get('/v2/srun_portal_captcha_image_info',
        {'user_name': credentials['username'], 'ip': ip}))
    if captcha.get('code') != 0 or captcha.get('data') != '0':
        raise CampusError('Captcha required or unknown policy; manual login needed')
    challenge = portal.get('/cgi-bin/get_challenge',
        {'username': credentials['username'], 'ip': ip}, jsonp=True)
    token = challenge.get('challenge')
    if challenge.get('error') != 'ok' or not isinstance(token, str) or not token:
        raise CampusError('Login challenge unavailable')
    params = login_params(credentials['username'], credentials['password'], ip, acid, token)
    result = portal.get('/cgi-bin/srun_portal', params, jsonp=True)
    if result.get('error') != 'ok':
        # Portal errors can echo account information; never log response values.
        raise CampusError('Login rejected; no immediate retry')
    for _ in range(3):
        time.sleep(2)
        online, _ = portal.status()
        if online:
            logging.info('RECOVERED: login accepted and online status verified')
            return 0
    raise CampusError('Login response accepted but online state not confirmed')


def main():
    global DATA_DIR
    parser = argparse.ArgumentParser(
        description='Check ZJU authentication; log in only after confirmed offline status.',
        epilog='Run Setup.cmd to store credentials locally and enable the Windows task. '
               'Installed with administrator rights it runs at startup and periodically as SYSTEM, '
               'without any user session; otherwise it runs at Windows logon and periodically in '
               'the current user session (works while locked, not after sign-out). '
               'Logs are in the per-user ZjuCampusAutoLogin application data directory. '
               'Remove scheduling: powershell -File Install-Task.ps1 -Remove. '
               'No logout requests or proxy configuration changes are made.')
    parser.add_argument('--check', action='store_true', help='Query only; never authenticate')
    parser.add_argument('--data-dir', help='override the runtime data directory (used by the scheduled task)')
    args = parser.parse_args()
    if args.data_dir:
        # The SYSTEM task has no user profile, so the installer passes the
        # interactive user's data directory explicitly.
        DATA_DIR = Path(args.data_dir).expanduser()
    try:
        directory = ensure_data_dir()
        handler = RotatingFileHandler(directory / 'campus.log', maxBytes=262144,
                                      backupCount=2, encoding='utf-8')
        handlers = [handler]
        if sys.stderr is not None:
            handlers.append(logging.StreamHandler())
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s',
                            handlers=handlers)
        return run(args.check)
    except CampusError as exc:
        logging.error('%s', exc)
        return 1
    except Exception as exc:
        logging.error('Operation failed (%s); no sensitive details logged', type(exc).__name__)
        return 1


if __name__ == '__main__':
    sys.exit(main())
