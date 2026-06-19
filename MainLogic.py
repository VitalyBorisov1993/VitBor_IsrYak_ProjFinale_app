import sys
import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
from packaging import version
from datetime import datetime
from urllib.parse import urlparse
import re
import json
import requests
import subprocess
import glob
import time
import random
import math
import shlex
import hashlib
import uuid
import argparse
import urllib3
import xml.etree.ElementTree as ET
from google import genai
from google.genai import types

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# gemini configuration
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    print("[!] GEMINI_API_KEY environment variable not set. AI summary will be skipped.")

# supabase imports
try:
    from supabase import create_client, Client
except ImportError:
    print("[!] Supabase package not found. Run: pip install supabase")
    sys.exit(1)

# ==========================================
# CONFIGURATION & VARIABLES
# ==========================================
OUTPUT_DIR = "scan_output"
MASTER_PLUGINS_FILE = "master_plugins.txt"  # track A: the 160 plugins to scan for
FFUF_DICT_FILE = "ffuf_dict.txt"            # track B: the 50 webshells to hunt for

FFUF_RATE = 10
FFUF_THREADS = 5
NUCLEI_RATE = 20

# supabase configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
WORDFENCE_API_KEY = os.environ.get("WORDFENCE_API_KEY", "")

# global buffer to store the raw log text for the database
RAW_LOG_BUFFER = ""
SCAN_START_TIME = None  # will be set in __main__ right before the scan begins

# colors for terminal output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'

# user agents pool for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1'
]

# create output directory if it doesn't exist
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)
        
def extract_site_metadata(target_url):
    print_status("Extracting site metadata (VirusTotal style)...")
    headers = {
        'User-Agent': get_random_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    
    try:
        response = requests.get(target_url, headers=headers, timeout=15, verify=False)
        
        # calculate body SHA-256
        body_bytes = response.content
        body_sha256 = hashlib.sha256(body_bytes).hexdigest()
        
        # format and log the output
        print_and_log(f"\n{YELLOW}=== Site Metadata ==={RESET}")
        print_and_log(f"Body SHA-256 : {body_sha256}")
        print_and_log(f"Status Code  : {response.status_code}")
        
        print_and_log(f"\n{YELLOW}--- HTTP Headers ---{RESET}")
        for key, value in response.headers.items():
            # formatting it similar to the VT screenshot (lowercase keys)
            print_and_log(f"{key.lower():<17}: {value}")
        print_and_log(f"{YELLOW}====================={RESET}\n")
        
        return {
            "sha256": body_sha256,
            "headers": dict(response.headers)
        }
        
    except Exception as e:
        print_status(f"Failed to extract metadata: {e}", "WARN")
        return None
# ==========================================
# HELPER FUNCTIONS
# ==========================================
def __get_elapsed_time():
    if SCAN_START_TIME is None:
        return "[00:00] "
    elapsed = int(time.time() - SCAN_START_TIME)
    mins = elapsed // 60
    secs = elapsed % 60
    return f"[{mins:02d}:{secs:02d}] "

# now appends to our RAW_LOG_BUFFER
def print_status(msg, level="INFO"):
    global RAW_LOG_BUFFER
    ts = __get_elapsed_time()
    log_line = ""
    if level == "INFO":
        log_line = f"{ts}[i] {msg}"
    elif level == "WARN":
        log_line = f"{YELLOW}{ts}[!] {msg}{RESET}"
    elif level == "ALERT":
        log_line = f"{RED}{ts}[!!!] {msg}{RESET}"
    elif level == "SUCCESS":
        log_line = f"{GREEN}{ts}[+] {msg}{RESET}"
    else:
        log_line = f"{ts}[*] {msg}"
    
    print(log_line)
    # strip ANSI color codes before saving to database so it reads cleanly later
    clean_line = re.sub(r'\x1b\[[0-9;]*m', '', log_line)
    RAW_LOG_BUFFER += clean_line + "\n"

# helper to capture standard print statements into the buffer too
def print_and_log(msg):
    global RAW_LOG_BUFFER
    ts = __get_elapsed_time()
    if msg.startswith('\n'):
        formatted_msg = '\n' + ts + msg[1:]
    else:
        formatted_msg = ts + msg
    print(formatted_msg)
    clean_msg = re.sub(r'\x1b\[[0-9;]*m', '', formatted_msg)
    RAW_LOG_BUFFER += clean_msg + "\n"

def ensure_wordfence_db(db_path="wordfence_db.json"):
    """
    Checks if the Wordfence database exists and is up to date (max 2 months old).
    If not, downloads the latest available version (usually 1 month behind for free users).
    """
    api_key = WORDFENCE_API_KEY
    download_url = f"https://www.wordfence.com/api/intelligence/v3/vulnerabilities/scanner"
    
    needs_download = False
    
    if not os.path.exists(db_path):
        print_status(f"Wordfence DB '{db_path}' not found. Initializing download...", "INFO")
        needs_download = True
    else:
        # check file age (2 months = 60 days)
        file_mtime = os.path.getmtime(db_path)
        file_age_days = (time.time() - file_mtime) / (24 * 3600)
        
        if file_age_days >= 60:
            print_status(f"Wordfence DB is {int(file_age_days)} days old (>= 60). Refreshing database...", "INFO")
            needs_download = True
        else:
            print_status(f"Wordfence DB is up to date ({int(file_age_days)} days old).", "SUCCESS")

    if needs_download:
        try:
            print_status("Downloading Wordfence Intelligence DB (approx 60MB)...", "INFO")
            headers = {"Authorization": f"Bearer {api_key}"}
            # using stream=True for large file download
            response = requests.get(download_url, headers=headers, stream=True, timeout=60)
            response.raise_for_status()
            
            with open(db_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            
            print_status("Wordfence DB download complete.", "SUCCESS")
        except Exception as e:
            print_status(f"Failed to download Wordfence DB: {e}", "ALERT")
            if not os.path.exists(db_path):
                print_status("Crucial: Vulnerability checks will be skipped as DB is missing.", "WARN")
    
    return db_path

def run_command(cmd, timeout_seconds=300):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout_seconds)
        return result.stdout
    except subprocess.TimeoutExpired:
        print_status(f"Command timed out: {cmd[:100]}...", "WARN")
        return ""
    except Exception as e:
        print_status(f"Command failed: {e}", "WARN")
        return ""

def random_delay(min_seconds=2, max_seconds=5):
    delay = random.uniform(min_seconds, max_seconds)
    time.sleep(delay)

def human_jitter(median_s=25, min_s=8, max_s=65):
    """
    Log-normal inter-request pause that mimics human think-time.
    Real human gaps cluster around a median with a long right tail (occasional long pauses),
    unlike uniform random which has no tail. More evasive against ML-based rate detectors.
    """
    import math
    mu = math.log(median_s)
    sigma = 0.55  # controls spread; 0.55 gives ~2x median as rough 90th percentile
    delay = random.lognormvariate(mu, sigma)
    delay = max(min_s, min(delay, max_s))
    return delay

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def resolve_target_url(target: str) -> str:
    """
    Checks if target has a protocol scheme. If not, probes http and fallbacks to https if needed.
    """
    if target.startswith(("http://", "https://")):
        return target

    # try http first
    http_target = "http://" + target
    try:
        # perform a quick HEAD request to see if it responds (timeout 3s)
        requests.head(http_target, timeout=3, verify=False, allow_redirects=True)
        return http_target
    except Exception:
        # fallback to https
        https_target = "https://" + target
        try:
            requests.head(https_target, timeout=3, verify=False, allow_redirects=True)
            return https_target
        except Exception:
            # if both fail, default to http (e.g. if the host is down/offline)
            return http_target

# ==========================================

# WEBSHELL DETECTION: SOFT-404 BASELINE + CONTENT SIGNATURES
# ==========================================
def compute_soft_404_baseline(target_url, dir_path, timeout=8):
    """
    Probe a random non-existent .php inside dir_path. Many WordPress sites
    return HTTP 200 with a themed 404 page for missing PHP files, which causes
    FFUF to flag every wordlist entry as 'found'. Capturing the baseline body
    length / sha256 lets us filter those false positives.

    Returns dict {status, len, sha256, content_type} or None on error.
    """
    bogus_name = f"__nonexistent_{uuid.uuid4().hex[:12]}.php"
    probe_url = f"{target_url.rstrip('/')}{dir_path.rstrip('/')}/{bogus_name}"
    try:
        resp = requests.get(
            probe_url,
            headers={'User-Agent': get_random_user_agent()},
            timeout=timeout, verify=False, allow_redirects=False,
        )
        body = resp.content or b''
        return {
            'status': resp.status_code,
            'len': len(body),
            'sha256': hashlib.sha256(body).hexdigest(),
            'content_type': resp.headers.get('Content-Type', ''),
        }
    except Exception as e:
        print_status(f"Baseline probe failed for {dir_path}: {e}", "WARN")
        return None


# compiled once at import time. each tuple: (regex, label, weight).
# weight reflects how shell-specific the pattern is. sum >= 2 = high confidence.
WEBSHELL_PATTERNS = [
    (re.compile(rb'\beval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)', re.IGNORECASE),    'eval($_VAR)',                     2),
    (re.compile(rb'\bassert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)', re.IGNORECASE),  'assert($_VAR)',                   2),
    (re.compile(rb'\bpassthru\s*\(\s*\$_(POST|GET|REQUEST)', re.IGNORECASE),       'passthru($_VAR)',                 2),
    (re.compile(rb'\bshell_exec\s*\(\s*\$_(POST|GET|REQUEST)', re.IGNORECASE),     'shell_exec($_VAR)',               2),
    (re.compile(rb'\bsystem\s*\(\s*\$_(POST|GET|REQUEST)', re.IGNORECASE),         'system($_VAR)',                   2),
    (re.compile(rb'\bproc_open\s*\(\s*\$_(POST|GET|REQUEST)', re.IGNORECASE),      'proc_open($_VAR)',                2),
    (re.compile(rb'\bgzinflate\s*\(\s*base64_decode', re.IGNORECASE),              'gzinflate(base64_decode())',      2),
    (re.compile(rb'\bbase64_decode\s*\(\s*[\'"][A-Za-z0-9+/=]{40,}', re.IGNORECASE), 'base64_decode(<long-blob>)',    2),
    (re.compile(rb'preg_replace\s*\([^)]{0,80}/[a-z]*e[a-z]*[\'"]', re.IGNORECASE), 'preg_replace /e modifier (RCE)', 2),
    (re.compile(rb'GIF89a.{0,32}<\?php', re.DOTALL),                               'GIF89a + PHP polyglot',           2),
    (re.compile(rb'\bFilesMan\b'),                                                 'FilesMan banner',                 2),
    (re.compile(rb'\bb374k\b', re.IGNORECASE),                                     'b374k banner',                    2),
    (re.compile(rb'WSO\s*\d+\.\d+', re.IGNORECASE),                                'WSO version banner',              2),
    (re.compile(rb'\bc99\s*shell\b', re.IGNORECASE),                               'c99shell banner',                 2),
    (re.compile(rb'\bp0wny\s*@?\s*shell\b', re.IGNORECASE),                        'p0wny@shell banner',              2),
    (re.compile(rb'\balfa[\s_-]?team\b', re.IGNORECASE),                           'AlfaShell banner',                2),
    (re.compile(rb'IndoXploit', re.IGNORECASE),                                    'IndoXploit banner',               2),
    (re.compile(rb'\bweevely\b', re.IGNORECASE),                                   'Weevely marker',                  2),
    (re.compile(rb'\$auth_pass\s*=\s*[\'"]', re.IGNORECASE),                       '$auth_pass (shell login)',        2),
    (re.compile(rb'@?error_reporting\s*\(\s*0\s*\).{0,80}@?set_time_limit\s*\(\s*0\s*\)', re.DOTALL), 'shell preamble (suppress + unlimit)', 1),
    (re.compile(rb'\beval\s*\(', re.IGNORECASE),                                   'eval(',                           1),
    (re.compile(rb'\bbase64_decode\s*\(', re.IGNORECASE),                          'base64_decode(',                  1),
    (re.compile(rb'\bcreate_function\s*\(', re.IGNORECASE),                        'create_function(',                1),
    (re.compile(rb'\bpcntl_exec\s*\(', re.IGNORECASE),                             'pcntl_exec(',                     1),
    (re.compile(rb'\$_(POST|GET|REQUEST|COOKIE)\s*\[\s*[\'"][a-z0-9_]{1,12}[\'"]\s*\]', re.IGNORECASE), 'direct superglobal indexing', 1),
    (re.compile(rb'\bstr_rot13\s*\(\s*base64_decode', re.IGNORECASE),              'str_rot13(base64_decode())',      2),
]
PHP_OPEN_TAG = re.compile(rb'<\?(php|=)?\b', re.IGNORECASE)


def inspect_url_for_shell_signatures(url, max_bytes=16384, timeout=10):
    """
    Fetch up to max_bytes of url body, regex-match against WEBSHELL_PATTERNS.
    Returns dict:
      status         - HTTP status (0 on connection error)
      length         - bytes inspected
      sha256         - sha256 of inspected bytes
      has_php_tag    - bool, whether '<?php' appeared in body
      matches        - list of matched pattern labels
      score          - sum of matched-pattern weights
      verdict        - 'CONFIRMED' (score >= 2 AND has_php_tag) /
                       'SUSPICIOUS' (score >= 1 AND has_php_tag) /
                       'CLEAN'
    """
    result = {
        'status': 0, 'length': 0, 'sha256': '',
        'has_php_tag': False, 'matches': [], 'score': 0, 'verdict': 'CLEAN',
    }
    try:
        resp = requests.get(
            url,
            headers={
                'User-Agent': get_random_user_agent(),
                'Range': f'bytes=0-{max_bytes - 1}',
                'Accept': '*/*',
            },
            timeout=timeout, verify=False, allow_redirects=False, stream=True,
        )
        result['status'] = resp.status_code
        body = b''
        try:
            for chunk in resp.iter_content(chunk_size=4096):
                if not chunk:
                    break
                body += chunk
                if len(body) >= max_bytes:
                    body = body[:max_bytes]
                    break
        finally:
            resp.close()
    except Exception as e:
        print_status(f"Sniff failed for {url}: {e}", "WARN")
        return result

    if not body:
        return result

    result['length'] = len(body)
    result['sha256'] = hashlib.sha256(body).hexdigest()
    result['has_php_tag'] = bool(PHP_OPEN_TAG.search(body))

    score = 0
    matches = []
    for pat, label, weight in WEBSHELL_PATTERNS:
        if pat.search(body):
            matches.append(label)
            score += weight
    result['matches'] = matches
    result['score'] = score

    if score >= 2 and result['has_php_tag']:
        result['verdict'] = 'CONFIRMED'
    elif score >= 1 and result['has_php_tag']:
        result['verdict'] = 'SUSPICIOUS'
    else:
        result['verdict'] = 'CLEAN'
    return result


def matches_soft_404(url, body_length, baselines, tolerance=0.05):
    """
    Return True if the FFUF hit's body length matches the soft-404 baseline
    of its parent dir within ±tolerance. Tolerance default 5%.
    """
    if not baselines:
        return False
    for dir_prefix, b in baselines.items():
        if dir_prefix in url:
            base_len = b.get('len', 0)
            if base_len > 0:
                delta = abs(body_length - base_len) / float(base_len)
                if delta <= tolerance:
                    return True
            elif body_length == base_len:  # both zero
                return True
    return False


def check_waf(target_url):
    print_status("Checking for WAF/bot-protection presence...")
    headers = {
        'User-Agent': get_random_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }

    # header-name (lowercase) -> WAF display name
    HEADER_FINGERPRINTS = {
        'sg-captcha':            'NinjaFirewall',
        'x-ninjafirewall':       'NinjaFirewall',
        'cf-ray':                'Cloudflare',
        'cf-cache-status':       'Cloudflare',
        'x-sucuri-id':           'Sucuri',
        'x-sucuri-cache':        'Sucuri',
        'x-cdn':                 'Sucuri',
        'x-fw-hash':             'Wordfence',
        'x-protected-by':        'Generic WAF',
        'x-waf':                 'Generic WAF',
        'x-powered-by-plesk':    'Plesk',
        'x-akamai-transformed':  'Akamai',
        'x-mod-pagespeed':       'ModPageSpeed',
    }

    # cookie-name prefix (lowercase) -> WAF display name
    COOKIE_FINGERPRINTS = {
        'nevercache':   'NinjaFirewall',
        '__cf_bm':      'Cloudflare Bot Management',
        'cf_clearance': 'Cloudflare',
        'sucuri_cloudproxy_uuid': 'Sucuri',
    }

    # body substring (lowercase) -> WAF display name
    BODY_FINGERPRINTS = {
        'sg-captcha':                     'NinjaFirewall Challenge',
        'ninjafirewall':                  'NinjaFirewall',
        'just a moment':                  'Cloudflare Challenge',
        'enable javascript and cookies':  'Cloudflare Challenge',
        'sucuri website firewall':        'Sucuri',
        'wordfence':                      'Wordfence',
    }

    try:
        response = requests.get(target_url, headers=headers, timeout=10, allow_redirects=True, verify=False)
        detected = {}  # name -> reason (dedup by name)

        # header fingerprints
        for hdr_name, hdr_val in response.headers.items():
            hl = hdr_name.lower()
            for fp, waf_name in HEADER_FINGERPRINTS.items():
                if fp in hl:
                    detected[waf_name] = f"header:{hdr_name}"

        # cookie fingerprints
        raw_cookies = response.headers.get('set-cookie', '')
        for cookie_prefix, waf_name in COOKIE_FINGERPRINTS.items():
            if cookie_prefix in raw_cookies.lower():
                detected[waf_name] = f"cookie:{cookie_prefix}"

        # body fingerprints (only read first 4 KB to stay fast)
        try:
            body_snippet = response.text[:4096].lower()
        except Exception:
            body_snippet = ''
        for phrase, waf_name in BODY_FINGERPRINTS.items():
            if phrase in body_snippet:
                detected[waf_name] = f"body:{phrase}"

        # HTTP 202 = bot-challenge page (NinjaFirewall / similar)
        bot_challenge = response.status_code == 202

        if detected:
            names = list(detected.keys())
            reasons = [f"{n} ({detected[n]})" for n in names]
            print_status(f"Protection detected: {', '.join(names)}", "WARN")
            for r in reasons:
                print_status(f"  └─ {r}", "INFO")
        else:
            print_status("No WAF/bot-protection signatures detected")

        if bot_challenge:
            print_status(f"HTTP 202 response — bot-challenge page active. Passive scan results may be unreliable.", "WARN")

        return response.status_code, list(detected.keys())

    except Exception as e:
        print_status(f"Error checking WAF: {e}", "WARN")
        return None, []

def enumerate_users(target_url):
    """
    Enumerate WordPress usernames via REST API and author-archive redirect.
    Relevant to T1505.003: attackers need valid credentials to authenticate
    and upload webshells through wp-admin or vulnerable plugins.
    Returns list of found usernames.
    """
    print_status("Enumerating users (REST API + author archive)...", "INFO")
    found_users = []
    ua = get_random_user_agent()

    # REST API /wp-json/wp/v2/users - may be public
    try:
        resp = requests.get(
            f"{target_url}/wp-json/wp/v2/users",
            headers={'User-Agent': ua, 'Accept': 'application/json'},
            timeout=10, allow_redirects=True, verify=False
        )
        if resp.status_code == 200:
            try:
                users = resp.json()
                if isinstance(users, list):
                    for u in users:
                        name = u.get('slug') or u.get('name') or u.get('link', '')
                        if name:
                            found_users.append(str(name))
            except (json.JSONDecodeError, ValueError):
                pass
    except Exception:
        pass

    # author archive redirect /?author=N -> /author/<slug>/
    if not found_users:
        for i in range(1, 6):
            try:
                resp = requests.get(
                    f"{target_url}/?author={i}",
                    headers={'User-Agent': ua},
                    timeout=8, allow_redirects=False, verify=False
                )
                # WordPress 301/302 redirects to /author/<username>/
                location = resp.headers.get('Location', '')
                m = re.search(r'/author/([^/?#]+)', location)
                if m:
                    found_users.append(m.group(1))
                elif resp.status_code == 404:
                    break  # no more authors
            except Exception:
                break

    found_users = list(dict.fromkeys(found_users))  # deduplicate, preserve order

    if found_users:
        print_status(f"Users enumerated: {', '.join(found_users)}", "ALERT")
        print_status("Username exposure increases credential-attack surface for webshell upload.", "WARN")
    else:
        print_status("No users enumerated (REST API protected or no author pages)", "INFO")

    return found_users


def check_registration_open(target_url):
    """
    Check if WordPress open user registration is enabled.
    Open registration → attacker self-registers → subscriber/contributor role → upload vector.
    """
    print_status("Checking open user registration...", "INFO")
    try:
        resp = requests.get(
            f"{target_url}/wp-login.php?action=register",
            headers={'User-Agent': get_random_user_agent()},
            timeout=8, allow_redirects=True, verify=False
        )
        body = resp.text.lower()

        # WordPress disabled messages - any of these = registration is OFF
        disabled_phrases = [
            'user registration is currently not allowed',
            'registration is currently not allowed',
            'registration has been disabled',
            'registration is disabled',
            'registrations are not allowed',
        ]
        if any(p in body for p in disabled_phrases):
            print_status("User registration disabled", "INFO")
            return False

        # positive confirmation: actual registration form present (input fields for user_login + user_email)
        has_form = ('name="user_login"' in resp.text or 'id="user_login"' in resp.text) and \
                   ('name="user_email"' in resp.text or 'id="user_email"' in resp.text)

        if resp.status_code == 200 and has_form:
            print_status("Open registration ENABLED — anyone can create an account", "ALERT")
            print_status("Attacker can self-register and potentially access file-upload functionality.", "WARN")
            return True

        print_status("User registration disabled or inaccessible", "INFO")
        return False
    except Exception:
        return False


def probe_xmlrpc_post(target_url):
    """
    POST system.listMethods to xmlrpc.php to confirm it's truly enabled.
    xmlrpc.php is MITRE T1190/T1505.003 vector: wp.uploadFile allows webshell upload.
    """
    print_status("Confirming xmlrpc.php via POST system.listMethods...", "INFO")
    payload = """<?xml version="1.0" encoding="utf-8"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>"""
    try:
        resp = requests.post(
            f"{target_url}/xmlrpc.php",
            data=payload,
            headers={
                'User-Agent': get_random_user_agent(),
                'Content-Type': 'text/xml',
            },
            timeout=10, allow_redirects=True, verify=False
        )
        if resp.status_code == 200 and '<methodResponse>' in resp.text:
            methods = re.findall(r'<string>([^<]+)</string>', resp.text)
            dangerous = [m for m in methods if m in (
                'wp.uploadFile', 'wp.newPost', 'wp.editPost',
                'metaWeblog.newMediaObject', 'blogger.newPost',
            )]
            print_status(f"xmlrpc.php is enabled (default WordPress behavior) — {len(methods)} methods exposed", "WARN")
            if dangerous:
                print_status(f"Auth-required upload methods present: {', '.join(dangerous)}", "WARN")
                print_status("Note: wp.uploadFile / metaWeblog.newMediaObject require valid WordPress credentials to exploit. Not a confirmed compromise — credential-attack surface only.", "INFO")
            return True, methods
        elif resp.status_code == 403:
            print_status("xmlrpc.php POST blocked (403 — hardened)", "INFO")
        elif resp.status_code == 405:
            print_status("xmlrpc.php POST method not allowed (hardened)", "INFO")
        else:
            print_status(f"xmlrpc.php POST → HTTP {resp.status_code}", "INFO")
        return False, []
    except Exception as e:
        print_status(f"xmlrpc POST probe error: {e}", "WARN")
        return False, []


def probe_admin_ajax(target_url):
    """
    Probe wp-admin/admin-ajax.php for unauthenticated AJAX actions exposed by plugins.
    No-auth AJAX handlers in vulnerable plugins are a common webshell upload path.
    """
    print_status("Probing admin-ajax.php for unauthenticated handlers...", "INFO")

    # known unauthenticated actions that historically allowed file upload or RCE
    # format: (action, method, post_data_or_None, description)
    NOAUTH_ACTIONS = [
        ("upload-attachment", "POST", {"async-upload": ""}, "Core media upload (requires auth, 403 expected)"),
        ("revslider_ajax_action", "POST", {"client_action": "update_plugin"}, "RevSlider (CVE-2014-9734) unauthenticated upload"),
        ("layerslider_ajax", "POST", {"action": "layerslider_ajax"}, "LayerSlider unauthenticated handler"),
        ("duplicator_download", "GET", None, "Duplicator Plugin arbitrary file download (CVE-2020-11738)"),
        ("wpdm_ajax_call", "GET", None, "Download Manager arbitrary file access"),
        ("motopress-hotel-booking-file-upload", "POST", {}, "MotoPress Hotel Booking unauthenticated upload"),
        ("nopriv_example", "GET", None, "Generic nopriv handler probe"),
    ]

    vulnerable_actions = []
    for action, method, post_data, description in NOAUTH_ACTIONS:
        try:
            url = f"{target_url}/wp-admin/admin-ajax.php?action={action}"
            headers = {'User-Agent': get_random_user_agent(), 'Content-Type': 'application/x-www-form-urlencoded'}
            if method == "POST":
                resp = requests.post(url, data=(post_data or {}), headers=headers, timeout=8, verify=False)
            else:
                resp = requests.get(url, headers=headers, timeout=8, verify=False)

            # -1 = WP "not found" for this action (plugin not active) - self-hosted WP only
            # 0  = WP "no priv" (action exists but requires auth)
            # anything else = potentially exposed handler
            # WordPress.com and some hosts return 0 for ALL unknown actions (not -1),
            # so only flag genuinely unexpected responses to avoid noise.
            body = resp.text.strip()
            ct = resp.headers.get('Content-Type', '')

            # suppress JSON error objects - plugins that return structured {"code":..., "message":...}
            # are registering the action (auth required) but not exposing it. avoids FP on
            # any plugin that returns a well-formed WP_Error JSON instead of plain "0".
            is_wp_json_error = False
            if 'application/json' in ct and body.startswith('{'):
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, dict) and ('code' in parsed or 'message' in parsed):
                        is_wp_json_error = True
                except Exception:
                    pass

            if resp.status_code == 200 and body not in ('-1', '0', '', 'false', 'null') and not is_wp_json_error:
                print_status(f"admin-ajax '{action}' returned unexpected data — possible exposed handler: {description}", "ALERT")
                vulnerable_actions.append(action)
            elif body == '0':
                # only log at INFO for known-dangerous actions to reduce noise
                if action in ('revslider_ajax_action', 'duplicator_download', 'layerslider_ajax', 'motopress-hotel-booking-file-upload'):
                    print_status(f"admin-ajax '{action}' — action registered (requires auth); plugin may be active", "INFO")
        except Exception:
            continue

    if vulnerable_actions:
        print_status(f"Potentially exposed unauthenticated AJAX actions: {', '.join(vulnerable_actions)}", "ALERT")
    else:
        print_status("No obviously exposed unauthenticated admin-ajax handlers found", "INFO")

    return vulnerable_actions


def probe_unauthenticated_vectors(target_url):
    """
    Probe known unauthenticated T1505.003 / T1078 upload & file-read vectors.
    All checks are passive HTTP requests — no exploitation, no modification.
    """
    print_status("Probing unauthenticated file-upload / file-read vectors...", "INFO")

    findings = []
    ua = get_random_user_agent()
    clean = target_url.rstrip('/')

    # WP file manager <= 6.8 - CVE-2020-25213
    # connector endpoint publicly accessible = unauthenticated arbitrary file upload (RCE)
    fm_url = f"{clean}/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php"
    try:
        r = requests.get(fm_url, headers={'User-Agent': ua}, timeout=8, verify=False, allow_redirects=False)
        if r.status_code == 200:
            print_status("WP File Manager connector.minimal.php ACCESSIBLE — unauthenticated upload (CVE-2020-25213)", "ALERT")
            findings.append(("WP File Manager unauth connector", fm_url, "CVE-2020-25213"))
        elif r.status_code == 403:
            print_status("WP File Manager connector.minimal.php present but blocked (403 — patched or hardened)", "INFO")
    except Exception:
        pass

    # duplicator <= 1.3.26 - CVE-2020-11738 - arbitrary file read
    dup_url = f"{clean}/wp-admin/admin-ajax.php?action=duplicator_download&file=../wp-config.php"
    try:
        r = requests.get(dup_url, headers={'User-Agent': ua}, timeout=8, verify=False)
        if r.status_code == 200 and any(k in r.text for k in ('DB_NAME', 'DB_PASSWORD', '<?php')):
            print_status("Duplicator arbitrary file read CONFIRMED — wp-config.php exposed (CVE-2020-11738)", "ALERT")
            findings.append(("Duplicator arbitrary file read", dup_url, "CVE-2020-11738"))
    except Exception:
        pass

    # BackupBuddy <= 8.7.4.1 - CVE-2022-31474 - arbitrary file download
    bb_url = f"{clean}/?action=ibk_download&token=0&local_to=../wp-config.php"
    try:
        r = requests.get(bb_url, headers={'User-Agent': ua}, timeout=8, verify=False)
        if r.status_code == 200 and 'DB_' in r.text:
            print_status("BackupBuddy arbitrary file download CONFIRMED — wp-config.php exposed (CVE-2022-31474)", "ALERT")
            findings.append(("BackupBuddy arbitrary file read", bb_url, "CVE-2022-31474"))
    except Exception:
        pass

    # all-in-one WP migration - backup storage directory exposed
    aiowm_url = f"{clean}/wp-content/plugins/all-in-one-wp-migration/storage/"
    try:
        r = requests.get(aiowm_url, headers={'User-Agent': ua}, timeout=8, verify=False)
        if r.status_code == 200 and any(k in r.text for k in ('Index of', '.wpress', 'backup')):
            print_status("All-in-One WP Migration backup storage EXPOSED — backup archives publicly accessible", "ALERT")
            findings.append(("AIOWM backup storage exposed", aiowm_url, "CWE-538"))
    except Exception:
        pass

    # UpdraftPlus - backup storage directory exposed
    udp_url = f"{clean}/wp-content/updraft/"
    try:
        r = requests.get(udp_url, headers={'User-Agent': ua}, timeout=8, verify=False)
        if r.status_code == 200 and any(k in r.text for k in ('Index of', '.zip', '.tar', 'backup')):
            print_status("UpdraftPlus backup directory EXPOSED — backup files publicly accessible", "ALERT")
            findings.append(("UpdraftPlus backup dir exposed", udp_url, "CWE-538"))
    except Exception:
        pass

    # REST API /wp/v2/media - unauthenticated upload?
    media_url = f"{clean}/wp-json/wp/v2/media"
    try:
        r = requests.post(
            media_url,
            headers={'User-Agent': ua, 'Content-Type': 'application/json'},
            timeout=8, verify=False
        )
        if r.status_code == 200:
            print_status("REST API /wp/v2/media accepts unauthenticated POST — direct upload vector (T1505.003)", "ALERT")
            findings.append(("REST API unauth media upload", media_url, "T1505.003"))
        elif r.status_code == 401:
            print_status("REST API /wp/v2/media requires authentication (expected)", "INFO")
    except Exception:
        pass

    # wp-cron.php public access
    # attacker can trigger cron hooks that some plugins expose as file-write actions
    try:
        r = requests.get(
            f"{clean}/wp-cron.php?doing_wp_cron=1",
            headers={'User-Agent': ua}, timeout=8, verify=False
        )
        if r.status_code == 200:
            print_status("wp-cron.php publicly accessible — cron-triggered plugin hooks are attack surface", "WARN")
    except Exception:
        pass

    # theme/plugin editor - reachable without auth redirect?
    # normally /wp-admin/ redirects unauthenticated users to wp-login.php (302)
    # 200 = misconfigured or auth bypass
    for editor_path in ('theme-editor.php', 'plugin-editor.php'):
        try:
            r = requests.get(
                f"{clean}/wp-admin/{editor_path}",
                headers={'User-Agent': ua}, timeout=8, verify=False, allow_redirects=False
            )
            if r.status_code == 200:
                print_status(f"wp-admin/{editor_path} accessible without auth redirect — potential code editor exposure", "ALERT")
                findings.append((f"{editor_path} no-auth access", f"{clean}/wp-admin/{editor_path}", "T1505.003"))
        except Exception:
            pass

    if findings:
        print_status(f"{len(findings)} unauthenticated vector(s) confirmed — direct T1505.003 attack paths:", "ALERT")
        for name, url, ref in findings:
            print_status(f"  [{ref}] {name}: {url}", "ALERT")
    else:
        print_status("No unauthenticated upload/file-read vectors detected", "INFO")

    return findings


def get_optimized_list(master_file, found_plugins):
    try:
        with open(master_file, 'r') as f:
            master_set = set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print_status(f"Wordlist '{master_file}' not found. Creating a blank one.", "WARN")
        master_set = set()
        open(master_file, 'w').close()

    passive_set = set(found_plugins)
    remaining_to_scan = master_set - passive_set  
    
    print_and_log(f"    [+] Master List: {len(master_set)} | Passive Found: {len(passive_set)}")
    print_and_log(f"    [+] Optimization: WPScan will only check the remaining {len(remaining_to_scan)} plugins.")
    return list(remaining_to_scan)

# ==========================================
# ENHANCED PASSIVE SCANNING
# ==========================================
def enhanced_passive_scan(target_url):
    print_status(f"Step 1: Enhanced Passive Reconnaissance on {target_url}...")
    found_plugins = set()
    found_themes = set()
    rate_limited = False
    passive_plugin_versions = {}  # slug -> version extracted from ?ver= asset params
    passive_theme_versions = {}   # slug -> version extracted from ?ver= asset params
    wp_core_version = None

    # expanded plugin indicator map - fingerprints found in HTML source
    plugin_indicators = {
        "yoast": "wordpress-seo", "elementor": "elementor",
        "woocommerce": "woocommerce", "wpforms": "wpforms-lite",
        "contact form 7": "contact-form-7", "wordfence": "wordfence",
        "jetpack": "jetpack", "akismet": "akismet",
        "monsterinsights": "google-analytics-for-wordpress",
        "rank math": "seo-by-rank-math", "updraftplus": "updraftplus",
        "w3 total cache": "w3-total-cache", "wp super cache": "wp-super-cache",
        "litespeed": "litespeed-cache", "wp rocket": "wp-rocket",
        "sucuri": "sucuri-scanner", "ithemes security": "better-wp-security",
        "all in one seo": "all-in-one-seo-pack", "gravity forms": "gravityforms",
        "ninja forms": "ninja-forms", "tablepress": "tablepress",
        "nextgen gallery": "nextgen-gallery", "smush": "wp-smushit",
        "redirection": "redirection", "broken link checker": "broken-link-checker",
        "cookie notice": "cookie-notice", "gdpr": "cookie-law-info",
        "mailchimp": "mailchimp-for-wp", "optinmonster": "optinmonster",
        "beaver builder": "beaver-builder-lite-version",
        "starter templates": "starter-templates", "astra": "astra-sites",
        "revslider": "revslider", "slider revolution": "revslider",
    }
    
    # REST namespace -> plugin slug mapping
    namespace_to_plugin = {
        "wc": "woocommerce", "yoast": "wordpress-seo",
        "contact-form-7": "contact-form-7", "jetpack": "jetpack",
        "wordfence": "wordfence", "wpforms": "wpforms-lite",
        "rankmath": "seo-by-rank-math", "rank-math": "seo-by-rank-math",
        "monsterinsights": "google-analytics-for-wordpress",
        "elementor": "elementor", "wp-mail-smtp": "wp-mail-smtp",
        "ithemes-security": "better-wp-security",
        "redirection": "redirection", "acf": "advanced-custom-fields",
        "updraftplus": "updraftplus", "meow": "meow-lightbox",
        "ninja-forms": "ninja-forms", "gravityforms": "gravityforms",
        "mailchimp": "mailchimp-for-wp", "mc4wp": "mailchimp-for-wp",
        "surecart": "surecart", "sureforms": "sureforms",
        "learnpress": "learnpress", "buddypress": "buddypress",
        "pmpro": "paid-memberships-pro", "fluentform": "fluentform",
        "nextgen-gallery": "nextgen-gallery",
        "tablepress": "tablepress", "wps-hide-login": "wps-hide-login",
        "limit-login-attempts": "limit-login-attempts-reloaded",
        "starter-templates": "starter-templates",
    }

    plugin_patterns = [
        r"/wp-content/plugins/([a-zA-Z0-9\-_]+)/",
        r"'plugin': '([a-zA-Z0-9\-_]+)'",
        r'"plugin":"([a-zA-Z0-9\-_]+)"',
        r"plugins: \{'([a-zA-Z0-9\-_]+)':",
        r"\[([a-zA-Z0-9\-_]+)\]\]=\{\$",
        r"wp-content/plugins/([^/\"'<>]+)",
    ]

    def __extract_plugins_from_html(text):
        """Core extraction logic reused for every page we scrape."""
        for pattern in plugin_patterns:
            matches = re.findall(pattern, text)
            for m in matches:
                if m and "," not in m and " " not in m and re.match(r"^[a-z0-9-]+$", m):
                    found_plugins.add(m)
        
        text_lower = text.lower()
        
        # check indicator keywords
        for indicator, plugin_slug in plugin_indicators.items():
            if indicator in text_lower:
                found_plugins.add(plugin_slug)
        
        # HTML comments (e.g. "<!-- This site is optimized with the Yoast SEO plugin -->")
        html_comments = re.findall(r"<!--(.*?)-->", text, re.DOTALL)
        for comment in html_comments:
            comment_lower = comment.lower().strip()
            for indicator, plugin_slug in plugin_indicators.items():
                if indicator in comment_lower:
                    found_plugins.add(plugin_slug)
        
        # meta generator tags (e.g. <meta name="generator" content="Starter Templates v3.1.21">)
        generators = re.findall(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', text, re.IGNORECASE)
        generators += re.findall(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', text, re.IGNORECASE)
        for gen in generators:
            gen_lower = gen.lower()
            for indicator, plugin_slug in plugin_indicators.items():
                if indicator in gen_lower:
                    found_plugins.add(plugin_slug)

        # plugin versions from ?ver= in script/style asset URLs (e.g. plugin.js?ver=1.2.3)
        # this works even when WPScan is blocked - purely passive.
        for slug, ver in re.findall(r"wp-content/plugins/([a-zA-Z0-9\-_]+)/[^?\"'\s]+\?ver=([\d][.\d]*)", text):
            slug = slug.lower()
            if re.match(r'^[a-z0-9-]+$', slug):
                found_plugins.add(slug)
                if slug not in passive_plugin_versions:
                    passive_plugin_versions[slug] = ver

        # theme slugs from URL paths
        for slug in re.findall(r"wp-content/themes/([a-zA-Z0-9\-_]+)/", text):
            slug = slug.lower()
            if re.match(r'^[a-z0-9-]+$', slug):
                found_themes.add(slug)

        # theme versions from ?ver= in theme asset URLs
        for slug, ver in re.findall(r"wp-content/themes/([a-zA-Z0-9\-_]+)/[^?\"'\s]+\?ver=([\d][.\d]*)", text):
            slug = slug.lower()
            if re.match(r'^[a-z0-9-]+$', slug):
                found_themes.add(slug)
                if slug not in passive_theme_versions:
                    passive_theme_versions[slug] = ver

    # scrape the standard WP endpoints
    targets = [
        target_url,
        f"{target_url}/wp-json/wp/v2/posts",
        f"{target_url}/wp-json/wp/v2/pages",
        f"{target_url}/?rest_route=/wp/v2/posts",
        f"{target_url}/wp-content/themes/",
        f"{target_url}/readme.html",
        f"{target_url}/wp-links-opml.php",
        f"{target_url}/license.txt",
        f"{target_url}/wp-includes/",
        f"{target_url}/wp-content/plugins/",
        f"{target_url}/wp-admin/admin-ajax.php",
        f"{target_url}/feed/",  # RSS feed often contains plugin traces
    ]

    session = requests.Session()
    for url in targets:
        headers = {
            'User-Agent': get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'DNT': '1'
        }

        try:
            random_delay(1, 3)
            response = session.get(url, headers=headers, timeout=15, allow_redirects=True)
            
            if response.status_code == 200:
                __extract_plugins_from_html(response.text)

                # WP core version - check each fetched page, stop once found
                if wp_core_version is None:
                    for _pat in [
                        r'<meta[^>]+content=["\']WordPress ([\d]+\.[\d][.\d]*)["\'][^>]+name=["\']generator["\']',
                        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress ([\d]+\.[\d][.\d]*)',
                        r'<generator>https?://wordpress\.org/\?v=([\d]+\.[\d][.\d]*)</generator>',
                        # last resort: "Version: X.Y" in readme.html/license.txt - require X.Y min (not bare "1")
                        r'(?:^|\s)Version:\s*([\d]+\.[\d][.\d]*)\s*$',
                    ]:
                        _m = re.search(_pat, response.text, re.IGNORECASE | re.MULTILINE)
                        if _m:
                            wp_core_version = _m.group(1)
                            break

            elif response.status_code == 429:
                print_status(f"Rate limited on {url} (HTTP 429) - slowing down...", "WARN")
                rate_limited = True
                time.sleep(10)
            elif response.status_code == 403:
                # 403 on /wp-content/themes/, /wp-includes/, /wp-content/plugins/ is
                # standard WordPress directory listing hardening - NOT rate-limiting.
                print_status(f"Directory listing disabled on {url} (HTTP 403) - expected, skipping.", "INFO")
                
        except requests.exceptions.ConnectionError:
            print_status(f"Connection error on {url} - target might be down", "WARN")
            time.sleep(5)
        except Exception as e:
            continue
    
    # REST API namespace discovery
    # one request to /wp-json/ reveals all plugin REST routes
    print_status("Probing REST API namespaces for plugin fingerprints...", "INFO")
    try:
        random_delay(1, 2)
        rest_root = requests.get(
            f"{target_url}/wp-json/",
            headers={'User-Agent': get_random_user_agent(), 'Accept': 'application/json'},
            timeout=10, allow_redirects=True
        )
        if rest_root.status_code == 200:
            try:
                api_data = rest_root.json()
                namespaces = api_data.get('namespaces', [])
                for ns in namespaces:
                    # namespace format is usually "plugin-slug/v1" - grab the prefix
                    ns_prefix = ns.split('/')[0].lower()
                    if ns_prefix in namespace_to_plugin:
                        found_plugins.add(namespace_to_plugin[ns_prefix])
                    elif ns_prefix not in ['wp', 'oembed', ''] and re.match(r'^[a-z0-9-]+$', ns_prefix):
                        # unknown namespace - could be a plugin slug itself
                        found_plugins.add(ns_prefix)
                if namespaces:
                    print_status(f"REST API exposed {len(namespaces)} namespaces", "SUCCESS")
            except (json.JSONDecodeError, ValueError):
                pass
    except Exception:
        pass

    # sitemap crawl - discover internal pages that load different plugins
    print_status("Checking sitemap for additional pages to fingerprint...", "INFO")
    extra_pages = []
    try:
        random_delay(1, 2)
        sitemap_resp = requests.get(
            f"{target_url}/sitemap.xml",
            headers={'User-Agent': get_random_user_agent()},
            timeout=10, allow_redirects=True
        )
        if sitemap_resp.status_code == 200:
            # extract URLs from sitemap (handle both index and regular sitemaps)
            try:
                root = ET.fromstring(sitemap_resp.text)
                ns = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                sitemap_urls = [loc.text.strip() for loc in root.findall('.//sm:loc', ns) if loc.text]
                if not sitemap_urls:
                    sitemap_urls = [loc.text.strip() for loc in root.findall('.//loc') if loc.text]
            except ET.ParseError:
                sitemap_urls = re.findall(r'<loc>(.*?)</loc>', sitemap_resp.text)
            
            # filter to only internal pages (not images/videos), deduplicate, take first 5
            page_urls = [u for u in sitemap_urls if target_url in u and not any(
                ext in u.lower() for ext in ['.jpg', '.png', '.gif', '.pdf', '.xml']
            )]
            # remove homepage (already scanned) and pick up to 5 unique pages
            page_urls = [u for u in page_urls if u.rstrip('/') != target_url.rstrip('/')]
            extra_pages = page_urls[:5]
            
            if extra_pages:
                print_status(f"Sitemap found {len(sitemap_urls)} URLs, sampling {len(extra_pages)} internal pages", "SUCCESS")
    except Exception:
        pass
    
    # scrape extra pages from sitemap for plugin fingerprints
    for page_url in extra_pages:
        try:
            random_delay(1, 3)
            resp = requests.get(
                page_url,
                headers={'User-Agent': get_random_user_agent(),
                         'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'},
                timeout=10, allow_redirects=True
            )
            if resp.status_code == 200:
                __extract_plugins_from_html(resp.text)
            elif resp.status_code == 429:
                rate_limited = True
                break  # stop crawling if rate-limited
        except Exception:
            continue

    # fallback - authenticated plugins REST endpoint
    if not found_plugins:
        print_status("Trying REST API for plugin discovery...", "INFO")
        rest_url = f"{target_url}/wp-json/wp/v2/plugins"
        try:
            random_delay(2, 4)
            response = requests.get(rest_url, headers={'User-Agent': get_random_user_agent()}, timeout=10)
            if response.status_code == 200:
                for plugin in response.json():
                    if 'plugin' in plugin: found_plugins.add(plugin['plugin'])
                    if 'name' in plugin: found_plugins.add(plugin['name'].lower().replace(' ', '-'))
        except Exception:
            pass
    
    # T1505.003 attack-surface probes

    # xmlrpc.php - GET first, then POST system.listMethods to confirm
    print_status("Probing xmlrpc.php (T1190 file-upload vector)...", "INFO")
    xmlrpc_get_status = None
    try:
        random_delay(1, 2)
        xmlrpc_resp = requests.get(
            f"{target_url}/xmlrpc.php",
            headers={'User-Agent': get_random_user_agent()},
            timeout=8, allow_redirects=True, verify=False
        )
        xmlrpc_get_status = xmlrpc_resp.status_code
        if xmlrpc_resp.status_code == 200 and 'xml-rpc' in xmlrpc_resp.text.lower():
            print_status("xmlrpc.php responds to GET — confirming with POST...", "WARN")
            probe_xmlrpc_post(target_url)
        elif xmlrpc_resp.status_code == 405:
            print_status("xmlrpc.php exists (blocks GET) — confirming with POST...", "WARN")
            probe_xmlrpc_post(target_url)
        elif xmlrpc_resp.status_code == 403:
            print_status("xmlrpc.php present but access denied (hardened)", "INFO")
        else:
            print_status(f"xmlrpc.php → HTTP {xmlrpc_resp.status_code}", "INFO")
    except Exception:
        pass

    # user enumeration - username exposure = credential attack surface
    random_delay(1, 2)
    found_users = enumerate_users(target_url)

    # open registration check
    random_delay(1, 2)
    check_registration_open(target_url)

    # unauthenticated admin-ajax handlers
    random_delay(1, 2)
    probe_admin_ajax(target_url)

    # log WP core version
    if wp_core_version:
        print_status(f"WordPress core version detected passively: {wp_core_version}", "SUCCESS")
    else:
        print_status("WordPress core version not found in passive sources", "INFO")

    # passive vuln checks on versions extracted from asset ?ver= params
    # runs before WPScan - works even when active scanning is blocked.
    if passive_plugin_versions or passive_theme_versions:
        print_status(
            f"Running passive Wordfence checks: {len(passive_plugin_versions)} plugin version(s), "
            f"{len(passive_theme_versions)} theme version(s) from asset fingerprints...", "INFO"
        )
        try:
            with open("wordfence_db.json", 'r') as f:
                passive_vuln_db = json.load(f)
            for slug, ver in passive_plugin_versions.items():
                offline_vuln_check(slug, ver, vuln_db=passive_vuln_db, software_type='plugin')
            for slug, ver in passive_theme_versions.items():
                offline_vuln_check(slug, ver, vuln_db=passive_vuln_db, software_type='theme')
        except FileNotFoundError:
            pass
        except Exception as e:
            print_status(f"Passive vuln check error: {e}", "WARN")

    print_status(
        f"Passive Scan complete: {len(found_plugins)} plugins, {len(found_themes)} themes identified", "SUCCESS"
    )
    return list(found_plugins), list(found_themes), rate_limited, passive_plugin_versions, wp_core_version

# ==========================================
# WPSCAN WITH TARGETED WEBSHELL FILTER
# ==========================================
def stealth_wpscan(target, scan_queue, known_plugins=None, mode="stealth", passive_versions=None):
    if known_plugins is None:
        known_plugins = []
        
    print_status(f"Step 2: {mode.capitalize()} Active Reconnaissance on {target}...")
    active_found = set()
    plugin_versions = {} 
    
    try:
        subprocess.run("wpscan --version", shell=True, capture_output=True, check=True)
    except subprocess.CalledProcessError:
        print_status("WPScan not found. Please install it first.", "WARN")
        return [], {}
    
    # discovery pass (popular plugins)
    # this finds the most common plugins and their versions in one shot.
    discovery_file = os.path.join(OUTPUT_DIR, "wpscan_popular.json")
    
    # mode differentiation for discovery
    if mode == "aggressive":
        probe_throttle_param = ""
        throttle_param = ""
        discovery_detection = "mixed"
        batch_detection = "mixed"
        force_flag = "--force"
        req_timeout = 30
    else:
        probe_throttle_param = "--throttle 2000" # 2s on first contact - harder for WAF to fingerprint
        throttle_param = "--throttle 1000"       # 1s for targeted batches - fast enough, still stealthy
        discovery_detection = "passive"    # real stealth avoids mass brute-forcing the top 50 plugins
        batch_detection = "mixed"          # we must use mixed for targeted webshells
        force_flag = ""
        req_timeout = 10                   # lower timeout so WAF tar-pits don't cause 5 min global freezes

    # dynamic ceiling: batch_size x ~6 paths/plugin x throttle_s x 2x safety
    # stealth: 20 x 6 x 2s x 2 = 480s (8 min). aggressive: 300s fixed.
    throttle_s = 2 if mode == "stealth" else 0
    wpscan_timeout = max(300, 20 * 6 * throttle_s * 2) if mode == "stealth" else 300

    def parse_wpscan_json(filepath):
        found = []
        versions = {}
        try:
            if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    plugins_data = data.get('plugins', {})
                    for p_name, p_info in plugins_data.items():
                        found.append(p_name)
                        v_info = p_info.get('version', {})
                        if v_info:
                            versions[p_name] = v_info.get('number', 'Unknown')
                        else:
                            versions[p_name] = 'Unknown'
        except Exception as e:
            print_status(f"Error parsing {os.path.basename(filepath)}: {e}", "WARN")
        return found, versions

    # discovery pass
    # problem: stealth --enumerate p checks ~1400 plugins at 1000ms throttle = up to 23 min.
    # when it times out, probe_blocked fires and skips ALL targeted batches - even on live sites.
    # fix: if passive found plugins, use 1 known plugin as a fast 90s reachability probe instead.
    # the popular scan is redundant in this path - targeted batches cover the full master list.
    if known_plugins and mode == "stealth":
        probe_slug = list(known_plugins)[0]
        probe_list_path = os.path.join(OUTPUT_DIR, "probe_list.txt")
        with open(probe_list_path, 'w') as f_probe:
            f_probe.write(probe_slug)

        print_status(f"Smart probe: verifying WPScan reachability via '{probe_slug}' (90s max)...", "INFO")
        probe_file = os.path.join(OUTPUT_DIR, "wpscan_probe.json")
        cmd_probe = (f"wpscan --url {shlex.quote(target)} --plugins-list {shlex.quote(probe_list_path)} "
                     f"--plugins-detection mixed --random-user-agent --format json "
                     f"--no-update --disable-tls-checks {probe_throttle_param} "
                     f"--request-timeout {req_timeout} --connect-timeout {req_timeout} "
                     f"> {shlex.quote(probe_file)} 2>/dev/null")
        run_command(cmd_probe, timeout_seconds=90)
        try: os.remove(probe_list_path)
        except: pass

        p_found, v_found = parse_wpscan_json(probe_file)
        probe_file_empty = (not os.path.exists(probe_file) or os.path.getsize(probe_file) < 50)
    else:
        # aggressive mode or no passive hints - run standard popular plugin discovery
        print_status("Running Popular Plugin discovery scan...", "INFO")
        cmd_popular = (f"wpscan --url {shlex.quote(target)} --enumerate p --plugins-detection {discovery_detection} {force_flag} "
                       f"--random-user-agent --format json --no-update --disable-tls-checks "
                       f"{throttle_param} --request-timeout {req_timeout} --connect-timeout {req_timeout} "
                       f"> {shlex.quote(discovery_file)} 2>/dev/null")
        run_command(cmd_popular, timeout_seconds=wpscan_timeout)
        p_found, v_found = parse_wpscan_json(discovery_file)
        probe_file_empty = (not os.path.exists(discovery_file) or os.path.getsize(discovery_file) < 50)

    # initial findings from probe/popular scan
    for p_name in p_found:
        if p_name not in active_found:
            active_found.add(p_name)
            plugin_versions[p_name] = v_found.get(p_name, 'Unknown')
            if plugin_versions[p_name] != 'Unknown':
                print_status(f"Found {p_name} version {plugin_versions[p_name]}", "SUCCESS")

    probe_blocked = (len(p_found) == 0 and probe_file_empty)

    # targeted pass (remaining plugins in batches)
    # we remove --enumerate p here to prevent repeating findings.
    plugins_to_check = [p for p in list(set(scan_queue + known_plugins)) if p not in active_found]
    
    if plugins_to_check:
        # if the probe was blocked and we're in stealth mode, skip the targeted batches.
        # they'll all timeout too - no point waiting 9 x 15 min for 0 results.
        if probe_blocked and mode == "stealth":
            print_status("WPScan probe returned no results — site is likely blocking active scanning.", "WARN")
            print_status(f"Skipping {len(plugins_to_check)} targeted plugin checks to avoid {math.ceil(len(plugins_to_check)/20) * 15}+ min of timeouts.", "WARN")
            print_status("Continuing with passive findings + FFUF discovery.", "INFO")
        else:
            print_and_log(f"    [>] Checking {len(plugins_to_check)} targeted plugins...")
            batch_size = 20
            num_batches = math.ceil(len(plugins_to_check) / batch_size)
            
            for i in range(0, len(plugins_to_check), batch_size):
                batch = plugins_to_check[i:i+batch_size]
                batch_num = (i // batch_size) + 1
                scan_list_str = ",".join(batch)
                
                outfile_discovery = os.path.join(OUTPUT_DIR, f"wpscan_batch_{batch_num}.json")
                
                # we write the batch to a temporary file.
                # this avoids the "File name too long" error in ruby's CLI parser.
                batch_list_path = os.path.join(OUTPUT_DIR, f"batch_list_{batch_num}.txt")
                with open(batch_list_path, 'w') as f_list:
                    f_list.write(",".join(batch))

                cmd_batch = (f"wpscan --url {shlex.quote(target)} --plugins-list {shlex.quote(batch_list_path)} "
                             f"--plugins-detection {batch_detection} {force_flag} "
                             f"--random-user-agent --format json --no-update --disable-tls-checks "
                             f"{throttle_param} --request-timeout {req_timeout} --connect-timeout {req_timeout} > {shlex.quote(outfile_discovery)} 2>/dev/null")
                
                print_status(f"Running targeted batch {batch_num}/{num_batches}", "INFO")
                run_command(cmd_batch, timeout_seconds=wpscan_timeout)
                
                # cleanup temp list file
                try: os.remove(batch_list_path)
                except: pass

                if batch_num < num_batches:
                    if mode == "stealth":
                        jitter = human_jitter(median_s=25, min_s=8, max_s=65)
                        print_status(f"Batch cooldown: {jitter:.1f}s (log-normal jitter)...", "INFO")
                        time.sleep(jitter)
                    else:
                        time.sleep(0.5)

                batch_found, batch_versions = parse_wpscan_json(outfile_discovery)
                for p_name in batch_found:
                    if p_name not in active_found:
                        active_found.add(p_name)
                        v_num = batch_versions.get(p_name, 'Unknown')
                        plugin_versions[p_name] = v_num
                        if v_num != 'Unknown':
                            print_status(f"Found {p_name} version {v_num}", "SUCCESS")
    
    total_confirmed = list(set(known_plugins) | active_found)
    print_status(f"Total confirmed plugins: {len(total_confirmed)}", "SUCCESS")

    # fallback: seed plugin_versions with passive ?ver= fingerprints for any plugin
    # WPScan didn't version-detect (e.g., site was blocked or probe missed it).
    # ensures step 2.5 always has data to check.
    for slug in total_confirmed:
        if slug not in plugin_versions and slug in (passive_versions or {}):
            plugin_versions[slug] = passive_versions[slug]
            print_status(f"Using passive version for {slug}: {passive_versions[slug]}", "INFO")

    if plugin_versions:
        print_status(f"Step 2.5: Running offline Webshell Vulnerability checks on {len(plugin_versions)} plugins...")
        loaded_vuln_db = None
        try:
            with open("wordfence_db.json", 'r') as f:
                loaded_vuln_db = json.load(f)
        except FileNotFoundError:
            print_and_log(f"    {YELLOW}[WARN] Offline DB 'wordfence_db.json' not found.{RESET}")
        if loaded_vuln_db:
            for plugin_slug, detected_version in plugin_versions.items():
                offline_vuln_check(plugin_slug, detected_version, vuln_db=loaded_vuln_db)
    
    return total_confirmed, plugin_versions

def offline_vuln_check(plugin_slug, detected_version, db_path="wordfence_db.json", vuln_db=None, software_type='plugin'):
    if detected_version == 'Unknown':
        return

    if vuln_db is None:
        try:
            with open(db_path, 'r') as f:
                vuln_db = json.load(f)
        except FileNotFoundError:
            print_and_log(f"    {YELLOW}[WARN] Offline DB '{db_path}' not found.{RESET}")
            return

    precursors_found = []
    ignored_vulns = []
    precursor_keywords = [
        "upload", "rce", "remote code execution", "arbitrary file", 
        "file write", "lfi", "local file inclusion", "command injection"
    ]

    for vuln_id, vuln_data in vuln_db.items():
        for software in vuln_data.get('software', []):
            if software.get('slug') == plugin_slug and software.get('type') == software_type:
                for range_key, version_data in software.get('affected_versions', {}).items():
                    raw_from = version_data.get('from_version', '0.0')
                    raw_to = version_data.get('to_version', '999.999')

                    if raw_from == '*' or not raw_from: raw_from = '0.0'
                    if raw_to == '*' or not raw_to: raw_to = '999.999'

                    try:
                        from_ver = version.parse(raw_from)
                        to_ver = version.parse(raw_to)
                        current_ver = version.parse(detected_version)
                        
                        from_inclusive = version_data.get('from_inclusive', True)
                        to_inclusive = version_data.get('to_inclusive', True)

                        passes_lower = current_ver >= from_ver if from_inclusive else current_ver > from_ver
                        passes_upper = current_ver <= to_ver if to_inclusive else current_ver < to_ver

                        if passes_lower and passes_upper:
                            title = vuln_data.get('title', 'Unknown Vulnerability')
                            
                            if any(keyword in title.lower() for keyword in precursor_keywords):
                                precursors_found.append(title)
                            else:
                                ignored_vulns.append(title)
                                
                    except Exception:
                        continue 

    if precursors_found:
        unique_precursors = list(set(precursors_found))
        label = "THEME" if software_type == 'theme' else "PLUGIN"
        print_and_log(f"    {RED}[TRUE PRECURSOR DETECTED] {label}:{plugin_slug} (v{detected_version}){RESET}")
        for v in unique_precursors:
            print_and_log(f"        -> Pathway: {v}")
    elif ignored_vulns:
        print_and_log(f"    {YELLOW}[IGNORED] {plugin_slug} (v{detected_version}) has general bugs, but NO webshell pathways.{RESET}")

# ==========================================
# .HTACCESS / .USER.INI TAMPER DETECTION
# ==========================================
HTACCESS_DANGER_PATTERNS = [
    (re.compile(rb'auto_prepend_file\s*=', re.IGNORECASE),                          'auto_prepend_file'),
    (re.compile(rb'auto_append_file\s*=', re.IGNORECASE),                           'auto_append_file'),
    (re.compile(rb'AddType\s+application/x-httpd-php', re.IGNORECASE),              'AddType PHP execution'),
    (re.compile(rb'SetHandler\s+application/x-httpd-php', re.IGNORECASE),           'SetHandler PHP'),
    (re.compile(rb'Options\s+[+]ExecCGI', re.IGNORECASE),                           'Options +ExecCGI'),
    (re.compile(rb'php_value\s+auto_prepend_file', re.IGNORECASE),                  'php_value auto_prepend_file'),
    (re.compile(rb'php_flag\s+engine\s+on', re.IGNORECASE),                         'php_flag engine on'),
    (re.compile(rb'<\?(php|=)', re.IGNORECASE),                                     'PHP code in .htaccess'),
]

def check_htaccess_tampering(target_url, mode="stealth"):
    """
    Fetch .htaccess and .user.ini files from key WP directories and scan for
    directives that enable PHP execution in directories where it should be blocked
    (especially uploads/). A tampered uploads/.htaccess is a common post-compromise
    persistence trick: the shell is a renamed .jpg that the modified .htaccess
    makes the server execute as PHP.
    """
    print_status("Step 1d: Checking .htaccess / .user.ini for PHP execution tampering...", "INFO")
    clean = target_url.rstrip('/')

    check_paths = [
        ('/wp-content/uploads/.htaccess',    '.htaccess in uploads (PHP exec bypass)'),
        ('/wp-content/uploads/.user.ini',    '.user.ini in uploads (PHP auto-prepend)'),
        ('/.htaccess',                        'Root .htaccess'),
        ('/wp-content/.htaccess',            'wp-content/.htaccess'),
        ('/wp-content/mu-plugins/.htaccess', 'mu-plugins/.htaccess'),
    ]

    tampered = []
    for path, label in check_paths:
        url = f"{clean}{path}"
        try:
            resp = requests.get(
                url,
                headers={'User-Agent': get_random_user_agent()},
                timeout=8, verify=False, allow_redirects=False,
            )
        except Exception:
            continue

        if resp.status_code == 200:
            body = resp.content[:8192]
            hits = [desc for pat, desc in HTACCESS_DANGER_PATTERNS if pat.search(body)]
            if hits:
                tampered.append(url)
                print_status(
                    f"[HTACCESS TAMPERED] {url} — dangerous directives: {', '.join(hits)}",
                    "ALERT"
                )
            else:
                print_status(f"[HTACCESS EXISTS] {url} — accessible but no dangerous directives. Review manually.", "WARN")

        if mode == "stealth":
            time.sleep(random.uniform(1.5, 3.0))

    if not tampered:
        print_status("No .htaccess / .user.ini PHP execution tampering detected.", "INFO")
    return tampered


# ==========================================
# WP-CONFIG.PHP BACKUP CREDENTIAL EXPOSURE
# ==========================================
WP_CONFIG_BACKUP_PATHS = [
    '/wp-config.php.bak',
    '/wp-config.php.old',
    '/wp-config.php.orig',
    '/wp-config.php.save',
    '/wp-config.php~',
    '/wp-config.bak',
    '/wp-config.old',
    '/wp-config.txt',
    '/local-config.php',
    '/wp-config.php.swp',
    '/.wp-config.php.swp',
]

WP_CONFIG_CRED_PATTERNS = [
    re.compile(rb"define\s*\(\s*['\"]DB_PASSWORD['\"]",  re.IGNORECASE),
    re.compile(rb"define\s*\(\s*['\"]DB_NAME['\"]",      re.IGNORECASE),
    re.compile(rb"define\s*\(\s*['\"]DB_USER['\"]",      re.IGNORECASE),
    re.compile(rb"\$table_prefix\s*=",                     re.IGNORECASE),
    re.compile(rb"define\s*\(\s*['\"]AUTH_KEY['\"]",     re.IGNORECASE),
    re.compile(rb"define\s*\(\s*['\"]SECRET_KEY['\"]",   re.IGNORECASE),
]

def check_wpconfig_backups(target_url, mode="stealth"):
    """
    Probe common wp-config.php backup filenames. An accessible backup exposes
    DB_NAME, DB_PASSWORD, DB_USER, AUTH_KEY, and table_prefix — sufficient for
    full database takeover and WordPress authentication bypass without any server
    access. WEBSHELL_PATTERNS won't detect these; they need credential-specific checks.
    """
    print_status("Step 1e: Probing wp-config.php backup variants for credential exposure...", "INFO")
    clean = target_url.rstrip('/')
    exposed = []

    for path in WP_CONFIG_BACKUP_PATHS:
        url = f"{clean}{path}"
        try:
            resp = requests.get(
                url,
                headers={'User-Agent': get_random_user_agent()},
                timeout=8, verify=False, allow_redirects=False,
            )
        except Exception:
            continue

        if resp.status_code == 200:
            body = resp.content[:16384]
            cred_hits = [pat.pattern for pat in WP_CONFIG_CRED_PATTERNS if pat.search(body)]
            if cred_hits:
                exposed.append(url)
                print_status(
                    f"[WP-CONFIG BACKUP EXPOSED] {url} — {len(cred_hits)} credential pattern(s) matched. DB credentials at risk.",
                    "ALERT"
                )
            else:
                print_status(f"[WP-CONFIG BACKUP] {url} — accessible but credential patterns not matched. Review manually.", "WARN")

        if mode == "stealth":
            time.sleep(random.uniform(1.5, 3.0))

    if not exposed:
        print_status("No wp-config.php backup credential exposure detected.", "INFO")
    return exposed


# ==========================================
# WP DEBUG LOG LEAK DETECTION
# ==========================================
def check_debug_log(target_url):
    """
    WP debug.log at wp-content/debug.log is frequently world-readable and leaks
    PHP error stack traces. These traces contain full server file paths — including
    paths to dropped shells that caused PHP errors on first execution, giving an
    attacker (or a scanner) a direct map to the backdoor's location.
    """
    print_status("Step 1f: Checking wp-content/debug.log for path leakage...", "INFO")
    clean = target_url.rstrip('/')
    log_url = f"{clean}/wp-content/debug.log"

    try:
        resp = requests.get(
            log_url,
            headers={'User-Agent': get_random_user_agent()},
            timeout=8, verify=False, allow_redirects=False,
        )
    except Exception as e:
        print_status(f"debug.log probe failed: {e}", "WARN")
        return []

    if resp.status_code != 200:
        print_status(f"debug.log not accessible (HTTP {resp.status_code})", "INFO")
        return []

    body = resp.text[:32768]
    print_status(f"[DEBUG LOG EXPOSED] {log_url} — {len(resp.content)} bytes publicly readable. Restrict immediately.", "ALERT")

    # extract PHP file paths from stack traces
    path_pat = re.compile(r'(?:in|require|include|Stack trace:.{0,40}?)\s+(/[^\s:\'\"]+\.php)', re.IGNORECASE)
    leaked = list(dict.fromkeys(m.group(1) for m in path_pat.finditer(body)))

    # flag paths in write-accessible dirs - most likely shell locations
    suspicious_paths = [p for p in leaked if any(d in p for d in ('/uploads/', '/tmp/', '/cache/', '/mu-plugins/'))]
    if suspicious_paths:
        print_status(f"[DEBUG LOG] {len(suspicious_paths)} suspicious PHP path(s) leaked (possible shell location):", "ALERT")
        for p in suspicious_paths[:10]:
            print_and_log(f"    {RED}→ {p}{RESET}")
    elif leaked:
        print_status(f"[DEBUG LOG] {len(leaked)} PHP file path(s) leaked via stack traces.", "WARN")

    return [log_url]


# ==========================================
# WP REST MEDIA SWEEP
# ==========================================
def scan_wp_rest_media(target_url, mode="stealth"):
    """
    Enumerate uploaded media via WP REST API.
    Catches renamed shells regardless of filename — FFUF can only guess names
    from a wordlist, but REST exposes every actual uploaded file.
    Returns list of suspicious URLs for downstream nuclei/content inspection.
    """
    print_status("Step 3c: WP REST Media Sweep (enumerating uploaded attachments)...", "INFO")
    PHP_EXTS = ('.php', '.phtml', '.phar', '.pht', '.php3', '.php5', '.php7', '.inc', '.shtml')
    suspicious = []
    clean = target_url.rstrip('/')
    page = 1
    total_checked = 0

    while True:
        url = (f"{clean}/wp-json/wp/v2/media"
               f"?per_page=100&page={page}"
               f"&_fields=source_url,mime_type,date,title")
        try:
            resp = requests.get(
                url,
                headers={'User-Agent': get_random_user_agent(), 'Accept': 'application/json'},
                timeout=12, verify=False, allow_redirects=True,
            )
        except Exception as e:
            print_status(f"REST media page {page} failed: {e}", "WARN")
            break

        if resp.status_code == 401:
            print_status("REST API /media requires authentication — sweep skipped.", "INFO")
            return []
        if resp.status_code == 404:
            print_status("REST API /media endpoint not found (disabled or custom prefix).", "INFO")
            return []
        if resp.status_code != 200:
            print_status(f"REST API /media returned HTTP {resp.status_code} on page {page} — stopping.", "WARN")
            break

        try:
            items = resp.json()
        except Exception:
            break

        if not isinstance(items, list) or not items:
            break

        for item in items:
            src = item.get('source_url', '') or ''
            mime = item.get('mime_type', '') or ''
            date = item.get('date', '') or ''
            total_checked += 1
            src_lower = src.lower()

            if any(src_lower.endswith(ext) for ext in PHP_EXTS):
                print_status(f"[REST-MEDIA] PHP-extension file in uploads: {src} (mime={mime}, date={date})", "ALERT")
                suspicious.append(src)
                continue

            if 'php' in mime.lower():
                print_status(f"[REST-MEDIA] PHP mime type on upload: {src} (mime={mime})", "ALERT")
                suspicious.append(src)
                continue

            # off-hours upload (00:00-05:00 UTC) on media files is anomalous - flag for review
            if date:
                try:
                    upload_hour = int(date[11:13])
                    if 0 <= upload_hour < 5:
                        print_status(f"[REST-MEDIA] Off-hours upload at {date[:16]} UTC: {src}", "WARN")
                except Exception:
                    pass

        if mode == "stealth":
            time.sleep(random.uniform(1.5, 3.0))

        if len(items) < 100:
            break
        page += 1

    level = "ALERT" if suspicious else "INFO"
    print_status(f"REST media sweep: {total_checked} attachments checked, {len(suspicious)} suspicious.", level)
    return suspicious


# ==========================================
# WP DROP-IN PERSISTENCE DETECTION
# ==========================================
WP_DROPIN_FILES = [
    'db.php',
    'object-cache.php',
    'advanced-cache.php',
    'sunrise.php',
    'blog-deleted.php',
    'blog-inactive.php',
    'blog-suspended.php',
]

def check_wp_dropins(target_url, mode="stealth"):
    """
    Probe WP drop-in plugin files under wp-content/. WordPress auto-loads
    every matching filename on each request with no admin activation required —
    making them the highest-value persistence path for attackers. A 200 + content
    signature match means the site is actively backdoored in the request pipeline.
    """
    print_status("Step 1c: Checking WP drop-in persistence paths...", "INFO")
    clean = target_url.rstrip('/')
    confirmed = []
    suspicious_dropins = []

    for dropin in WP_DROPIN_FILES:
        url = f"{clean}/wp-content/{dropin}"
        try:
            resp = requests.get(
                url,
                headers={'User-Agent': get_random_user_agent()},
                timeout=8, verify=False, allow_redirects=False,
            )
        except Exception:
            continue

        if resp.status_code == 200:
            sniff = inspect_url_for_shell_signatures(url)
            verdict = sniff['verdict']
            if verdict == 'CONFIRMED':
                confirmed.append(url)
                matched = ', '.join(sniff['matches'][:4])
                print_status(
                    f"[CONFIRMED DROPIN SHELL] {url} — auto-loaded every request. Patterns: {matched} sha256={sniff['sha256'][:16]}",
                    "ALERT"
                )
            elif verdict == 'SUSPICIOUS':
                suspicious_dropins.append(url)
                print_status(
                    f"[SUSPICIOUS DROPIN] {url} — shell patterns detected. sha256={sniff['sha256'][:16]}",
                    "ALERT"
                )
            else:
                print_status(
                    f"[DROPIN EXISTS] {url} — accessible, content appears clean. Verify manually. sha256={sniff['sha256'][:16]}",
                    "WARN"
                )
        elif resp.status_code == 403:
            print_status(f"[DROPIN] {url} → 403 (present but protected)", "INFO")

        if mode == "stealth":
            time.sleep(random.uniform(2.0, 4.0))

    if confirmed:
        print_and_log(f"\n{RED}=== [!!!] {len(confirmed)} DROP-IN SHELL(S) CONFIRMED — SITE ACTIVELY COMPROMISED [!!!] ==={RESET}")
        for u in confirmed:
            print_and_log(f"    {RED}→ {u}{RESET}")
    elif not suspicious_dropins:
        print_status("No suspicious WP drop-in files found.", "INFO")

    return confirmed + suspicious_dropins


# ==========================================
# DIRECTORY BRUTE-FORCING FOR EXISTING SHELLS
# ==========================================
def stealth_ffuf(target, plugins, wordlist_path=FFUF_DICT_FILE, mode="stealth"):
    """FFUF-driven discovery for the 3 webshell entry vectors, with soft-404
    baseline filtering and post-collection content-signature inspection.

    Filename matching alone produced false-positive 'CONFIRMED WEBSHELL'
    alerts. We now stage all hits, filter by per-directory soft-404 baselines,
    then GET each PHP-extension hit and regex-match the body against
    WEBSHELL_PATTERNS. CONFIRMED is only emitted on actual content evidence.
    """
    print_status(f"Step 3: {mode.capitalize()} Discovery (FFUF)...")

    # filename tiers - used as a base label only. final verdict comes from
    # inspect_url_for_shell_signatures(), not filename.
    CWE_434 = {'upload.php', 'test_upload.php', 'file_manager.php', 'up.php',
               'ajax_upload.php', 'uploader.php'}
    CWE_94  = {'debug.php', 'test.php', 'eval.php', 'cmd_test.php', 'info.php',
               'phpinfo.php', 'db_sync.php', 'exec.php', 'system.php', 'cmd.php'}
    LFI     = {'download.php', 'proxy.php', 'read.php', 'fetch.php', 'view.php',
               'db.php', 'sql.php'}
    KNOWN_SHELL_NAMES = {'shell.php', 'backdoor.php', 'wso.php', 'c99.php', 'r57.php',
                         'b374k.php', 'alfa.php', 'p0wny.php', 'bypass.php', 'webshell.php',
                         'vuln.php', 'exploit.php'}

    def classify_filename(url):
        fname = url.rstrip('/').split('/')[-1].lower()
        if fname in KNOWN_SHELL_NAMES:
            return ("Known shell filename (pre-content-check)", "T1505.003")
        if fname in CWE_434:
            return ("File Upload Vulnerability", "CWE-434")
        if fname in CWE_94:
            return ("RCE Precursor", "CWE-94")
        if fname in LFI:
            return ("LFI Precursor", "CWE-22/98")
        if fname.endswith(('.php', '.phtml', '.phar', '.pht', '.php3', '.php5', '.php7', '.inc')):
            return ("Unrecognized PHP file", "T1505.003 Precursor")
        return ("Suspicious file", "UNKNOWN")

    try:
        subprocess.run("ffuf -V", shell=True, capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print_status("FFUF not found. Please install it first.", "WARN")
        return []

    if not os.path.exists(wordlist_path):
        print_status(f"Wordlist '{wordlist_path}' not found! FFUF requires this list to run.", "WARN")
        return []

    try:
        with open(wordlist_path) as _wf:
            wl_count = sum(1 for l in _wf if l.strip())
    except Exception:
        wl_count = 50

    clean_target = target.rstrip('/')
    found_files = []
    staged_hits = []  # each: {url, length, base_label, base_cwe}

    # soft-404 baselines (filters WP themed-404 false positives)
    print_status("Computing soft-404 baselines for FFUF result filtering...", "INFO")
    baseline_dirs = ['/wp-content/uploads', '/wp-content/plugins', '/wp-admin']
    baselines = {}
    for d in baseline_dirs:
        b = compute_soft_404_baseline(clean_target, d)
        if b is not None:
            baselines[d] = b
            print_and_log(f"    [baseline] {d} → status={b['status']} len={b['len']} ct={b['content_type']}")
        if mode == "stealth":
            time.sleep(random.uniform(1.0, 2.5))

    if not baselines:
        print_status("No baselines obtained — soft-404 filtering disabled (results may include FPs).", "WARN")

    current_year = datetime.now().year
    current_month = datetime.now().month

    if plugins:
        temp_plugins_file = os.path.join(OUTPUT_DIR, "ffuf_plugins_list.txt")
        valid_plugins = [p for p in list(set(plugins)) if "," not in p and " " not in p]

        with open(temp_plugins_file, 'w') as f_plugins:
            f_plugins.write("\n".join(valid_plugins))

        print_and_log(f"    [>] Consolidating discovery for {len(valid_plugins)} plugins into a single pass...")
        print_and_log(f"    [>] Scanning Method 1+2: /wp-content/plugins/<plugin>/FUZZ ({wl_count} filenames × {len(valid_plugins)} plugins)")
        outfile = os.path.join(OUTPUT_DIR, "ffuf_consolidated_plugins.json")

        if mode == "aggressive":
            rate_param = f"-rate {FFUF_RATE}"
            threads_param = f"-t {FFUF_THREADS}"
            delay_param = ""
        else:
            rate_param = f"-rate {FFUF_RATE}"
            threads_param = f"-t {FFUF_THREADS}"
            delay_param = "-p 1.0-3.0"

        cmd = (f"ffuf -u {shlex.quote(clean_target)}/wp-content/plugins/W1/FUZZ "
               f"-w {shlex.quote(temp_plugins_file)}:W1 "
               f"-w {shlex.quote(wordlist_path)}:FUZZ "
               f"-mc 200 -fc 202,403,429,500,502,503 "
               f"{rate_param} {threads_param} {delay_param} "
               f"-H 'User-Agent: {get_random_user_agent()}' "
               f"-o {shlex.quote(outfile)} -of json")

        total_requests = len(valid_plugins) * wl_count
        if mode == "stealth":
            consolidated_timeout = max(300, total_requests * 3 + 120)
        else:
            consolidated_timeout = max(120, total_requests // 5 + 60)
        run_command(cmd, timeout_seconds=consolidated_timeout)

        try:
            if os.path.exists(outfile):
                with open(outfile, 'r') as f:
                    data = json.load(f)
                    for result in data.get('results', []):
                        found_path = result.get('url', '')
                        result_len = result.get('length', 0)
                        if not found_path:
                            continue
                        if matches_soft_404(found_path, result_len, baselines):
                            print_and_log(f"    [filtered: soft-404] {found_path} (len={result_len})")
                            continue
                        label, cwe = classify_filename(found_path)
                        found_files.append(found_path)
                        staged_hits.append({
                            'url': found_path, 'length': result_len,
                            'base_label': label, 'base_cwe': cwe,
                        })
                        print_status(f"[DETECTED] [{cwe}] {label}: {found_path} (len={result_len})", "WARN")
        except Exception:
            pass

        try: os.remove(temp_plugins_file)
        except: pass

    scan_targets = []
    for i in range(4):
        m = current_month - i
        y = current_year
        while m <= 0:
            m += 12
            y -= 1
        year_month_path = f"{y}/{m:02d}"
        scan_targets.append((f"/wp-content/uploads/{year_month_path}/FUZZ", f"vector1_uploads_{year_month_path.replace('/','_')}", "Method 1 — Unrestricted File Upload (CWE-434)"))

    scan_targets.append(("/wp-content/uploads/FUZZ", "vector1_uploads_root", "Method 1 — Unrestricted File Upload root (CWE-434)"))
    scan_targets.append(("/wp-content/plugins/FUZZ", "vector3_main_plugins", "Method 3 — Compromised Admin / Fake Plugin (T1505.003)"))
    scan_targets.append(("/wp-content/mu-plugins/FUZZ", "vector4_mu_plugins", "Method 4 — mu-plugins (auto-loaded, no admin activation required)"))
    scan_targets.append(("/wp-content/upgrade/FUZZ", "vector5_upgrade", "Method 5 — upgrade temp dir (often world-writable, frequently overlooked)"))
    scan_targets.append(("/wp-content/cache/FUZZ", "vector6_cache", "Method 6 — cache dir (common shell stash location)"))

    for scan_idx, (path_suffix, name, vector_label) in enumerate(scan_targets):
        target_path = f"{clean_target}{path_suffix}"
        outfile = os.path.join(OUTPUT_DIR, f"ffuf_{name}.json")

        speed_label = 'High speed' if mode == 'aggressive' else 'Very slow rate to avoid detection'
        print_and_log(f"    [>] Scanning target: {target_path} ({speed_label})")
        print_and_log(f"    [>] Vector: {vector_label}")

        if mode == "aggressive":
            rate_param = f"-rate {FFUF_RATE}"
            threads_param = f"-t {FFUF_THREADS}"
            delay_param = ""
        else:
            rate_param = f"-rate {FFUF_RATE}"
            threads_param = f"-t {FFUF_THREADS}"
            delay_param = "-p 1.0-3.0"

        cmd = (f"ffuf -u {shlex.quote(target_path)} -w {shlex.quote(wordlist_path)} "
               f"-mc 200 -fc 202,403,429,500,502,503 "
               f"{rate_param} {threads_param} {delay_param} "
               f"-H 'User-Agent: {get_random_user_agent()}' "
               f"-o {shlex.quote(outfile)} -of json -s 2>/dev/null")

        run_command(cmd)

        if scan_idx < len(scan_targets) - 1:
            sleep_time = random.uniform(15, 30) if mode == "stealth" else 1
            time.sleep(sleep_time)

        try:
            if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
                with open(outfile, 'r') as f:
                    try:
                        data = json.load(f)
                        for result in data.get('results', []):
                            url = result.get('url')
                            status = result.get('status')
                            length = result.get('length', 0)
                            if status == 200 and url:
                                if matches_soft_404(url, length, baselines):
                                    print_and_log(f"    [filtered: soft-404] {url} (len={length})")
                                    continue
                                label, cwe = classify_filename(url)
                                found_files.append(url)
                                staged_hits.append({
                                    'url': url, 'length': length,
                                    'base_label': label, 'base_cwe': cwe,
                                })
                                print_status(f"[DETECTED] [{cwe}] {label}: {url} (len={length})", "WARN")
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print_status(f"Error parsing ffuf output: {e}", "WARN")

    # content-signature inspection on PHP-extension hits
    php_exts = ('.php', '.phtml', '.phar', '.pht', '.php3', '.php5', '.php7', '.inc')
    sniff_targets = [h for h in staged_hits
                     if h['url'].rstrip('/').split('/')[-1].lower().endswith(php_exts)]
    if sniff_targets:
        print_status(f"Step 3b: Content-signature inspection on {len(sniff_targets)} PHP file(s)...", "INFO")
        confirmed_shells = []
        suspicious_files = []
        clean_files = []
        for hit in sniff_targets:
            sniff = inspect_url_for_shell_signatures(hit['url'])
            hit['sniff'] = sniff
            verdict = sniff['verdict']
            matched = ', '.join(sniff['matches'][:5]) if sniff['matches'] else '-'
            if verdict == 'CONFIRMED':
                confirmed_shells.append(hit)
                print_status(f"[CONFIRMED WEBSHELL] T1505.003 {hit['url']} (score={sniff['score']}, sha256={sniff['sha256'][:16]}, patterns: {matched})", "ALERT")
            elif verdict == 'SUSPICIOUS':
                suspicious_files.append(hit)
                print_status(f"[SUSPICIOUS] [{hit['base_cwe']}] {hit['url']} (score={sniff['score']}, patterns: {matched})", "WARN")
            else:
                clean_files.append(hit)
                print_status(f"[CLEAN-CONTENT] [{hit['base_cwe']}] {hit['url']} (status={sniff['status']}, len={sniff['length']}) — kept for nuclei", "INFO")
            time.sleep(random.uniform(2.0, 4.0) if mode == "stealth" else 0.1)

        if confirmed_shells:
            print_and_log(f"\n{RED}=== [!!!] {len(confirmed_shells)} WEBSHELL(S) CONFIRMED VIA CONTENT SIGNATURE [!!!] ==={RESET}")
            for h in confirmed_shells:
                print_and_log(f"    {RED}→ {h['url']} sha256={h['sniff']['sha256']}{RESET}")
        if suspicious_files:
            print_and_log(f"\n{YELLOW}=== [!] {len(suspicious_files)} SUSPICIOUS FILE(S) — REVIEW MANUALLY ==={RESET}")
            for h in suspicious_files:
                print_and_log(f"    {YELLOW}→ {h['url']} sha256={h['sniff']['sha256']}{RESET}")
    elif staged_hits:
        print_status("No PHP-extension files among FFUF hits — content inspection skipped.", "INFO")

    return found_files

def run_nuclei(suspicious_urls):
    print_status("Step 4: Signature Verification (Nuclei)...")
    if not suspicious_urls:
        return

    try:
        subprocess.run("nuclei -version", shell=True, capture_output=True, check=True)
    except subprocess.CalledProcessError:
        return

    unique_urls = list(dict.fromkeys(suspicious_urls))
    target_file = os.path.join(OUTPUT_DIR, "nuclei_targets.txt")
    outfile = os.path.join(OUTPUT_DIR, "nuclei_results.txt")

    with open(target_file, "w") as f:
        for url in unique_urls:
            f.write(url + "\n")

    cmd = (f"nuclei -l {shlex.quote(target_file)} "
           f"-tags webshell,exposure,backup,db,wordpress,wp-plugin,fileupload,cve "
           f"-rl {NUCLEI_RATE} -c {FFUF_THREADS} -o {shlex.quote(outfile)} -si 10 -json 2>/dev/null")

    run_command(cmd)

    HIGH_SEVERITY = {'critical', 'high'}
    SHELL_TAGS = {'webshell', 'backdoor', 'rce', 'exposure', 'fileupload'}

    nuclei_confirmed = []
    nuclei_notable = []

    try:
        if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
            with open(outfile, 'r') as f:
                for raw_line in f:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        finding = json.loads(raw_line)
                    except json.JSONDecodeError:
                        continue

                    severity = (finding.get('info', {}).get('severity') or '').lower()
                    tags = set(t.lower() for t in (finding.get('info', {}).get('tags') or []))
                    template_id = finding.get('template-id', '')
                    matched_at = finding.get('matched-at', '')
                    name = finding.get('info', {}).get('name', template_id)

                    if severity in HIGH_SEVERITY or bool(tags & SHELL_TAGS):
                        nuclei_confirmed.append({
                            'severity': severity, 'name': name,
                            'matched_at': matched_at, 'template_id': template_id, 'tags': tags,
                        })
                    elif severity == 'medium':
                        nuclei_notable.append({
                            'severity': severity, 'name': name,
                            'matched_at': matched_at, 'template_id': template_id,
                        })
    except Exception as e:
        print_status(f"Error reading Nuclei results: {e}", "WARN")

    if nuclei_confirmed:
        print_and_log(f"\n{RED}=== [!!!] {len(nuclei_confirmed)} HIGH/CRITICAL NUCLEI FINDING(S) [!!!] ==={RESET}")
        for fnd in nuclei_confirmed:
            tag_str = ','.join(sorted(fnd['tags']))
            print_and_log(f"    {RED}[{fnd['severity'].upper()}] {fnd['name']} → {fnd['matched_at']} (tags: {tag_str}){RESET}")
    if nuclei_notable:
        print_and_log(f"\n{YELLOW}=== [!] {len(nuclei_notable)} MEDIUM NUCLEI FINDING(S) ==={RESET}")
        for fnd in nuclei_notable:
            print_and_log(f"    {YELLOW}[MEDIUM] {fnd['name']} → {fnd['matched_at']}{RESET}")
    if not nuclei_confirmed and not nuclei_notable:
        print_status("No significant Nuclei findings.", "INFO")

def save_scan_to_supabase_and_summarize(scan_id, target_url, raw_log):
    if not SUPABASE_URL or not SUPABASE_KEY:
        print_status("SUPABASE_URL / SUPABASE_KEY not set. Skipping database save.", "WARN")
        return
    print_status("Saving raw scan log to Supabase...")
    try:
        supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
        
        # insert the initial raw data
        data = {
            "scan_id": str(scan_id),
            "target_url": target_url,
            "raw_log": raw_log
        }
        supabase.table("scan_logs").insert(data).execute()
        print_status(f"Successfully saved raw log to database! Scan ID: {scan_id}", "SUCCESS")
        
        # fetch the prompt from the database
        print_status("Fetching AI prompt from Supabase...")
        prompt_res = supabase.table("system_prompts").select("prompt_text").eq("prompt_name", "executive_summary").execute()
        
        if prompt_res.data:
            system_prompt = prompt_res.data[0]['prompt_text']

            if not GEMINI_API_KEY:
                print_status("GEMINI_API_KEY not set. Skipping AI summary.", "WARN")
                return

            # connect to gemini and generate the summary
            print_status("Generating AI Executive Summary with Gemini...")
            
            # initialize the new client
            client = genai.Client(api_key=GEMINI_API_KEY)
            
            max_retries = 5
            base_delay = 2
            ai_summary = None
            
            for attempt in range(max_retries):
                try:
                    # call the model using the new syntax
                    response = client.models.generate_content(
                        model='gemini-2.5-flash-lite',
                        contents=raw_log,
                        config=types.GenerateContentConfig(
                            system_instruction=system_prompt,
                        )
                    )
                    ai_summary = response.text
                    break  # success
                except Exception as e:
                    error_msg = str(e)
                    # check for 503 or UNAVAILABLE error
                    if "503" in error_msg or "UNAVAILABLE" in error_msg or "high demand" in error_msg.lower():
                        if attempt < max_retries - 1:
                            # exponential backoff with some jitter
                            delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                            print_status(f"Gemini API experiencing high demand (503). Retrying in {delay:.1f}s... (Attempt {attempt+1}/{max_retries})", "WARN")
                            time.sleep(delay)
                        else:
                            raise e
                    else:
                        raise e
            
            # update the database with the AI summary
            print_status("Updating database with AI Summary...")
            supabase.table("scan_logs").update({"ai_summary": ai_summary}).eq("scan_id", str(scan_id)).execute()
            print_status("Database updated successfully!", "SUCCESS")
            
            # save the summary locally to the output directory
            summary_file = os.path.join(OUTPUT_DIR, f"executive_summary_{scan_id}.txt")
            with open(summary_file, "w") as f:
                f.write(ai_summary)
            print_status(f"Saved AI Summary locally to {summary_file}", "SUCCESS")
            
            # print it beautifully to the terminal
            ai_lower = ai_summary.lower()
            is_critical = any(x in ai_lower for x in ["not safe", "immediate action", "critical", "vulnerable", "webshell", "compromised", "backdoor", "breach"])
            is_warning = any(x in ai_lower for x in ["warning", "outdated component", "potential access", "rate limited", "firewall blocked", "blocked"])
            
            summary_color = GREEN
            if is_critical:
                summary_color = RED
            elif is_warning:
                summary_color = YELLOW
                
            print(f"\n{summary_color}=========================================={RESET}")
            print(f"{summary_color}        AI EXECUTIVE SUMMARY              {RESET}")
            print(f"{summary_color}=========================================={RESET}")
            print(f"{summary_color}{ai_summary}{RESET}")
            print(f"{summary_color}=========================================={RESET}\n")
            
        else:
            print_status("System prompt 'executive_summary' not found in database. Skipping AI generation.", "WARN")
            
    except Exception as e:
        print_status(f"Failed during Database/AI integration: {e}", "ALERT")

# ==========================================
# MAIN EXECUTION BLOCK
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Webshell Hunter Security Scan")
    parser.add_argument("target", help="The target URL to scan")
    parser.add_argument("--mode", choices=["stealth", "aggressive"], default="stealth", help="Scan speed mode")
    parser.add_argument("--master-list", default=MASTER_PLUGINS_FILE, help="Path to master plugins list")
    parser.add_argument("--wordlist", default=FFUF_DICT_FILE, help="Path to FFUF webshell dictionary")
    
    args = parser.parse_args()
    target = resolve_target_url(args.target.rstrip('/'))
    
    # update global configurations based on mode
    if args.mode == "aggressive":
        print("[!] AGGRESSIVE MODE ENABLED - Increased scan speed")
        FFUF_RATE = 50
        FFUF_THREADS = 10
        NUCLEI_RATE = 50
    else:
        # default stealth settings already mostly match globals
        FFUF_RATE = 1
        FFUF_THREADS = 1
        NUCLEI_RATE = 5

    # target specific wordlists
    MASTER_PLUGINS_FILE = args.master_list
    FFUF_DICT_FILE = args.wordlist

    # generate a unique ID for this execution
    current_scan_id = uuid.uuid4()

    # bug 10 fix: clean up old scan output at scan start, not at import time
    for old_file in glob.glob(os.path.join(OUTPUT_DIR, "*.json")):
        try:
            os.remove(old_file)
        except OSError:
            pass

    # bug 9 fix: start the timer HERE, not at import time
    SCAN_START_TIME = time.time()

    # ensure database is present and fresh
    ensure_wordfence_db()

    print_and_log(f"\n{GREEN}=== Starting MITRE T1505.003 Scan on: {target} ==={RESET}")
    print_and_log(f"=== Scan ID: {current_scan_id} ===\n")
    
    status_code, detected_wafs = check_waf(target)
    if status_code == 429:
        print_status("HTTP 429 (rate limiting). Forcing stealth mode.", "WARN")
        args.mode = "stealth"
        FFUF_RATE = 1
        FFUF_THREADS = 1
        NUCLEI_RATE = 5
    elif status_code == 403:
        print_status("HTTP 403 (access denied). Site may be blocking scanners.", "WARN")
    elif status_code == 202:
        print_status("HTTP 202 — bot-challenge active. Stealth mode recommended; passive results may be incomplete.", "WARN")
        if args.mode != "aggressive":
            args.mode = "stealth"
    if detected_wafs:
        print_status(f"Active protections identified: {', '.join(detected_wafs)}", "WARN")
        if any(w in detected_wafs for w in ("NinjaFirewall", "Cloudflare Bot Management", "Cloudflare Challenge", "NinjaFirewall Challenge")):
            print_status("Bot-challenge WAF detected — scanner requests may return challenge pages instead of real content.", "WARN")

    # metadata call
    site_meta = extract_site_metadata(target)

    passive_found, themes_found, was_blocked, passive_plugin_versions, wp_core_version = enhanced_passive_scan(target)
    
    if was_blocked:
        print_status("[!] Rate-limiting detected! Aggressive mode may miss some results.", "WARN")
        print_status("[i] Consider rescanning in Stealth mode if key information is missing.", "INFO")

    # unauthenticated T1505.003 direct-access vector probes
    probe_unauthenticated_vectors(target)

    # WP drop-in persistence path probes (auto-loaded files - highest-value persistence)
    dropin_hits = check_wp_dropins(target, mode=args.mode)

    # .htaccess / .user.ini PHP execution tampering check
    htaccess_hits = check_htaccess_tampering(target, mode=args.mode)

    # wp-config.php backup credential exposure
    wpconfig_hits = check_wpconfig_backups(target, mode=args.mode)

    # wp-content/debug.log path leakage
    debuglog_hits = check_debug_log(target)

    # optimization with track A list
    optimized_list = get_optimized_list(MASTER_PLUGINS_FILE, passive_found)

    if optimized_list or passive_found:
        final_plugin_list, plugin_versions = stealth_wpscan(target, optimized_list, passive_found, mode=args.mode, passive_versions=passive_plugin_versions)

        if final_plugin_list:
            # brute forcing with track B list
            suspicious_files = stealth_ffuf(target, final_plugin_list, FFUF_DICT_FILE, mode=args.mode)

            # WP REST media sweep - enumerates actual uploads, catches renamed shells
            rest_media_hits = scan_wp_rest_media(target, mode=args.mode)

            all_suspicious = list(dict.fromkeys(
                suspicious_files + rest_media_hits + dropin_hits +
                htaccess_hits + wpconfig_hits + debuglog_hits
            ))
            if all_suspicious:
                run_nuclei(all_suspicious)
            else:
                print_status("No suspicious files found during directory brute-forcing or media sweep.", "INFO")
    else:
        print_status("No plugins identified via passive or active scanning. Skipping FFUF and Nuclei.", "WARN")
        # still run REST media sweep and drop-in check - these don't need plugin list
        rest_media_hits = scan_wp_rest_media(target, mode=args.mode)
        all_suspicious = list(dict.fromkeys(
            rest_media_hits + dropin_hits +
            htaccess_hits + wpconfig_hits + debuglog_hits
        ))
        if all_suspicious:
            run_nuclei(all_suspicious)
    
    # print total elapsed time for the full scan
    total_elapsed = int(time.time() - SCAN_START_TIME)
    total_mins = total_elapsed // 60
    total_secs = total_elapsed % 60
    
    print_and_log(f"\n{GREEN}=== Scan Complete in [{total_mins:02d}:{total_secs:02d}] ==={RESET}\n")

    # push logs to DB, generate AI summary, and update DB
    save_scan_to_supabase_and_summarize(current_scan_id, target, RAW_LOG_BUFFER)
