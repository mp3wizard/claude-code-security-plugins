"""TEST FIXTURE — intentionally vulnerable. Do not deploy.

Used by tests/run-tests.sh to confirm Bandit/Semgrep actually fire.
Every construct below is a deliberate planted finding.
"""
import hashlib
import os
import pickle
import subprocess

import yaml


def weak_hash(password):
    # Bandit B303 — insecure MD5
    return hashlib.md5(password.encode()).hexdigest()


def run_user_cmd(user_input):
    # Bandit B602 — subprocess with shell=True on untrusted input (command injection)
    return subprocess.call("echo " + user_input, shell=True)


def eval_expr(expr):
    # Bandit B307 — eval on untrusted input
    return eval(expr)


def load_config(blob):
    # Bandit B506 — yaml.load without SafeLoader
    return yaml.load(blob)


def load_pickle(data):
    # Bandit B301 — insecure deserialization
    return pickle.loads(data)


# Hardcoded credential — planted secret for Gitleaks/TruffleHog/Semgrep p/secrets.
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # noqa
DEBUG = True  # security misconfiguration when shipped to prod


def os_system(cmd):
    # Bandit B605 — os.system with f-string
    os.system(f"ls {cmd}")
