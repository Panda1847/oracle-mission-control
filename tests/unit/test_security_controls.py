from pathlib import Path

from security.binary_verifier import verify_binaries
from security.plugin_sandbox import PluginSandbox
from security.signer import CommandSigner
from security.vault import SecretVault


def test_command_signer_signs_and_verifies():
    signer = CommandSigner("oracle-secret")
    payload = {"command": "nmap -sV 127.0.0.1"}
    signed = signer.sign(payload)
    assert signer.verify(payload, signed["signature"])


def test_secret_vault_round_trip(tmp_path):
    vault = SecretVault(tmp_path / "vault.json", "passphrase")
    vault.store("api_key", "secret-value")
    assert vault.get("api_key") == "secret-value"
    assert vault.export_masked() == {"api_key": "***"}


def test_plugin_sandbox_and_binary_verifier():
    sandbox = PluginSandbox(allowed_binaries=["echo"])
    allowed = sandbox.validate("echo hi")
    denied = sandbox.validate("printf hi")
    assert allowed.allowed is True
    assert denied.allowed is False
    verified = verify_binaries(["sh"])
    assert verified["sh"]["present"] is True

