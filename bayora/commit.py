"""Commit-reveal for blind tests: teams publish H(nonce || content) before the run and reveal after."""
import hashlib, os


def commit(content: bytes):
    nonce = os.urandom(16)
    return hashlib.sha256(nonce + content).hexdigest(), nonce


def verify_reveal(commitment_hex, nonce, content: bytes):
    return hashlib.sha256(nonce + content).hexdigest() == commitment_hex
