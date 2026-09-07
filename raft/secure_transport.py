import os
import hmac
import json
import time
import base64
import hashlib
from typing import Dict, Optional, Tuple, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecureKeystore:

	def __init__(self, keys: Optional[Dict[str, bytes]] = None):
		self._keys = dict(keys or {})

	def add_key(self, key_id: str, key_material: bytes) -> None:
		self._keys[key_id] = key_material

	def get_key(self, key_id: str) -> Optional[bytes]:
		return self._keys.get(key_id)


class ReplayCache:

	def __init__(self, max_entries_per_peer: int = 2048, ttl_seconds: int = 1800):
		self._max_entries_per_peer = max_entries_per_peer
		self._ttl_seconds = ttl_seconds
		self._peer_to_txid_to_ts: Dict[str, Dict[str, float]] = {}

	def _prune(self, peer_id: str) -> None:
		now = time.time()
		bucket = self._peer_to_txid_to_ts.get(peer_id)
		if not bucket:
			return
		# TTL prune
		expired = [tx_id for tx_id, ts in bucket.items() if (now - ts) > self._ttl_seconds]
		for tx_id in expired:
			bucket.pop(tx_id, None)
		# Size prune (simple FIFO by timestamp)
		if len(bucket) > self._max_entries_per_peer:
			sorted_tx = sorted(bucket.items(), key=lambda kv: kv[1])
			for tx_id, _ in sorted_tx[: (len(bucket) - self._max_entries_per_peer)]:
				bucket.pop(tx_id, None)

	def seen(self, peer_id: str, tx_id: str) -> bool:
		self._prune(peer_id)
		bucket = self._peer_to_txid_to_ts.get(peer_id)
		seen = tx_id in bucket if bucket else False
		return seen

	def remember(self, peer_id: str, tx_id: str) -> None:
		bucket = self._peer_to_txid_to_ts.setdefault(peer_id, {})
		bucket[tx_id] = time.time()
		self._prune(peer_id)


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
	if not salt:
		salt = b"\x00" * hashlib.sha256().digest_size
	prk = hmac.new(salt, ikm, hashlib.sha256).digest()
	okm = b""
	prev = b""
	blocks = (length + 31) // 32
	for i in range(1, blocks + 1):
		prev = hmac.new(prk, prev + info + bytes([i]), hashlib.sha256).digest()
		okm += prev
	return okm[:length]


def _b64e(b: bytes) -> str:
	return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
	return base64.b64decode(s.encode("ascii"))


def _serialize_message(message_dict: Dict[str, Any]) -> bytes:
	return json.dumps(message_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _context_binding(message_dict: Dict[str, Any], peer_id: str) -> bytes:
	# Use only peer_id to derive the per-message key so the receiver
	# can compute it before decrypting the payload.
	return peer_id.encode("utf-8")


def _compute_tag(key: bytes, fields: Tuple[bytes, ...]) -> bytes:
	mac = hmac.new(key, digestmod=hashlib.sha256)
	for field in fields:
		mac.update(len(field).to_bytes(4, "big"))
		mac.update(field)
	return mac.digest()


def encode_secure_message(
	message_dict: Dict[str, Any],
	peer_id: str,
	key_id: str,
	keystore: SecureKeystore,
	confidential: bool = False,
) -> Dict[str, Any]:
	K_master = keystore.get_key(key_id)
	if not K_master:
		raise ValueError("Unknown key_id")

	# AES-GCM standard nonce length is 12 bytes
	nonce = os.urandom(12)
	tx_id = os.urandom(16)
	context = _context_binding(message_dict, peer_id)
	K_tx = _hkdf_sha256(ikm=K_master, salt=nonce, info=context, length=32)

	plaintext = _serialize_message(message_dict)
	# AEAD: AES-256-GCM for authenticity and optional confidentiality
	aad = b"|".join([key_id.encode("utf-8"), nonce, tx_id, context])
	if confidential:
		aesgcm = AESGCM(K_tx)
		ct = aesgcm.encrypt(nonce=nonce, data=plaintext, associated_data=aad)
		ciphertext, tag = ct[:-16], ct[-16:]
	else:
		# Integrity-only: compute tag over plaintext, no encryption
		ciphertext = plaintext
		tag = _compute_tag(K_tx, (aad, ciphertext))

	return {
		"key_id": key_id,
		"nonce": _b64e(nonce),
		"tx_id": _b64e(tx_id),
		"payload": _b64e(ciphertext),
		"tag": _b64e(tag),
	}


def decode_secure_message(
	envelope: Dict[str, Any],
	peer_id: str,
	keystore: SecureKeystore,
	replay_cache: ReplayCache,
	confidential: bool = False,
) -> Dict[str, Any]:
	key_id = str(envelope.get("key_id"))
	nonce = _b64d(str(envelope.get("nonce")))
	tx_id_b = _b64d(str(envelope.get("tx_id")))
	payload = _b64d(str(envelope.get("payload")))
	tag = _b64d(str(envelope.get("tag")))

	tx_id = base64.b16encode(tx_id_b).decode("ascii")
	if replay_cache.seen(peer_id, tx_id):
		raise ValueError("Replay detected")

	K_master = keystore.get_key(key_id)
	if not K_master:
		raise ValueError("Unknown key_id")

	# We need context to derive K_tx. Bind only to peer_id so this is available pre-decryption.
	message_dict = {}
	context = _context_binding(message_dict, peer_id)
	K_tx = _hkdf_sha256(ikm=K_master, salt=nonce, info=context, length=32)
	aad = b"|".join([key_id.encode("utf-8"), nonce, tx_id_b, context])
	if confidential:
		try:
			aesgcm = AESGCM(K_tx)
			ct = payload + tag
			plaintext = aesgcm.decrypt(nonce=nonce, data=ct, associated_data=aad)
		except Exception as exc:
			print("[secure_transport] Decryption/authentication failed")
			raise ValueError("Authentication failed") from exc
	else:
		calc_tag = _compute_tag(K_tx, (aad, payload))
		if not hmac.compare_digest(calc_tag, tag):
			print("[secure_transport] Authentication failed (integrity-only)")
			raise ValueError("Authentication failed")
		plaintext = payload

	try:
		message = json.loads(plaintext.decode("utf-8"))
	except Exception as exc:
		raise ValueError("Invalid payload JSON") from exc

	replay_cache.remember(peer_id, tx_id)
	return message


__all__ = [
	"SecureKeystore",
	"ReplayCache",
	"encode_secure_message",
	"decode_secure_message",
]


