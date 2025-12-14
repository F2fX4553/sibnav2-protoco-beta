from ._native import *
import ctypes

class ProtocolError(Exception):
    pass

class SecureContext:
    def __init__(self, **kwargs):
        if not lib:
            raise RuntimeError("Native library not loaded")
            
        config = ConfigFFI()
        config.enable_forward_secrecy = kwargs.get("enable_forward_secrecy", True)
        config.enable_post_compromise_security = kwargs.get("enable_post_compromise_security", True)
        config.max_skipped_messages = kwargs.get("max_skipped_messages", 2000)
        config.key_rotation_interval = kwargs.get("key_rotation_interval", 86400)
        config.handshake_timeout = kwargs.get("handshake_timeout", 30)
        config.message_buffer_size = kwargs.get("message_buffer_size", 1024)
        
        self._handle = lib.secure_context_create(ctypes.byref(config))
        if not self._handle:
            raise ProtocolError("Failed to create context")
            
    def __del__(self):
        if hasattr(self, "_handle") and self._handle and lib:
            lib.secure_context_free(self._handle)

    def create_session(self, peer_id: bytes) -> "SecureSession":
        if not isinstance(peer_id, bytes):
            raise TypeError("peer_id must be bytes")
            
        handle = lib.secure_session_create(
            self._handle,
            (c_uint8 * len(peer_id)).from_buffer_copy(peer_id),
            len(peer_id)
        )
        
        if not handle:
            raise ProtocolError("Failed to create session")
            
        return SecureSession(handle)

class SecureSession:
    def __init__(self, handle):
        self._handle = handle
        
    # We do NOT implement __del__ to free the session handle here easily
    # because session ownership semantics in C++ wrapper were unique_ptr.
    # But in Python, if we just expose the handle, we need to be careful.
    # Ideally, we expose a free method or wrap it in a safe object.
    # The FFI `secure_session_free` cleans up the Arc reference.
    # So yes, we should call it on GC.
    
    def encrypt(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
            
        out_ptr = POINTER(c_uint8)()
        out_len = c_size_t(0)
        
        res = lib.secure_session_encrypt(
            self._handle,
            (c_uint8 * len(plaintext)).from_buffer_copy(plaintext),
            len(plaintext),
            ctypes.byref(out_ptr),
            ctypes.byref(out_len)
        )
        
        if res != FFI_SUCCESS:
            raise ProtocolError(f"Encryption failed: {res}")
            
        try:
            # Copy data to python bytes
            # We cast the pointer to char pointer to use string_at, 
            # but string_at stops at null? No, can take size.
            return ctypes.string_at(out_ptr, out_len.value)
        finally:
            lib.secure_free_buffer(out_ptr, out_len)
            
    def decrypt(self, ciphertext: bytes) -> bytes:
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")
            
        out_ptr = POINTER(c_uint8)()
        out_len = c_size_t(0)
        
        res = lib.secure_session_decrypt(
            self._handle,
            (c_uint8 * len(ciphertext)).from_buffer_copy(ciphertext),
            len(ciphertext),
            ctypes.byref(out_ptr),
            ctypes.byref(out_len)
        )
        
        if res != FFI_SUCCESS:
            raise ProtocolError(f"Decryption failed: {res}")
            
        try:
            return ctypes.string_at(out_ptr, out_len.value)
        finally:
            lib.secure_free_buffer(out_ptr, out_len)

def generate_keypair():
    public = (c_uint8 * 32)()
    private = (c_uint8 * 32)()
    
    res = lib.secure_generate_keypair(public, private)
    if res != FFI_SUCCESS:
        raise ProtocolError("Key generation failed")
        
    return bytes(public), bytes(private)
