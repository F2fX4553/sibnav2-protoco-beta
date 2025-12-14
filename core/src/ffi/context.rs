use super::*;
use std::slice;

#[repr(C)]
pub struct ConfigFFI {
    enable_forward_secrecy: u8,
    enable_post_compromise_security: u8,
    max_skipped_messages: size_t,
    key_rotation_interval: u64,
    handshake_timeout: u64,
    message_buffer_size: size_t,
}

impl From<ConfigFFI> for crate::Config {
    fn from(config: ConfigFFI) -> Self {
        Self {
            enable_forward_secrecy: config.enable_forward_secrecy != 0,
            enable_post_compromise_security: config.enable_post_compromise_security != 0,
            max_skipped_messages: config.max_skipped_messages,
            key_rotation_interval: config.key_rotation_interval,
            handshake_timeout: config.handshake_timeout,
            message_buffer_size: config.message_buffer_size,
        }
    }
}

#[no_mangle]
pub extern "C" fn secure_context_create(config: *const ConfigFFI) -> *mut SecureContextHandle {
    // We can't return Result across FFI easily for constructors returning pointers, usually return NULL on fail
    let result = panic::catch_unwind(|| {
        let rs_config = if config.is_null() {
            crate::Config::default()
        } else {
            unsafe { crate::Config::from(ptr::read(config)) }
        };
        
        match SecureContext::new(rs_config) {
            Ok(ctx) => {
                let handle = Box::new(SecureContextHandle {
                    context: Box::into_raw(Box::new(ctx)),
                });
                Box::into_raw(handle)
            }
            Err(_) => ptr::null_mut(),
        }
    });
    
    result.unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn secure_context_free(handle: *mut SecureContextHandle) -> FFIError {
    if handle.is_null() {
        return FFIError::NullPointer;
    }
    
    unsafe {
        let handle = Box::from_raw(handle);
        if !handle.context.is_null() {
            drop(Box::from_raw(handle.context));
        }
    }
    
    FFIError::Success
}

#[no_mangle]
pub extern "C" fn secure_session_create(
    context: *mut SecureContextHandle,
    peer_id: *const uint8_t,
    peer_id_len: size_t,
) -> *mut SecureSessionHandle {
    if context.is_null() || peer_id.is_null() {
        return ptr::null_mut();
    }
    
    let result = panic::catch_unwind(|| {
        unsafe {
            let ctx_handle = &*context;
            let ctx = &*ctx_handle.context;
            
            let peer_id_slice = slice::from_raw_parts(peer_id, peer_id_len);
            
            match ctx.create_session(peer_id_slice) {
                Ok(session_handle) => {
                    let session_arc = session_handle.session();
                    // We need to keep the session alive. 
                    // SessionHandle holds an Arc. 
                    // But our FFI SecureSessionHandle holds a *mut DoubleRatchetSession?
                    // Wait, DoubleRatchetSession is inside an RwLock inside an Arc.
                    // We need a stable pointer. 
                    // Let's change SecureSessionHandle to hold the raw pointer to the Arc or simply use the Arc via raw pointer.
                    // Actually, if we want to share the session between Context (SessionManager) and the Handle returned here,
                    // we should probably keep the Arc alive.
                    
                    // For FFI simplicity, let's say the Handle owns a `Clone` of the Arc.
                    // But we need to define SecureSessionHandle to hold *const c_void which is the Arc.
                    let raw_arc = std::sync::Arc::into_raw(session_arc);
                    
                    Box::into_raw(Box::new(SecureSessionHandle {
                        session: raw_arc as *mut DoubleRatchetSession, // Casting const to mut for the struct, but treat carefully
                    }))
                }
                Err(_) => ptr::null_mut(),
            }
        }
    });
    
    result.unwrap_or(ptr::null_mut())
}
