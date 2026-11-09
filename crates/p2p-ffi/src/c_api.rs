//! C-ABI Interface com Memória Compartilhada (Zero-Copy) para Android, Electron, iOS e C/C++.

use crate::engine::FfiEngine;
use crate::memory::FfiByteBuffer;
use p2p_core::identity::UserIdentity;
use p2p_core::runtime::{CoreCommand, CoreConfig};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;

/// Código de retorno de sucesso nas operações C
pub const FFI_OK: i32 = 0;
/// Código de retorno de erro de ponteiro nulo
pub const FFI_ERR_NULL_PTR: i32 = -1;
/// Código de retorno de erro de decodificação
pub const FFI_ERR_CODEC: i32 = -2;
/// Código de retorno de erro ao executar/enviar comando
pub const FFI_ERR_EXEC: i32 = -3;

use std::sync::Mutex;

static LAST_ERROR: Mutex<String> = Mutex::new(String::new());

pub fn set_last_error(msg: String) {
    if let Ok(mut lock) = LAST_ERROR.lock() {
        *lock = msg;
    }
}

pub fn get_last_error() -> String {
    LAST_ERROR.lock().map(|l| l.clone()).unwrap_or_default()
}

/// Inicia o nó P2P com configurações básicas (Nick, Diretório de Armazenamento e Porta).
///
/// # Safety
/// `nick` e `data_dir` devem ser strings válidas terminadas em null (`\0`).
#[no_mangle]
pub unsafe extern "C" fn p2p_ffi_start_simple(
    nick: *const c_char,
    data_dir: *const c_char,
    port: u16,
) -> *mut FfiEngine {
    if nick.is_null() || data_dir.is_null() {
        set_last_error("Ponteiro nulo passado para p2p_ffi_start_simple".into());
        return std::ptr::null_mut();
    }

    let nick_str = match CStr::from_ptr(nick).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("Nick inválido: {}", e));
            return std::ptr::null_mut();
        }
    };
    let dir_str = match CStr::from_ptr(data_dir).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("DataDir inválido: {}", e));
            return std::ptr::null_mut();
        }
    };

    let dir_path = PathBuf::from(dir_str);
    let _ = std::fs::create_dir_all(&dir_path);
    let _ = std::fs::create_dir_all(dir_path.join("servers"));
    let _ = std::fs::create_dir_all(dir_path.join("downloads"));

    let identity_path = dir_path.join("identity.json");
    let mut identity = if identity_path.exists() {
        UserIdentity::load_or_create(&identity_path).unwrap_or_else(|_| UserIdentity::generate_with_nick(nick_str))
    } else {
        UserIdentity::generate_with_nick(nick_str)
    };
    identity.profile.display_name = nick_str.to_string();
    let _ = identity.save_to(&identity_path);

    let mut config = CoreConfig::new(identity, dir_path.join("servers"), dir_path.join("downloads"));
    config.identity_path = Some(identity_path);
    config.config_path = Some(dir_path.join("config.json"));
    config.port = port;
    config.listen_ip = None; // 0.0.0.0 em produção/mobile
    config.discovery = true;
    config.public_defaults = true;
    // Em mobile, mDNS sem permissão de multicast e sem MulticastLock do Wi-Fi falha o socket UDP
    config.mdns = false;
    // UPnP só manda o M-SEARCH e recebe resposta unicast: não depende do MulticastLock.
    // Desligável por `network.upnp` no config.json
    config.upnp = true;

    match FfiEngine::start(config) {
        Ok(engine) => Box::into_raw(Box::new(engine)),
        Err(e) => {
            let err_msg = format!("FfiEngine::start falhou: {}", e);
            eprintln!("[p2p_ffi] {}", err_msg);
            set_last_error(err_msg);
            std::ptr::null_mut()
        }
    }
}

/// Envia um comando em formato binário (ou JSON) apontando para uma fatia de memória direta.
///
/// # Safety
/// `engine` e `cmd_ptr` devem ser ponteiros válidos.
#[no_mangle]
pub unsafe extern "C" fn p2p_ffi_send_command(
    engine: *mut FfiEngine,
    cmd_ptr: *const u8,
    cmd_len: usize,
) -> i32 {
    if engine.is_null() || cmd_ptr.is_null() {
        return FFI_ERR_NULL_PTR;
    }
    let slice = std::slice::from_raw_parts(cmd_ptr, cmd_len);
    let eng = &*engine;

    match eng.send_command_bytes(slice) {
        Ok(_) => FFI_OK,
        Err(crate::engine::FfiError::Codec(_)) => FFI_ERR_CODEC,
        Err(_) => FFI_ERR_EXEC,
    }
}

/// Atalho de alta velocidade para enviar uma mensagem de texto no canal ativo.
///
/// # Safety
/// `engine` e `text` devem ser ponteiros válidos.
#[no_mangle]
pub unsafe extern "C" fn p2p_ffi_send_message(
    engine: *mut FfiEngine,
    text: *const c_char,
) -> i32 {
    if engine.is_null() || text.is_null() {
        return FFI_ERR_NULL_PTR;
    }
    let text_str = match CStr::from_ptr(text).to_str() {
        Ok(s) => s,
        Err(_) => return FFI_ERR_CODEC,
    };
    let eng = &*engine;

    match eng.send_command(CoreCommand::SendMessage(text_str.to_string())) {
        Ok(_) => FFI_OK,
        Err(_) => FFI_ERR_EXEC,
    }
}

/// Atalho para trocar de canal de texto.
///
/// # Safety
/// `engine` e `channel` devem ser ponteiros válidos.
#[no_mangle]
pub unsafe extern "C" fn p2p_ffi_join_channel(
    engine: *mut FfiEngine,
    channel: *const c_char,
) -> i32 {
    if engine.is_null() || channel.is_null() {
        return FFI_ERR_NULL_PTR;
    }
    let channel_str = match CStr::from_ptr(channel).to_str() {
        Ok(s) => s,
        Err(_) => return FFI_ERR_CODEC,
    };
    let eng = &*engine;

    match eng.send_command(CoreCommand::JoinChannel(channel_str.to_string())) {
        Ok(_) => FFI_OK,
        Err(_) => FFI_ERR_EXEC,
    }
}

/// Coleta o próximo evento gerado pelo core em formato binário Postcard (Zero-Copy).
///
/// O chamador externo DEVE chamar `p2p_ffi_free_buffer` com o buffer retornado após a leitura.
///
/// # Safety
/// `engine` deve ser um ponteiro válido.
#[no_mangle]
pub unsafe extern "C" fn p2p_ffi_poll_event(engine: *mut FfiEngine) -> FfiByteBuffer {
    if engine.is_null() {
        return FfiByteBuffer::empty();
    }
    let eng = &mut *engine;
    match eng.poll_event_bytes() {
        Some(bytes) => FfiByteBuffer::from_vec(bytes),
        None => FfiByteBuffer::empty(),
    }
}

/// Coleta o próximo evento serializado em JSON (para integrações que prefiram JSON).
///
/// # Safety
/// `engine` deve ser um ponteiro válido.
#[no_mangle]
pub unsafe extern "C" fn p2p_ffi_poll_event_json(engine: *mut FfiEngine) -> FfiByteBuffer {
    if engine.is_null() {
        return FfiByteBuffer::empty();
    }
    let eng = &mut *engine;
    match eng.poll_event() {
        Some(ev) => match serde_json::to_vec(&ev) {
            Ok(v) => FfiByteBuffer::from_vec(v),
            Err(_) => FfiByteBuffer::empty(),
        },
        None => FfiByteBuffer::empty(),
    }
}

/// Retorna a porta local de escuta (TCP e UDP/QUIC) do nó.
///
/// # Safety
/// `engine` deve ser um ponteiro válido.
#[no_mangle]
pub unsafe extern "C" fn p2p_ffi_listen_port(engine: *mut FfiEngine) -> u16 {
    if engine.is_null() {
        0
    } else {
        let eng = &*engine;
        eng.listen_port()
    }
}

/// Envia sinal de encerramento para o nó P2P.
///
/// # Safety
/// `engine` deve ser um ponteiro válido.
#[no_mangle]
pub unsafe extern "C" fn p2p_ffi_stop(engine: *mut FfiEngine) {
    if !engine.is_null() {
        let eng = &*engine;
        eng.stop();
    }
}

/// Destrói a instância do motor FFI liberando sua memória na heap.
///
/// # Safety
/// Deve ser chamado apenas uma vez quando o app estiver finalizando.
#[no_mangle]
pub unsafe extern "C" fn p2p_ffi_destroy(engine: *mut FfiEngine) {
    if !engine.is_null() {
        let boxed = Box::from_raw(engine);
        boxed.stop();
        drop(boxed);
    }
}
