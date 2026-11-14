//! Primitivas de memória compartilhada (Zero-Copy) para FFI C / Android / Electron / Desktop.

use std::ptr;

/// Estrutura universal com layout C `#[repr(C)]` representando um buffer de memória nativa.
///
/// Pode ser lida diretamente por:
/// - **Rust:** `buf.as_slice()`
/// - **Android (Kotlin):** `ByteBuffer.wrap()` ou `env.NewDirectByteBuffer(buf.ptr, buf.len)`
/// - **Electron / Node.js:** `Buffer.from(ptr, len)`
/// - **C / C++ / C# / Swift:** Ponteiro direto e tamanho em bytes
#[repr(C)]
#[derive(Debug)]
pub struct FfiByteBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl FfiByteBuffer {
    /// Converte um `Vec<u8>` de Rust em `FfiByteBuffer` sem copiar nenhum byte na memória.
    pub fn from_vec(mut v: Vec<u8>) -> Self {
        let ptr = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        std::mem::forget(v); // O caller externo agora gerencia este buffer
        Self { ptr, len, cap }
    }

    /// Cria um buffer vazio.
    pub fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    /// Verifica se o buffer é nulo ou vazio.
    pub fn is_empty(&self) -> bool {
        self.ptr.is_null() || self.len == 0
    }

    /// Acessa a fatia de bytes de forma segura se o ponteiro for válido.
    ///
    /// # Safety
    /// O chamador deve garantir que o ponteiro é válido pelo tempo de vida da referência.
    pub unsafe fn as_slice(&self) -> &[u8] {
        if self.ptr.is_null() || self.len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(self.ptr, self.len)
        }
    }

    /// Reconstitui o `Vec<u8>` para que o Rust desalogue a memória com segurança.
    ///
    /// # Safety
    /// O chamador deve garantir que este buffer foi originado de um `Vec<u8>` do Rust e
    /// que `into_vec` só é chamado uma única vez.
    pub unsafe fn into_vec(self) -> Vec<u8> {
        if self.ptr.is_null() || self.cap == 0 {
            Vec::new()
        } else {
            Vec::from_raw_parts(self.ptr, self.len, self.cap)
        }
    }
}

/// Referência somente-leitura a uma fatia contínua de memória sem alocação adicional.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FfiSlice {
    pub ptr: *const u8,
    pub len: usize,
}

impl FfiSlice {
    pub fn new(slice: &[u8]) -> Self {
        Self {
            ptr: slice.as_ptr(),
            len: slice.len(),
        }
    }

    /// # Safety
    /// Ponteiro deve ser válido por pelo menos `self.len` bytes.
    pub unsafe fn as_slice(&self) -> &[u8] {
        if self.ptr.is_null() || self.len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(self.ptr, self.len)
        }
    }
}

/// Desaloca um buffer gerado pelo Rust.
/// Esta função DEVE ser chamada pelo consumidor externo (Android/Electron) após terminar
/// de ler os bytes de um evento ou resposta, evitando memory leaks.
#[no_mangle]
pub extern "C" fn p2p_ffi_free_buffer(buf: FfiByteBuffer) {
    if !buf.ptr.is_null() && buf.cap > 0 {
        unsafe {
            drop(buf.into_vec());
        }
    }
}

/// Permite que ambientes externos aloquem um buffer na heap do Rust.
#[no_mangle]
pub extern "C" fn p2p_ffi_alloc_buffer(size: usize) -> FfiByteBuffer {
    let vec = vec![0u8; size];
    FfiByteBuffer::from_vec(vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_byte_buffer_roundtrip() {
        let original = b"Hello Anarchord Shared Memory FFI!".to_vec();
        let expected = original.clone();
        let ffi_buf = FfiByteBuffer::from_vec(original);

        assert_eq!(ffi_buf.len, expected.len());
        unsafe {
            assert_eq!(ffi_buf.as_slice(), expected.as_slice());
            let recovered = ffi_buf.into_vec();
            assert_eq!(recovered, expected);
        }
    }

    #[test]
    fn test_free_empty_buffer_does_not_panic() {
        p2p_ffi_free_buffer(FfiByteBuffer::empty());
    }

    #[test]
    fn test_alloc_and_free_buffer() {
        let buf = p2p_ffi_alloc_buffer(1024);
        assert_eq!(buf.len, 1024);
        p2p_ffi_free_buffer(buf);
    }
}
