//! Sniffer e dissecador criptográfico de pacotes de aplicação (`wire.rs`).
//!
//! No nível de transporte do SO/Docker (`eth0`), todo o tráfego `libp2p` (TCP/Noise e QUIC/TLS 1.3)
//! é cifrado ponto-a-ponto entre pares vizinhos. Para que o `anarlab` e auditorias de segurança
//! possam inspecionar os pacotes da aplicação na forma mais crua — validando chaves públicas
//! Ed25519, chaves efêmeras X25519 (Forward Secrecy), nonces ChaCha20-Poly1305, ciphertexts,
//! bytes exatos assinados (`signing_bytes_hex`) e assinaturas digitais Ed25519 (`signature_hex`) —
//! este módulo disseca qualquer quadro bruto Gossipsub (`TX` ou `RX`) e grava em JSON Lines.

use crate::community;
use crate::dm::{
    DirectMessageEnvelope, DmWireMessage, EphemeralKeyOffer, MailboxMessage, ReceiptAck,
    StoredEnvelope,
};
use crate::wire::{self, Incoming};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

/// Converte uma fatia de bytes para string hexadecimal minúscula
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

/// Metadados criptográficos extraídos da forma crua do pacote
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct SniffedCrypto {
    /// Chave pública Ed25519 do remetente/autor (64 chars hex = 32 bytes)
    pub sender_pubkey: Option<String>,
    /// Chave pública Ed25519 do destinatário (64 chars hex = 32 bytes, em DMs e Mailbox)
    pub recipient_pubkey: Option<String>,
    /// Chave pública efêmera X25519 (64 chars hex = 32 bytes, para ECDH / Forward Secrecy)
    pub ephemeral_x25519_pubkey: Option<String>,
    /// Indica se o envelope de DM utilizou chave de sessão efêmera mútua (`true`) ou Sealed Box (`false`)
    pub uses_session_key: Option<bool>,
    /// ID determinístico do envelope (para `Mailbox.Store`, `Mailbox.Deliver` e `Mailbox.Ack`)
    pub envelope_id: Option<String>,
    /// Nonce AEAD ChaCha20-Poly1305 (24 chars hex = 12 bytes)
    pub nonce_hex: Option<String>,
    /// Ciphertext bruto em hexadecimal (prova que o texto em claro não trafega no fio)
    pub ciphertext_hex: Option<String>,
    /// Bytes exatos (com separador de domínio) sobre os quais a assinatura Ed25519 foi calculada
    pub signing_bytes_hex: Option<String>,
    /// Assinatura digital Ed25519 bruta (128 chars hex = 64 bytes)
    pub signature_hex: Option<String>,
    /// Resultado da verificação criptográfica independente da assinatura Ed25519 externa
    pub signature_valid: Option<bool>,
    /// Prévia de texto claro APENAS se o pacote não for cifrado no protocolo (ex.: Chat público do Lobby)
    pub cleartext_preview: Option<String>,
}

/// Registro completo de um pacote capturado pelo sniffer na fronteira do Gossipsub
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SniffedPacket {
    /// Timestamp UNIX em segundos
    pub timestamp: u64,
    /// Apelido do nó onde a captura ocorreu
    pub node: String,
    /// Direção do pacote no nó: `"TX"` (publicado) ou `"RX"` (recebido)
    pub direction: String,
    /// Tópico Gossipsub completo
    pub topic: String,
    /// PeerId de origem (presente em `"RX"` quando informado pelo Gossipsub)
    pub source_peer_id: Option<String>,
    /// Tamanho total do quadro bruto em bytes
    pub raw_len: usize,
    /// Quadro completo exatamente como trafegou no fio (`[versão][kind][corpo_postcard]` ou ciphertext MLS)
    pub raw_hex: String,
    /// Versão do cabeçalho `wire.rs` (primeiro byte quando não envolto em MLS)
    pub wire_version: Option<u8>,
    /// Byte numérico do `wire::Kind`
    pub wire_kind_byte: Option<u8>,
    /// Tipo decodificado do pacote (`"Chat"`, `"DirectMessage.KeyOffer"`, `"DirectMessage.Message"`, `"Mailbox.Store"`, etc.)
    pub kind: String,
    /// `true` se o tópico é um canal de conteúdo de servidor cifrado por MLS na camada externa
    pub mls_encrypted: bool,
    /// Campos criptográficos extraídos do pacote
    pub crypto: SniffedCrypto,
}

impl SniffedPacket {
    /// Disseca um quadro bruto `bytes` trafegado em `topic`.
    /// Se `mls_decrypted` for fornecido (quando o nó faz parte do grupo MLS e decifrou a camada externa),
    /// disseca também o pacote interno mantendo `raw_hex` como o pacote externo cifrado que passou no fio.
    pub fn dissect(
        timestamp: u64,
        node: &str,
        direction: &str,
        topic: &str,
        source_peer_id: Option<String>,
        raw_bytes: &[u8],
        mls_decrypted: Option<&[u8]>,
    ) -> Self {
        let is_mls_topic = community::parse_server_content_topic(topic).is_some();
        let raw_hex = hex_encode(raw_bytes);
        let raw_len = raw_bytes.len();

        let inspect_bytes = mls_decrypted.unwrap_or(raw_bytes);
        if is_mls_topic && mls_decrypted.is_none() {
            return Self {
                timestamp,
                node: node.to_string(),
                direction: direction.to_string(),
                topic: topic.to_string(),
                source_peer_id,
                raw_len,
                raw_hex: raw_hex.clone(),
                wire_version: None,
                wire_kind_byte: None,
                kind: "MlsCiphertext".to_string(),
                mls_encrypted: true,
                crypto: SniffedCrypto {
                    ciphertext_hex: Some(raw_hex),
                    ..Default::default()
                },
            };
        }

        let wire_version = inspect_bytes.first().copied();
        let wire_kind_byte = inspect_bytes.get(1).copied();

        match wire::decode(inspect_bytes) {
            Ok(incoming) => {
                let (kind, crypto) = dissect_incoming(incoming);
                Self {
                    timestamp,
                    node: node.to_string(),
                    direction: direction.to_string(),
                    topic: topic.to_string(),
                    source_peer_id,
                    raw_len,
                    raw_hex,
                    wire_version,
                    wire_kind_byte,
                    kind,
                    mls_encrypted: is_mls_topic,
                    crypto,
                }
            }
            Err(_) => Self {
                timestamp,
                node: node.to_string(),
                direction: direction.to_string(),
                topic: topic.to_string(),
                source_peer_id,
                raw_len,
                raw_hex,
                wire_version,
                wire_kind_byte,
                kind: "Unknown".to_string(),
                mls_encrypted: is_mls_topic,
                crypto: SniffedCrypto::default(),
            },
        }
    }

    /// Grava o pacote como uma linha JSON (JSONL) no arquivo indicado
    pub fn append_to_file(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            if let Ok(line) = serde_json::to_string(self) {
                let _ = writeln!(file, "{}", line);
            }
        }
    }
}

fn dissect_incoming(incoming: Incoming) -> (String, SniffedCrypto) {
    match incoming {
        Incoming::Chat(chat) => {
            let sig_bytes = crate::api::ChatMessage::signing_payload(
                &chat.channel_id,
                &chat.text,
                chat.timestamp,
            );
            let valid = chat.verify_signature();
            (
                "Chat".to_string(),
                SniffedCrypto {
                    sender_pubkey: Some(chat.author_pubkey),
                    signing_bytes_hex: Some(hex_encode(&sig_bytes)),
                    signature_hex: Some(hex_encode(&chat.signature)),
                    signature_valid: Some(valid),
                    cleartext_preview: Some(chat.text),
                    ..Default::default()
                },
            )
        }
        Incoming::DirectMessage(DmWireMessage::KeyOffer(offer)) => {
            let sig_bytes = EphemeralKeyOffer::signing_bytes(
                &offer.sender_pubkey,
                &offer.recipient_pubkey,
                &offer.ephemeral_pubkey,
                offer.timestamp,
            );
            let valid = offer.verify();
            (
                "DirectMessage.KeyOffer".to_string(),
                SniffedCrypto {
                    sender_pubkey: Some(offer.sender_pubkey),
                    recipient_pubkey: Some(offer.recipient_pubkey),
                    ephemeral_x25519_pubkey: Some(hex_encode(&offer.ephemeral_pubkey)),
                    signing_bytes_hex: Some(hex_encode(&sig_bytes)),
                    signature_hex: Some(hex_encode(&offer.signature)),
                    signature_valid: Some(valid),
                    ..Default::default()
                },
            )
        }
        Incoming::DirectMessage(DmWireMessage::KeyAdvertisement(ad)) => {
            let sig_bytes = crate::identity::SignedEncryptionKeyAdvertisement::signing_bytes(&ad.advertisement);
            let valid = ad.verify();
            (
                "DirectMessage.KeyAdvertisement".to_string(),
                SniffedCrypto {
                    sender_pubkey: Some(ad.advertisement.user_id),
                    ephemeral_x25519_pubkey: Some(ad.advertisement.encryption_public_key),
                    signing_bytes_hex: Some(hex_encode(&sig_bytes)),
                    signature_hex: Some(hex_encode(&ad.signature)),
                    signature_valid: Some(valid),
                    ..Default::default()
                },
            )
        }
        Incoming::DirectMessage(DmWireMessage::FriendRequest(req)) => {
            let sig_bytes = crate::dm::FriendRequest::signing_bytes(
                &req.sender_pubkey,
                &req.sender_nick,
                &req.recipient_pubkey,
                req.message.as_deref(),
                &req.encryption_advertisement,
                req.timestamp,
            );
            let valid = req.verify();
            (
                "DirectMessage.FriendRequest".to_string(),
                SniffedCrypto {
                    sender_pubkey: Some(req.sender_pubkey),
                    recipient_pubkey: Some(req.recipient_pubkey),
                    signing_bytes_hex: Some(hex_encode(&sig_bytes)),
                    signature_hex: Some(hex_encode(&req.signature)),
                    signature_valid: Some(valid),
                    ..Default::default()
                },
            )
        }
        Incoming::DirectMessage(DmWireMessage::FriendResponse(resp)) => {
            let adv_pub = resp.encryption_advertisement.as_ref().map(|a| a.advertisement.encryption_public_key.as_str());
            let adv_epoch = resp.encryption_advertisement.as_ref().map(|a| a.advertisement.epoch);
            let sig_bytes = crate::dm::FriendResponse::signing_bytes(
                &resp.sender_pubkey,
                &resp.sender_nick,
                &resp.recipient_pubkey,
                resp.accepted,
                adv_pub,
                adv_epoch,
                resp.timestamp,
            );
            let valid = resp.verify();
            (
                "DirectMessage.FriendResponse".to_string(),
                SniffedCrypto {
                    sender_pubkey: Some(resp.sender_pubkey),
                    recipient_pubkey: Some(resp.recipient_pubkey),
                    signing_bytes_hex: Some(hex_encode(&sig_bytes)),
                    signature_hex: Some(hex_encode(&resp.signature)),
                    signature_valid: Some(valid),
                    ..Default::default()
                },
            )
        }
        Incoming::DirectMessage(DmWireMessage::Message(env)) => {
            let sig_bytes = DirectMessageEnvelope::signing_bytes(
                &env.sender_pubkey,
                &env.recipient_pubkey,
                &env.ephemeral_pubkey,
                env.uses_session_key,
                &env.nonce,
                &env.ciphertext,
                env.timestamp,
            );
            let valid = env.verify_outer();
            (
                "DirectMessage.Message".to_string(),
                SniffedCrypto {
                    sender_pubkey: Some(env.sender_pubkey),
                    recipient_pubkey: Some(env.recipient_pubkey),
                    ephemeral_x25519_pubkey: Some(hex_encode(&env.ephemeral_pubkey)),
                    uses_session_key: Some(env.uses_session_key),
                    envelope_id: None,
                    nonce_hex: Some(hex_encode(&env.nonce)),
                    ciphertext_hex: Some(hex_encode(&env.ciphertext)),
                    signing_bytes_hex: Some(hex_encode(&sig_bytes)),
                    signature_hex: Some(hex_encode(&env.signature)),
                    signature_valid: Some(valid),
                    cleartext_preview: None,
                },
            )
        }
        Incoming::DirectMessage(DmWireMessage::BlockNotice(notice)) => (
            "DirectMessage.BlockNotice".to_string(),
            SniffedCrypto {
                sender_pubkey: Some(notice.sender_pubkey),
                recipient_pubkey: Some(notice.recipient_pubkey),
                ephemeral_x25519_pubkey: None,
                uses_session_key: None,
                envelope_id: None,
                nonce_hex: None,
                ciphertext_hex: None,
                signing_bytes_hex: None,
                signature_hex: None,
                signature_valid: None,
                cleartext_preview: Some(format!("dur={}s: {}", notice.duration_secs, notice.reason)),
            },
        ),
        Incoming::Mailbox(MailboxMessage::Store(env)) => (
            "Mailbox.Store".to_string(),
            dissect_stored_envelope(env),
        ),
        Incoming::Mailbox(MailboxMessage::Deliver(env)) => (
            "Mailbox.Deliver".to_string(),
            dissect_stored_envelope(env),
        ),
        Incoming::Mailbox(MailboxMessage::Ack(ack)) => {
            let sig_bytes = ReceiptAck::signing_bytes(
                &ack.envelope_id,
                &ack.recipient_pubkey,
                ack.timestamp,
            );
            let valid = ack.verify();
            (
                "Mailbox.Ack".to_string(),
                SniffedCrypto {
                    sender_pubkey: Some(ack.recipient_pubkey.clone()),
                    recipient_pubkey: Some(ack.recipient_pubkey),
                    envelope_id: Some(ack.envelope_id),
                    signing_bytes_hex: Some(hex_encode(&sig_bytes)),
                    signature_hex: Some(hex_encode(&ack.signature)),
                    signature_valid: Some(valid),
                    ..Default::default()
                },
            )
        }
        Incoming::Mailbox(MailboxMessage::KeyAdvertisement(ad)) => {
            let sig_bytes = crate::identity::SignedEncryptionKeyAdvertisement::signing_bytes(&ad.advertisement);
            let valid = ad.verify();
            (
                "Mailbox.KeyAdvertisement".to_string(),
                SniffedCrypto {
                    sender_pubkey: Some(ad.advertisement.user_id),
                    ephemeral_x25519_pubkey: Some(ad.advertisement.encryption_public_key),
                    signing_bytes_hex: Some(hex_encode(&sig_bytes)),
                    signature_hex: Some(hex_encode(&ad.signature)),
                    signature_valid: Some(valid),
                    ..Default::default()
                },
            )
        }
        Incoming::Voice(pkt) => (
            "Voice".to_string(),
            SniffedCrypto {
                sender_pubkey: Some(pkt.sender_pubkey),
                ..Default::default()
            },
        ),
        Incoming::Swarm(swarm) => {
            let sender = match &swarm {
                crate::files::SwarmMessage::Offer(o) => Some(o.publisher.clone()),
                _ => None,
            };
            (
                "Swarm".to_string(),
                SniffedCrypto {
                    sender_pubkey: sender,
                    ..Default::default()
                },
            )
        }
        Incoming::ScreenFrame(pkt) => (
            "ScreenFrame".to_string(),
            SniffedCrypto {
                sender_pubkey: Some(pkt.sender_pubkey),
                ..Default::default()
            },
        ),
        Incoming::ScreenAnnounce(ann) => (
            "ScreenAnnounce".to_string(),
            SniffedCrypto {
                sender_pubkey: Some(ann.sender_pubkey),
                ..Default::default()
            },
        ),
        Incoming::Server(srv) => {
            let sub = match srv {
                crate::community::ServerMessage::Events { .. } => "Server.Events",
                crate::community::ServerMessage::Inventory { .. } => "Server.Inventory",
                crate::community::ServerMessage::KeyTransferOffer { .. } => "Server.KeyTransferOffer",
                crate::community::ServerMessage::KeyTransferAccept { .. } => "Server.KeyTransferAccept",
                crate::community::ServerMessage::KeyPackage { .. } => "Server.KeyPackage",
                crate::community::ServerMessage::Commit { .. } => "Server.Commit",
                crate::community::ServerMessage::Welcome { .. } => "Server.Welcome",
                crate::community::ServerMessage::GroupAnnounce { .. } => "Server.GroupAnnounce",
                crate::community::ServerMessage::PassportOffer { .. } => "Server.PassportOffer",
                crate::community::ServerMessage::FlattenRequest { .. } => "Server.FlattenRequest",
                crate::community::ServerMessage::AccessRequest { .. } => "Server.AccessRequest",
                crate::community::ServerMessage::AccessPolicy { .. } => "Server.AccessPolicy",
                crate::community::ServerMessage::GroupLeave { .. } => "Server.GroupLeave",
                crate::community::ServerMessage::StampRequest { .. } => "Server.StampRequest",
                crate::community::ServerMessage::Stamp { .. } => "Server.Stamp",
            };
            (sub.to_string(), SniffedCrypto::default())
        }
        Incoming::Peers(_) => ("Peers".to_string(), SniffedCrypto::default()),
        Incoming::Unknown { version, kind, .. } => (
            format!("Unknown(v{},kind={})", version, kind),
            SniffedCrypto::default(),
        ),
    }
}

fn dissect_stored_envelope(env: StoredEnvelope) -> SniffedCrypto {
    let sig_bytes = StoredEnvelope::outer_signing_bytes(
        &env.envelope_id,
        &env.sender_pubkey,
        &env.recipient_pubkey,
        &env.ephemeral_pubkey,
        &env.nonce,
        &env.ciphertext,
        env.created_at,
        env.suggested_ttl,
    );
    let valid = env.verify_outer();
    SniffedCrypto {
        sender_pubkey: Some(env.sender_pubkey),
        recipient_pubkey: Some(env.recipient_pubkey),
        ephemeral_x25519_pubkey: Some(hex_encode(&env.ephemeral_pubkey)),
        uses_session_key: Some(false),
        envelope_id: Some(env.envelope_id),
        nonce_hex: Some(hex_encode(&env.nonce)),
        ciphertext_hex: Some(hex_encode(&env.ciphertext)),
        signing_bytes_hex: Some(hex_encode(&sig_bytes)),
        signature_hex: Some(hex_encode(&env.outer_signature)),
        signature_valid: Some(valid),
        cleartext_preview: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ChatMessage;
    use crate::dm::{dm_topic, DmPeerSession, MAILBOX_TOPIC};
    use crate::identity::{verify_signature_hex, UserIdentity};

    fn hex_decode(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_sniffer_dissects_dm_key_offer_and_message_without_leaking_plaintext() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let carol = UserIdentity::generate_with_nick("Carol");
        let topic = dm_topic(&alice.public_key_hex(), &carol.public_key_hex());

        let mut alice_sess = DmPeerSession::new();
        let carol_sess = DmPeerSession::new();
        alice_sess.apply_peer_offer(carol_sess.my_ephemeral_public);

        // 1. KeyOffer
        let offer = EphemeralKeyOffer::new_signed(
            &alice,
            &carol.public_key_hex(),
            alice_sess.my_ephemeral_public,
            1_700_000_000,
        );
        let offer_wire = wire::encode(&DmWireMessage::KeyOffer(offer));
        let pkt_offer = SniffedPacket::dissect(
            1_700_000_000,
            "Alice",
            "TX",
            &topic,
            None,
            &offer_wire,
            None,
        );
        assert_eq!(pkt_offer.kind, "DirectMessage.KeyOffer");
        assert_eq!(pkt_offer.wire_version, Some(wire::VERSION));
        assert_eq!(pkt_offer.crypto.sender_pubkey.as_deref(), Some(alice.public_key_hex().as_str()));
        assert_eq!(pkt_offer.crypto.recipient_pubkey.as_deref(), Some(carol.public_key_hex().as_str()));
        assert_eq!(pkt_offer.crypto.ephemeral_x25519_pubkey.as_ref().unwrap().len(), 64);
        assert_eq!(pkt_offer.crypto.signature_hex.as_ref().unwrap().len(), 128);
        assert_eq!(pkt_offer.crypto.signature_valid, Some(true));

        // Verifica que os bytes brutos reportados pelo sniffer validam matematicamente com a chave pública Ed25519
        let sig_bytes = hex_decode(pkt_offer.crypto.signing_bytes_hex.as_ref().unwrap());
        let sig = hex_decode(pkt_offer.crypto.signature_hex.as_ref().unwrap());
        assert!(verify_signature_hex(
            pkt_offer.crypto.sender_pubkey.as_ref().unwrap(),
            &sig_bytes,
            &sig
        ));

        // 2. DirectMessageEnvelope (E2EE com chave de sessão efêmera)
        let secret_text = "segredo_ultra_confidencial_alice_para_carol_998877";
        let env = DirectMessageEnvelope::seal(
            &alice,
            &carol.public_key_hex(),
            secret_text,
            1_700_000_001,
            alice_sess.shared_session_key.as_ref(),
        )
        .unwrap();
        let dm_wire = wire::encode(&DmWireMessage::Message(env));
        let pkt_dm = SniffedPacket::dissect(
            1_700_000_001,
            "Alice",
            "TX",
            &topic,
            None,
            &dm_wire,
            None,
        );
        assert_eq!(pkt_dm.kind, "DirectMessage.Message");
        assert_eq!(pkt_dm.crypto.uses_session_key, Some(true));
        assert_eq!(pkt_dm.crypto.nonce_hex.as_ref().unwrap().len(), 24); // 12 bytes
        assert_eq!(pkt_dm.crypto.signature_valid, Some(true));
        assert!(pkt_dm.crypto.cleartext_preview.is_none());

        // Prova que o texto em claro NÃO aparece em lugar nenhum do quadro bruto nem em hex!
        let secret_hex = hex_encode(secret_text.as_bytes());
        assert!(!pkt_dm.raw_hex.contains(&secret_hex));
        assert!(
            !pkt_dm
                .crypto
                .ciphertext_hex
                .as_ref()
                .unwrap()
                .contains(&secret_hex)
        );

        // 3. Adulterar 1 bit no pacote bruto invalida a assinatura detectada pelo sniffer
        let mut tampered = dm_wire.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let pkt_tampered = SniffedPacket::dissect(
            1_700_000_001,
            "Eve",
            "RX",
            &topic,
            None,
            &tampered,
            None,
        );
        assert_eq!(pkt_tampered.crypto.signature_valid, Some(false));
    }

    #[test]
    fn test_sniffer_dissects_mailbox_store_deliver_and_ack() {
        let alice = UserIdentity::generate_with_nick("Alice");
        let carol = UserIdentity::generate_with_nick("Carol");
        let secret_offline = "mensagem_offline_guardada_por_bob_424242";

        let stored = StoredEnvelope::create_signed_and_sealed(
            &alice,
            &carol.public_key_hex(),
            secret_offline,
            1_700_000_010,
            Some(3600),
        )
        .unwrap();
        let env_id = stored.envelope_id.clone();

        let store_wire = wire::encode(&MailboxMessage::Store(stored.clone()));
        let pkt_store = SniffedPacket::dissect(
            1_700_000_010,
            "Bob",
            "RX",
            MAILBOX_TOPIC,
            None,
            &store_wire,
            None,
        );
        assert_eq!(pkt_store.kind, "Mailbox.Store");
        assert_eq!(pkt_store.crypto.envelope_id.as_deref(), Some(env_id.as_str()));
        assert_eq!(pkt_store.crypto.sender_pubkey.as_deref(), Some(alice.public_key_hex().as_str()));
        assert_eq!(pkt_store.crypto.recipient_pubkey.as_deref(), Some(carol.public_key_hex().as_str()));
        assert_eq!(pkt_store.crypto.signature_valid, Some(true));
        assert!(!pkt_store.raw_hex.contains(&hex_encode(secret_offline.as_bytes())));

        let deliver_wire = wire::encode(&MailboxMessage::Deliver(stored));
        let pkt_deliver = SniffedPacket::dissect(
            1_700_000_020,
            "Bob",
            "TX",
            MAILBOX_TOPIC,
            None,
            &deliver_wire,
            None,
        );
        assert_eq!(pkt_deliver.kind, "Mailbox.Deliver");
        assert_eq!(pkt_deliver.crypto.signature_valid, Some(true));

        let ack = ReceiptAck::new_signed(&carol, &env_id, 1_700_000_025);
        let ack_wire = wire::encode(&MailboxMessage::Ack(ack));
        let pkt_ack = SniffedPacket::dissect(
            1_700_000_025,
            "Carol",
            "TX",
            MAILBOX_TOPIC,
            None,
            &ack_wire,
            None,
        );
        assert_eq!(pkt_ack.kind, "Mailbox.Ack");
        assert_eq!(pkt_ack.crypto.envelope_id.as_deref(), Some(env_id.as_str()));
        assert_eq!(pkt_ack.crypto.sender_pubkey.as_deref(), Some(carol.public_key_hex().as_str()));
        assert_eq!(pkt_ack.crypto.signature_valid, Some(true));

        let chat = ChatMessage::new_signed(&alice, "geral", "olá lobby", 1_700_000_030);
        let chat_wire = wire::encode(&chat);
        let pkt_chat = SniffedPacket::dissect(
            1_700_000_030,
            "Alice",
            "TX",
            "p2p-anarchord/channel/geral",
            None,
            &chat_wire,
            None,
        );
        assert_eq!(pkt_chat.kind, "Chat");
        assert_eq!(pkt_chat.crypto.signature_valid, Some(true));
        assert_eq!(pkt_chat.crypto.cleartext_preview.as_deref(), Some("olá lobby"));
    }
}
