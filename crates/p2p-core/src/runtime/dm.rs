//! Runtime de Mensagens Diretas (DM 1:1 E2EE), Sessões Efêmeras e Mailbox Offline.

use super::{CoreError, CoreEvent, Runtime};
use crate::community::{format_duration, short_id};
use crate::config::NodeConfig;
use crate::dm::{
    dm_topic, BlockNotice, DirectMessageEnvelope, DmFirewall, DmFirewallVerdict, DmPeerSession,
    DmWireMessage, EphemeralKeyOffer, FriendRequest, FriendResponse, MailboxMessage, MailboxStore,
    ReceiptAck, StoredEnvelope, FRIEND_REQUEST_MAILBOX_TOPIC, FRIEND_RESPONSE_MAILBOX_TOPIC,
    MAILBOX_TOPIC,
};
use crate::identity::FriendState;
use crate::wire;
use libp2p::gossipsub::IdentTopic;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

pub(super) struct DmState {
    pub node_config: NodeConfig,
    pub config_path: Option<PathBuf>,
    pub mailbox: MailboxStore,
    /// Sessões efêmeras X25519 por chave pública (hex lowercase) do par
    pub sessions: HashMap<String, DmPeerSession>,
    /// Tópicos de DM em que já estamos inscritos
    pub subscribed_topics: HashSet<String>,
    /// Se o usuário está com uma conversa DM aberta como canal ativo: pubkey (hex lowercase) do amigo
    pub active_dm_peer: Option<String>,
    /// Firewall de aplicação local para DMs (políticas diferenciadas para Amigos vs Desconhecidos)
    pub firewall: DmFirewall,
    /// Cooldowns temporários impostos por outros pares contra nós (pubkey -> unblock_timestamp_secs) (Issue #73)
    pub peer_cooldowns: HashMap<String, u64>,
}

impl DmState {
    pub fn new(config_path: Option<PathBuf>, mailbox_file: Option<PathBuf>, now: u64) -> Self {
        let node_config = NodeConfig::load_or_default(config_path.as_deref()).unwrap_or_default();
        let mailbox = MailboxStore::load(mailbox_file, now);
        Self {
            node_config,
            config_path,
            mailbox,
            sessions: HashMap::new(),
            subscribed_topics: HashSet::new(),
            active_dm_peer: None,
            firewall: DmFirewall::new(),
            peer_cooldowns: HashMap::new(),
        }
    }

    pub fn is_under_cooldown(&self, peer_pubkey: &str, now: u64) -> Option<u64> {
        let clean = peer_pubkey.trim().to_lowercase();
        self.peer_cooldowns.get(&clean).copied().filter(|&until| until > now)
    }

    pub fn set_peer_cooldown(&mut self, peer_pubkey: &str, blocked_until: u64) {
        let clean = peer_pubkey.trim().to_lowercase();
        self.peer_cooldowns.insert(clean, blocked_until);
    }

    pub fn remove_peer_cooldown(&mut self, peer_pubkey: &str) -> Option<u64> {
        let clean = peer_pubkey.trim().to_lowercase();
        self.peer_cooldowns.remove(&clean)
    }
}

impl Runtime {
    /// Inscreve no tópico de Mailbox Offline e nos tópicos mútuos de DM de todos os amigos
    pub(super) fn init_dm_and_mailbox(&mut self) {
        let _ = self
            .node
            .swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&IdentTopic::new(MAILBOX_TOPIC));
        let friend_pks: Vec<String> = self
            .identity
            .get_friends()
            .iter()
            .map(|f| f.public_key.clone())
            .collect();
        for pk in friend_pks {
            self.subscribe_dm_with(&pk);
        }
        // Emite a lista inicial de amigos para a interface
        self.list_friends();
    }

    /// Garante que estamos inscritos no tópico determinístico de DM com `peer_pubkey`
    pub(super) fn subscribe_dm_with(&mut self, peer_pubkey: &str) -> String {
        let my_pk = self.my_pubkey();
        let topic_str = dm_topic(&my_pk, peer_pubkey);
        if self.dm.subscribed_topics.insert(topic_str.clone()) {
            let _ = self
                .node
                .swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&IdentTopic::new(&topic_str));
        }
        let clean_pk = peer_pubkey.trim().to_lowercase();
        self.dm.sessions.entry(clean_pk).or_default();
        topic_str
    }

    /// Publica nossa oferta de chave efêmera X25519 assinada para o par (Forward Secrecy)
    pub(super) fn send_ephemeral_key_offer(&mut self, peer_pubkey: &str) {
        let clean_pk = peer_pubkey.trim().to_lowercase();
        let topic_str = self.subscribe_dm_with(&clean_pk);
        let session = self.dm.sessions.entry(clean_pk.clone()).or_default();
        let offer = EphemeralKeyOffer::new_signed(
            &self.identity,
            &clean_pk,
            session.my_ephemeral_public,
            super::now_secs(),
        );
        let msg = DmWireMessage::KeyOffer(offer);
        let bytes = wire::encode(&msg);
        let _ = self.publish_gossip(IdentTopic::new(topic_str), bytes);
        self.send_key_advertisement(&clean_pk);
    }

    /// Publica nosso anúncio assinado de chave de criptografia X25519 no tópico mútuo de DM
    pub(super) fn send_key_advertisement(&mut self, peer_pubkey: &str) {
        let clean_pk = peer_pubkey.trim().to_lowercase();
        let topic_str = self.subscribe_dm_with(&clean_pk);
        let ad = self.identity.create_key_advertisement();
        let msg = DmWireMessage::KeyAdvertisement(ad);
        let bytes = wire::encode(&msg);
        let _ = self.publish_gossip(IdentTopic::new(topic_str), bytes);
    }

    /// Resolve um alvo (pubkey de 64 chars, apelido de amigo ou nick de par conectado) para `(pubkey_hex, display_name)`
    pub(super) fn resolve_dm_target(&self, target: &str) -> Option<(String, String)> {
        let trimmed = target.trim().trim_start_matches('@');
        if trimmed.is_empty() {
            return None;
        }
        // 1. Amigo pelo apelido (alias) ou pela pubkey
        if let Some(friend) = self.identity.get_friends().iter().find(|f| {
            f.alias.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(trimmed))
                || f.public_key.eq_ignore_ascii_case(trimmed)
                || (trimmed.len() >= 6 && f.public_key.starts_with(&trimmed.to_lowercase()))
        }) {
            let pk = friend.public_key.to_lowercase();
            let name = friend
                .alias
                .clone()
                .unwrap_or_else(|| self.nick_or_short(&pk));
            return Some((pk, name));
        }

        // 2. Par conectado pelo nick ou prefixo
        if let Some(peer_id) = self.find_peer(trimmed) {
            if let Some((nick, pk)) = self.peer_metadata.get(&peer_id) {
                return Some((pk.to_lowercase(), nick.clone()));
            }
        }

        // 3. Pubkey completa de 64 chars hex (mesmo sem estar nos amigos ainda)
        if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let pk = trimmed.to_lowercase();
            let name = self.nick_or_short(&pk);
            return Some((pk, name));
        }

        None
    }

    /// Nome amigável de um contato/par (alias de amigo > nick conectado > short_id)
    pub(super) fn friendly_name(&self, pubkey: &str) -> String {
        if let Some(friend) = self
            .identity
            .get_friends()
            .iter()
            .find(|f| f.public_key.eq_ignore_ascii_case(pubkey))
        {
            if let Some(alias) = &friend.alias {
                return alias.clone();
            }
        }
        self.nick_or_short(pubkey)
    }

    /// Verifica se uma pubkey está conectada e identificada agora no Swarm
    pub(super) fn is_pubkey_online(&self, pubkey: &str) -> bool {
        self.peer_metadata.iter().any(|(peer, (_, pk))| {
            pk.eq_ignore_ascii_case(pubkey) && self.connected_peers.contains(peer)
        })
    }

    /// Abre uma conversa privada de DM como canal ativo na TUI (`@Nome`)
    pub(super) fn open_dm(&mut self, target: &str) {
        let Some((peer_pk, peer_name)) = self.resolve_dm_target(target) else {
            return self.error(CoreError::PeerNotFound(target.to_string()));
        };
        if peer_pk.eq_ignore_ascii_case(&self.my_pubkey()) {
            return self.error(CoreError::Friend("Você não pode abrir uma DM consigo mesmo".into()));
        }
        self.subscribe_dm_with(&peer_pk);
        self.send_ephemeral_key_offer(&peer_pk);
        self.dm.active_dm_peer = Some(peer_pk.clone());

        let dm_channel_label = format!("@{}", peer_name);
        self.emit(CoreEvent::DmOpened {
            peer_pubkey: peer_pk,
            peer_name,
            channel: dm_channel_label,
        });
    }

    /// Envia uma DM (online via tópico mútuo E2EE ou offline via guardiões amigos se o destinatário não estiver conectado)
    pub(super) fn send_dm(&mut self, target: &str, text: &str, suggested_ttl: Option<u64>) {
        let Some((peer_pk, peer_name)) = self.resolve_dm_target(target) else {
            return self.error(CoreError::PeerNotFound(target.to_string()));
        };
        if peer_pk.eq_ignore_ascii_case(&self.my_pubkey()) {
            return self.error(CoreError::Friend("Você não pode enviar DM para si mesmo".into()));
        }
        let now = super::now_secs();
        let now_ms = super::now_millis();

        // Issue #73: Se estiver sob cooldown com o destinatário, retém na outbox local
        if let Some(until) = self.dm.is_under_cooldown(&peer_pk, now) {
            let remaining = until.saturating_sub(now);
            match StoredEnvelope::create_signed_and_sealed(
                &self.identity,
                &peer_pk,
                text,
                now_ms,
                suggested_ttl,
            ) {
                Ok(stored) => {
                    self.dm
                        .mailbox
                        .insert_own(stored, &self.dm.node_config, now);
                    let rem_fmt = format_duration(Some(remaining));
                    self.emit(CoreEvent::DirectMessage {
                        peer_pubkey: peer_pk,
                        peer_name,
                        author: "Sistema".to_string(),
                        author_pubkey: String::new(),
                        text: format!(
                            "⏳ Você está sob cooldown temporário com este par (restam {}). Sua mensagem foi retida na outbox e será enviada automaticamente após o término.",
                            rem_fmt
                        ),
                        timestamp: now_ms,
                        offline_delivery: false,
                    });
                }
                Err(e) => self.error(CoreError::Friend(e.to_string())),
            }
            return;
        }

        let topic_str = self.subscribe_dm_with(&peer_pk);
        let online = self.is_pubkey_online(&peer_pk);
        let subscribed_dm = self.is_peer_subscribed_to_dm(&peer_pk);

        if online && subscribed_dm {
            // Garante envio de oferta de chave efêmera e cifra a DM
            self.send_ephemeral_key_offer(&peer_pk);
            let session_key = self
                .dm
                .sessions
                .get(&peer_pk)
                .and_then(|s| s.shared_session_key);
            match DirectMessageEnvelope::seal(
                &self.identity,
                &peer_pk,
                text,
                now_ms,
                session_key.as_ref(),
            ) {
                Ok(envelope) => {
                    let wire_msg = DmWireMessage::Message(envelope);
                    let bytes = wire::encode(&wire_msg);
                    let _ = self.publish_gossip(IdentTopic::new(topic_str), bytes);
                    self.emit(CoreEvent::DirectMessage {
                        peer_pubkey: peer_pk,
                        peer_name,
                        author: self.nick.clone(),
                        author_pubkey: self.my_pubkey(),
                        text: text.to_string(),
                        timestamp: now_ms,
                        offline_delivery: false,
                    });
                }
                Err(e) => self.error(CoreError::Friend(e.to_string())),
            }
        } else if online {
            // O par está conectado no Swarm, mas ainda não completou o Gossipsub Subscribe do tópico mútuo de DM:
            // envia via MailboxMessage::Deliver no MAILBOX_TOPIC (no qual todo nó se inscreve no boot) e também no tópico de DM!
            self.send_ephemeral_key_offer(&peer_pk);
            let session_key = self
                .dm
                .sessions
                .get(&peer_pk)
                .and_then(|s| s.shared_session_key);
            match DirectMessageEnvelope::seal(
                &self.identity,
                &peer_pk,
                text,
                now_ms,
                session_key.as_ref(),
            ) {
                Ok(envelope) => {
                    let wire_msg = DmWireMessage::Message(envelope);
                    let bytes = wire::encode(&wire_msg);
                    let _ = self.publish_gossip(IdentTopic::new(topic_str), bytes);
                    if let Ok(stored) = StoredEnvelope::create_signed_and_sealed(
                        &self.identity,
                        &peer_pk,
                        text,
                        now_ms,
                        suggested_ttl,
                    ) {
                        let mb_msg = MailboxMessage::Deliver(stored);
                        let _ = self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), wire::encode(&mb_msg));
                    }
                    self.emit(CoreEvent::DirectMessage {
                        peer_pubkey: peer_pk,
                        peer_name,
                        author: self.nick.clone(),
                        author_pubkey: self.my_pubkey(),
                        text: text.to_string(),
                        timestamp: now_ms,
                        offline_delivery: false,
                    });
                }
                Err(e) => self.error(CoreError::Friend(e.to_string())),
            }
        } else {
            // Destinatário offline: cria StoredEnvelope Sign-then-Seal (timestamp em ms) e delega aos amigos guardiões
            match StoredEnvelope::create_signed_and_sealed(
                &self.identity,
                &peer_pk,
                text,
                now_ms,
                suggested_ttl,
            ) {
                Ok(stored) => {
                    let env_id = stored.envelope_id.clone();
                    self.broadcast_mailbox_store(stored, None);

                    self.emit(CoreEvent::DirectMessage {
                        peer_pubkey: peer_pk.clone(),
                        peer_name: peer_name.clone(),
                        author: self.nick.clone(),
                        author_pubkey: self.my_pubkey(),
                        text: text.to_string(),
                        timestamp: now_ms,
                        offline_delivery: true,
                    });
                    self.emit(CoreEvent::MailboxQueued {
                        recipient_pubkey: peer_pk,
                        recipient_name: peer_name,
                        envelope_id: env_id,
                        suggested_ttl,
                    });
                }
                Err(e) => self.error(CoreError::Friend(e.to_string())),
            }
        }
    }

    /// Recebe mensagem de tópico de DM (`DmWireMessage`)
    pub(super) fn on_dm_wire_message(&mut self, msg: DmWireMessage) {
        let my_pk = self.my_pubkey();
        match msg {
            DmWireMessage::KeyOffer(offer) => {
                if !offer.recipient_pubkey.eq_ignore_ascii_case(&my_pk)
                    || offer.sender_pubkey.eq_ignore_ascii_case(&my_pk)
                {
                    return;
                }
                if !offer.verify() {
                    tracing::debug!("Oferta de chave efêmera DM inválida descartada");
                    return;
                }
                let sender_pk = offer.sender_pubkey.to_lowercase();
                self.subscribe_dm_with(&sender_pk);
                let session = self.dm.sessions.entry(sender_pk.clone()).or_default();
                let had_peer_key = session.peer_ephemeral_public == Some(offer.ephemeral_pubkey);
                session.apply_peer_offer(offer.ephemeral_pubkey);
                // Responde com a nossa chave efêmera caso ainda não tenhamos respondido a esta chave
                if !had_peer_key {
                    self.send_ephemeral_key_offer(&sender_pk);
                }
            }
            DmWireMessage::KeyAdvertisement(ad) => {
                if ad.advertisement.user_id.eq_ignore_ascii_case(&my_pk) {
                    return;
                }
                if !ad.verify() {
                    tracing::debug!("Anúncio de chave de criptografia inválido descartado");
                    return;
                }
                let sender_pk = ad.advertisement.user_id.to_lowercase();
                if let Ok(updated) = self.identity.update_friend_encryption_key(&ad) {
                    if updated {
                        tracing::info!(peer = %sender_pk, epoch = ad.advertisement.epoch, "Chave de criptografia X25519 do amigo atualizada");
                        self.persist_identity();
                    }
                }
            }
            DmWireMessage::FriendRequest(req) => {
                if !req.recipient_pubkey.eq_ignore_ascii_case(&my_pk)
                    || req.sender_pubkey.eq_ignore_ascii_case(&my_pk)
                {
                    return;
                }
                if !req.verify() {
                    tracing::debug!("Pedido de amizade com assinatura inválida descartado");
                    return;
                }
                let sender_pk = req.sender_pubkey.to_lowercase();
                let now = super::now_secs();
                if self.dm.firewall.is_blocked(&sender_pk, now) {
                    tracing::debug!("Pedido de amizade de {} ignorado pelo firewall", short_id(&sender_pk));
                    return;
                }
                let current_state = self.identity.get_friend_state(&sender_pk);
                let sender_nick = req.sender_nick.clone();
                if current_state == Some(FriendState::Confirmed) {
                    let _ = self.identity.update_friend_encryption_key(&req.encryption_advertisement);
                    self.persist_identity();
                    return;
                }

                // Issue #73: Resolução de pedidos mútuos (Cross-Friend Requests) online
                if current_state == Some(FriendState::PendingOutgoing) {
                    let _ = self.identity.add_or_update_friend(&sender_pk, Some(&sender_nick), FriendState::Confirmed);
                    let _ = self.identity.update_friend_encryption_key(&req.encryption_advertisement);
                    self.persist_identity();
                    self.dm.firewall.unblock(&sender_pk);
                    self.subscribe_dm_with(&sender_pk);

                    // Responde com confirmação mútua online e offline via mailbox
                    let resp = FriendResponse::new_signed(&self.identity, &sender_pk, true, now);
                    let dm_top = IdentTopic::new(dm_topic(&my_pk, &sender_pk));
                    let _ = self.publish_gossip(dm_top, wire::encode(&DmWireMessage::FriendResponse(resp)));
                    if let Ok(stored) = StoredEnvelope::create_signed_and_sealed_topic(
                        &self.identity,
                        &sender_pk,
                        FRIEND_RESPONSE_MAILBOX_TOPIC,
                        "ACCEPTED",
                        super::now_millis(),
                        None,
                    ) {
                        self.broadcast_mailbox_store(stored, Some(FRIEND_RESPONSE_MAILBOX_TOPIC));
                    }

                    // Descarta da outbox nosso pedido de amizade que estava pendente
                    self.dm.mailbox.discard_outbox_for(&my_pk, &sender_pk, Some(FRIEND_REQUEST_MAILBOX_TOPIC));

                    let peer_name = self.friendly_name(&sender_pk);
                    self.emit(CoreEvent::FriendRequestAccepted {
                        pubkey: sender_pk.clone(),
                        peer_name,
                        offline_delivery: false,
                    });
                    self.emit(CoreEvent::FriendUpdated {
                        pubkey: sender_pk.clone(),
                        alias: self.identity.get_friend(&sender_pk).and_then(|f| f.alias.clone()),
                        removed: false,
                    });
                    self.list_friends();
                    self.on_peer_unblocked(&sender_pk);
                    if self.is_pubkey_online(&sender_pk) {
                        self.send_ephemeral_key_offer(&sender_pk);
                        self.delegate_pending_to_friend(&sender_pk);
                    }
                    return;
                }

                let _ = self.identity.add_or_update_friend(&sender_pk, Some(&sender_nick), FriendState::PendingIncoming);
                let _ = self.identity.update_friend_encryption_key(&req.encryption_advertisement);
                self.persist_identity();
                self.emit(CoreEvent::FriendRequestReceived {
                    pubkey: sender_pk,
                    sender_nick,
                    message: req.message,
                    offline_delivery: false,
                });
                self.list_friends();
            }
            DmWireMessage::FriendResponse(resp) => {
                if !resp.recipient_pubkey.eq_ignore_ascii_case(&my_pk)
                    || resp.sender_pubkey.eq_ignore_ascii_case(&my_pk)
                {
                    return;
                }
                if !resp.verify() {
                    tracing::debug!("Resposta de amizade com assinatura inválida descartada");
                    return;
                }
                let sender_pk = resp.sender_pubkey.to_lowercase();
                let peer_name = self.friendly_name(&sender_pk);
                if resp.accepted {
                    let _ = self.identity.add_or_update_friend(&sender_pk, None, FriendState::Confirmed);
                    if let Some(ref adv) = resp.encryption_advertisement {
                        let _ = self.identity.update_friend_encryption_key(adv);
                    }
                    self.persist_identity();
                    self.dm.firewall.unblock(&sender_pk);
                    self.subscribe_dm_with(&sender_pk);
                    self.on_peer_unblocked(&sender_pk);
                    self.dm.mailbox.discard_outbox_for(&my_pk, &sender_pk, Some(FRIEND_REQUEST_MAILBOX_TOPIC));
                    if self.is_pubkey_online(&sender_pk) {
                        self.send_ephemeral_key_offer(&sender_pk);
                        self.delegate_pending_to_friend(&sender_pk);
                    }
                    self.emit(CoreEvent::FriendRequestAccepted {
                        pubkey: sender_pk.clone(),
                        peer_name,
                        offline_delivery: false,
                    });
                    self.emit(CoreEvent::FriendUpdated {
                        pubkey: sender_pk,
                        alias: self.identity.get_friend(&resp.sender_pubkey).and_then(|f| f.alias.clone()),
                        removed: false,
                    });
                } else {
                    let _ = self.identity.set_friend_state(&sender_pk, FriendState::Rejected);
                    self.persist_identity();
                    self.emit(CoreEvent::FriendRequestRejected {
                        pubkey: sender_pk,
                        peer_name,
                        offline_delivery: false,
                    });
                }
                self.list_friends();
            }
            DmWireMessage::BlockNotice(notice) => {
                if !notice.recipient_pubkey.eq_ignore_ascii_case(&my_pk)
                    || notice.sender_pubkey.eq_ignore_ascii_case(&my_pk)
                {
                    return;
                }
                let sender_pk = notice.sender_pubkey.to_lowercase();
                let now = super::now_secs();
                if notice.blocked_until > now {
                    self.dm.set_peer_cooldown(&sender_pk, notice.blocked_until);
                    let rem = notice.blocked_until.saturating_sub(now);
                    let rem_fmt = format_duration(Some(rem));
                    let peer_name = self.friendly_name(&sender_pk);
                    self.emit(CoreEvent::DirectMessage {
                        peer_pubkey: sender_pk,
                        peer_name,
                        author: "Firewall Remoto".to_string(),
                        author_pubkey: notice.sender_pubkey,
                        text: format!(
                            "🛡️ Notificação de Firewall: Você foi temporariamente bloqueado por {} por {} (Motivo: {}). Mensagens futuras para este par serão retidas na outbox e enviadas automaticamente após o término.",
                            notice.sender_nick, rem_fmt, notice.reason
                        ),
                        timestamp: notice.timestamp,
                        offline_delivery: false,
                    });
                }
            }
            DmWireMessage::Message(envelope) => {
                if !envelope.recipient_pubkey.eq_ignore_ascii_case(&my_pk)
                    || envelope.sender_pubkey.eq_ignore_ascii_case(&my_pk)
                {
                    return;
                }
                let sender_pk = envelope.sender_pubkey.to_lowercase();
                let now = super::now_secs();
                let is_my_friend =
                    self.identity.get_friend_state(&sender_pk) == Some(FriendState::Confirmed);
                let session_key = self
                    .dm
                    .sessions
                    .get(&sender_pk)
                    .and_then(|s| s.shared_session_key);
                let opened = envelope
                    .open(&self.identity, session_key.as_ref())
                    .or_else(|_| envelope.open(&self.identity, None));
                match opened {
                    Ok(payload) => {
                        let peer_name = self
                            .identity
                            .get_friends()
                            .iter()
                            .find(|f| f.public_key.eq_ignore_ascii_case(&sender_pk))
                            .and_then(|f| f.alias.clone())
                            .unwrap_or_else(|| payload.sender_nick.clone());

                        // Verifica no Firewall de DMs (política assimétrica: Carol decide se Alice é amiga DELA)
                        match self.dm.firewall.check_incoming_dm(
                            &sender_pk,
                            is_my_friend,
                            payload.text.len(),
                            false,
                            &self.dm.node_config.dm,
                            now,
                        ) {
                            DmFirewallVerdict::Allowed => {
                                if let Some((invite, maybe_passport)) = super::parse_invite_details(&payload.text) {
                                    if let Some(passport) = maybe_passport {
                                        self.accept_invite_passport(&invite, &passport);
                                    }
                                    let known = self.servers.get(&invite).is_some();
                                    self.emit(CoreEvent::InviteReceived {
                                        from: payload.sender_nick.clone(),
                                        server_id: invite.clone(),
                                        known,
                                    });
                                    self.last_invite = Some(invite);
                                }
                                self.emit(CoreEvent::DirectMessage {
                                    peer_pubkey: sender_pk,
                                    peer_name,
                                    author: payload.sender_nick,
                                    author_pubkey: payload.sender_pubkey,
                                    text: payload.text,
                                    timestamp: payload.timestamp,
                                    offline_delivery: false,
                                });
                            }
                            DmFirewallVerdict::DroppedSilently { .. } => {
                                tracing::debug!("DM de {} descartada silenciosamente pelo firewall", short_id(&sender_pk));
                            }
                            DmFirewallVerdict::NewlyBlocked {
                                reason,
                                duration_secs,
                                blocked_until,
                                offense_level,
                                send_courtesy,
                            } => {
                                self.emit(CoreEvent::PeerBlocked {
                                    pubkey: sender_pk.clone(),
                                    peer_name,
                                    is_friend: is_my_friend,
                                    reason: reason.clone(),
                                    duration_secs,
                                    blocked_until,
                                    offense_level,
                                    courtesy_sent: send_courtesy,
                                });
                                if send_courtesy {
                                    self.send_courtesy_block_notice(&sender_pk, &reason, duration_secs, now);
                                }
                                if let Some(pid) = crate::api::peer_id_from_pubkey_hex(&sender_pk) {
                                    self.node.swarm.behaviour_mut().gossipsub.blacklist_peer(&pid);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("DM E2EE descartada de {}: {}", short_id(&sender_pk), e);
                    }
                }
            }
        }
    }

    /// Recebe mensagem do protocolo de Mailbox Offline (`MailboxMessage`)
    pub(super) fn on_mailbox_message(&mut self, msg: MailboxMessage) {
        let my_pk = self.my_pubkey();
        let now = super::now_secs();
        match msg {
            MailboxMessage::Store(envelope) => {
                // Se já sabemos que este envelope foi entregue (temos o ACK assinado), avisamos na malha para o remetente/guardião limpar!
                if let Some(ack) = self.dm.mailbox.get_ack(&envelope.envelope_id) {
                    self.publish_mailbox_ack(ack);
                    return;
                }
                // Se o envelope for para mim mesmo (eu estava online quando foi anunciado), recebo na hora!
                if envelope.recipient_pubkey.eq_ignore_ascii_case(&my_pk) {
                    self.receive_sealed_envelope(envelope, now);
                    return;
                }
                if envelope.sender_pubkey.eq_ignore_ascii_case(&my_pk) {
                    return;
                }
                // Verifica se o remetente (Alice) está na nossa lista de amigos
                let is_friend = self
                    .identity
                    .get_friends()
                    .iter()
                    .any(|f| f.public_key.eq_ignore_ascii_case(&envelope.sender_pubkey));
                let sender_name = self.friendly_name(&envelope.sender_pubkey);
                let recipient_short = short_id(&envelope.recipient_pubkey).to_string();
                let env_id = envelope.envelope_id.clone();
                let recipient_pk = envelope.recipient_pubkey.clone();
                let already_known = self.dm.mailbox.has_envelope_or_ack(&env_id);

                if let Ok(effective_ttl) =
                    self.dm
                        .mailbox
                        .store_for_friend(envelope, is_friend, &self.dm.node_config, now)
                {
                    if !already_known {
                        self.emit(CoreEvent::MailboxStoredForFriend {
                            sender_name,
                            recipient_short,
                            envelope_id: env_id,
                            effective_ttl_secs: effective_ttl,
                        });
                    }
                    // Se o destinatário já estiver conectado a nós agora, despacha imediatamente
                    if self.is_pubkey_online(&recipient_pk) {
                        self.deliver_pending_for(&recipient_pk);
                    }
                }
            }
            MailboxMessage::Deliver(envelope) => {
                if let Some(ack) = self.dm.mailbox.get_ack(&envelope.envelope_id) {
                    self.publish_mailbox_ack(ack);
                    return;
                }
                if envelope.recipient_pubkey.eq_ignore_ascii_case(&my_pk) {
                    self.receive_sealed_envelope(envelope, now);
                }
            }
            MailboxMessage::Ack(ack) => {
                if self.dm.mailbox.apply_ack(&ack) {
                    tracing::debug!("Envelope {} removido da mailbox após ACK", ack.envelope_id);
                }
            }
            MailboxMessage::KeyAdvertisement(ad) => {
                if ad.advertisement.user_id.eq_ignore_ascii_case(&my_pk) {
                    return;
                }
                if !ad.verify() {
                    tracing::debug!("Anúncio de chave de criptografia recebido via Mailbox inválido");
                    return;
                }
                let sender_pk = ad.advertisement.user_id.to_lowercase();
                if let Ok(updated) = self.identity.update_friend_encryption_key(&ad) {
                    if updated {
                        tracing::info!(peer = %sender_pk, epoch = ad.advertisement.epoch, "Chave de criptografia atualizada via rede de guardiões da Mailbox");
                        self.persist_identity();
                    }
                }
            }
        }
    }

    fn receive_sealed_envelope(&mut self, envelope: StoredEnvelope, now: u64) {
        let my_pk = self.my_pubkey();
        let ack = self
            .dm
            .mailbox
            .get_ack(&envelope.envelope_id)
            .unwrap_or_else(|| ReceiptAck::new_signed(&self.identity, &envelope.envelope_id, now));
        if !self.dm.mailbox.mark_delivered_to_me(&envelope.envelope_id, ack.clone()) {
            // Envelope já foi entregue antes (mesmo em sessão anterior!); apenas reenvia o ACK para limpar o remetente/guardião atrasado
            self.publish_mailbox_ack(ack);
            return;
        }

        match envelope.unseal_and_verify(&self.identity) {
            Ok(payload) => {
                if payload.topic == FRIEND_REQUEST_MAILBOX_TOPIC {
                    let sender_pk = payload.sender_pubkey.to_lowercase();
                    if !self.dm.firewall.is_blocked(&sender_pk, now) {
                        let current_state = self.identity.get_friend_state(&sender_pk);
                        if current_state == Some(FriendState::PendingOutgoing) {
                            // Issue #73: Resolução de pedidos mútuos via Mailbox offline
                            let _ = self.identity.add_or_update_friend(&sender_pk, Some(&payload.sender_nick), FriendState::Confirmed);
                            self.persist_identity();
                            self.dm.firewall.unblock(&sender_pk);
                            self.subscribe_dm_with(&sender_pk);

                            let resp = FriendResponse::new_signed(&self.identity, &sender_pk, true, now);
                            let dm_top = IdentTopic::new(dm_topic(&my_pk, &sender_pk));
                            let _ = self.publish_gossip(dm_top, wire::encode(&DmWireMessage::FriendResponse(resp)));
                            if let Ok(stored) = StoredEnvelope::create_signed_and_sealed_topic(
                                &self.identity,
                                &sender_pk,
                                FRIEND_RESPONSE_MAILBOX_TOPIC,
                                "ACCEPTED",
                                super::now_millis(),
                                None,
                            ) {
                                self.broadcast_mailbox_store(stored, Some(FRIEND_RESPONSE_MAILBOX_TOPIC));
                            }

                            self.dm.mailbox.discard_outbox_for(&my_pk, &sender_pk, Some(FRIEND_REQUEST_MAILBOX_TOPIC));
                            let peer_name = self.friendly_name(&sender_pk);
                            self.emit(CoreEvent::FriendRequestAccepted {
                                pubkey: sender_pk.clone(),
                                peer_name,
                                offline_delivery: true,
                            });
                            self.emit(CoreEvent::FriendUpdated {
                                pubkey: sender_pk.clone(),
                                alias: self.identity.get_friend(&sender_pk).and_then(|f| f.alias.clone()),
                                removed: false,
                            });
                            self.list_friends();
                            self.on_peer_unblocked(&sender_pk);
                            if self.is_pubkey_online(&sender_pk) {
                                self.send_ephemeral_key_offer(&sender_pk);
                                self.delegate_pending_to_friend(&sender_pk);
                            }
                        } else if current_state != Some(FriendState::Confirmed) {
                            let _ = self.identity.add_or_update_friend(&sender_pk, Some(&payload.sender_nick), FriendState::PendingIncoming);
                            self.persist_identity();
                            let msg = if payload.text.is_empty() { None } else { Some(payload.text) };
                            self.emit(CoreEvent::FriendRequestReceived {
                                pubkey: sender_pk,
                                sender_nick: payload.sender_nick,
                                message: msg,
                                offline_delivery: true,
                            });
                            self.list_friends();
                        }
                    }
                    self.publish_mailbox_ack(ack);
                    return;
                }

                if payload.topic == FRIEND_RESPONSE_MAILBOX_TOPIC {
                    let sender_pk = payload.sender_pubkey.to_lowercase();
                    let peer_name = self.friendly_name(&sender_pk);
                    if payload.text.trim().eq_ignore_ascii_case("ACCEPTED") {
                        let _ = self.identity.set_friend_state(&sender_pk, FriendState::Confirmed);
                        self.persist_identity();
                        self.dm.firewall.unblock(&sender_pk);
                        self.subscribe_dm_with(&sender_pk);
                        self.on_peer_unblocked(&sender_pk);
                        self.dm.mailbox.discard_outbox_for(&my_pk, &sender_pk, Some(FRIEND_REQUEST_MAILBOX_TOPIC));
                        if self.is_pubkey_online(&sender_pk) {
                            self.send_ephemeral_key_offer(&sender_pk);
                            self.delegate_pending_to_friend(&sender_pk);
                        }
                        self.emit(CoreEvent::FriendRequestAccepted {
                            pubkey: sender_pk.clone(),
                            peer_name,
                            offline_delivery: true,
                        });
                        self.emit(CoreEvent::FriendUpdated {
                            pubkey: sender_pk,
                            alias: self.identity.get_friend(&payload.sender_pubkey).and_then(|f| f.alias.clone()),
                            removed: false,
                        });
                    } else {
                        let _ = self.identity.set_friend_state(&sender_pk, FriendState::Rejected);
                        self.persist_identity();
                        self.emit(CoreEvent::FriendRequestRejected {
                            pubkey: sender_pk,
                            peer_name,
                            offline_delivery: true,
                        });
                    }
                    self.list_friends();
                    self.publish_mailbox_ack(ack);
                    return;
                }

                let sender_pk = payload.sender_pubkey.to_lowercase();
                let is_my_friend =
                    self.identity.get_friend_state(&sender_pk) == Some(FriendState::Confirmed);
                let sender_online = self.is_pubkey_online(&sender_pk);
                let peer_name = self
                    .identity
                    .get_friends()
                    .iter()
                    .find(|f| f.public_key.eq_ignore_ascii_case(&sender_pk))
                    .and_then(|f| f.alias.clone())
                    .unwrap_or_else(|| payload.sender_nick.clone());

                // Aplica o Firewall também para envelopes offline (evita que desconhecidos inundem a Carol via guardiões)
                match self.dm.firewall.check_incoming_dm(
                    &sender_pk,
                    is_my_friend,
                    payload.text.len(),
                    !sender_online,
                    &self.dm.node_config.dm,
                    now,
                ) {
                    DmFirewallVerdict::Allowed => {
                        if let Some((invite, maybe_passport)) = super::parse_invite_details(&payload.text) {
                            if let Some(passport) = maybe_passport {
                                self.accept_invite_passport(&invite, &passport);
                            }
                            let known = self.servers.get(&invite).is_some();
                            self.emit(CoreEvent::InviteReceived {
                                from: payload.sender_nick.clone(),
                                server_id: invite.clone(),
                                known,
                            });
                            self.last_invite = Some(invite);
                        }
                        self.emit(CoreEvent::DirectMessage {
                            peer_pubkey: sender_pk,
                            peer_name,
                            author: payload.sender_nick,
                            author_pubkey: payload.sender_pubkey,
                            text: payload.text,
                            timestamp: payload.timestamp,
                            offline_delivery: !sender_online,
                        });
                    }
                    DmFirewallVerdict::DroppedSilently { .. } => {
                        tracing::debug!("Envelope offline de {} descartado pelo firewall", short_id(&sender_pk));
                    }
                    DmFirewallVerdict::NewlyBlocked {
                        reason,
                        duration_secs,
                        blocked_until,
                        offense_level,
                        send_courtesy,
                    } => {
                        self.emit(CoreEvent::PeerBlocked {
                            pubkey: sender_pk.clone(),
                            peer_name,
                            is_friend: is_my_friend,
                            reason: reason.clone(),
                            duration_secs,
                            blocked_until,
                            offense_level,
                            courtesy_sent: send_courtesy,
                        });
                        if send_courtesy && sender_online {
                            self.send_courtesy_block_notice(&sender_pk, &reason, duration_secs, now);
                        }
                        if let Some(pid) = crate::api::peer_id_from_pubkey_hex(&sender_pk) {
                            self.node.swarm.behaviour_mut().gossipsub.blacklist_peer(&pid);
                        }
                    }
                }
                // Mesmo se bloqueado, envia ACK para que os guardiões limpem o envelope do disco deles
                self.publish_mailbox_ack(ack);
            }
            Err(e) => {
                tracing::debug!("Envelope offline inválido descartado: {}", e);
            }
        }
    }

    /// Envia 1 única mensagem de cortesia E2EE avisando o remetente de que ele foi bloqueado temporariamente pelo firewall local (Issue #73)
    fn send_courtesy_block_notice(&mut self, recipient_pubkey: &str, reason: &str, duration_secs: u64, now: u64) {
        let topic_str = self.subscribe_dm_with(recipient_pubkey);
        let blocked_until = now.saturating_add(duration_secs);

        // 1. Notificação estruturada Wire para o nó remoto configurar timer e reter mensagens na outbox
        let notice = BlockNotice {
            sender_pubkey: self.my_pubkey(),
            sender_nick: self.nick.clone(),
            recipient_pubkey: recipient_pubkey.to_string(),
            duration_secs,
            blocked_until,
            reason: reason.to_string(),
            timestamp: super::now_millis(),
        };
        let wire_notice = DmWireMessage::BlockNotice(notice);
        let _ = self.publish_gossip(IdentTopic::new(topic_str.clone()), wire::encode(&wire_notice));

        // 2. Mensagem em texto claro E2EE para o usuário ler no chat
        let courtesy_text = format!(
            "🛡️ [Aviso Automático do Firewall de {}]: Suas mensagens diretas foram temporariamente limitadas por {} ({}). Caso seja um engano, aguarde ou peça para {} te adicionar aos amigos.",
            self.nick,
            format_duration(Some(duration_secs)),
            reason,
            self.nick
        );
        let now_ms = super::now_millis();
        // Usa Sealed Box direto (None para session_key) para que mesmo um desconhecido sem handshake de sessão completo decifre na hora!
        if self.is_peer_subscribed_to_dm(recipient_pubkey) {
            if let Ok(envelope) = DirectMessageEnvelope::seal(
                &self.identity,
                recipient_pubkey,
                &courtesy_text,
                now_ms,
                None,
            ) {
                let wire_msg = DmWireMessage::Message(envelope);
                let bytes = wire::encode(&wire_msg);
                let _ = self.publish_gossip(IdentTopic::new(topic_str), bytes);
            }
        } else if let Ok(stored) = StoredEnvelope::create_signed_and_sealed(
            &self.identity,
            recipient_pubkey,
            &courtesy_text,
            now_ms,
            None,
        ) {
            let mb_msg = MailboxMessage::Deliver(stored);
            let _ = self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), wire::encode(&mb_msg));
        }
    }

    fn publish_mailbox_ack(&mut self, ack: ReceiptAck) {
        let msg = MailboxMessage::Ack(ack);
        let bytes = wire::encode(&msg);
        let _ = self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), bytes);
    }

    /// Enfileira um envelope na outbox local e distribui via MailboxMessage::Store aos amigos guardiões online
    pub(super) fn broadcast_mailbox_store(&mut self, stored: StoredEnvelope, topic: Option<&str>) {
        let now = super::now_secs();
        let env_id = stored.envelope_id.clone();
        if let Some(t) = topic {
            self.dm
                .mailbox
                .insert_own_with_topic(stored.clone(), t, &self.dm.node_config, now);
        } else {
            self.dm
                .mailbox
                .insert_own(stored.clone(), &self.dm.node_config, now);
        }
        let msg = MailboxMessage::Store(stored);
        let bytes = wire::encode(&msg);
        if self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), bytes).is_ok() {
            let mailbox_hash = IdentTopic::new(MAILBOX_TOPIC).hash();
            let subscribed_friends: Vec<String> = self
                .node
                .swarm
                .behaviour()
                .gossipsub
                .all_peers()
                .filter(|(_, topics)| topics.contains(&&mailbox_hash))
                .filter_map(|(peer, _)| self.peer_metadata.get(peer).map(|(_, pk)| pk.to_lowercase()))
                .filter(|pk| {
                    self.identity
                        .get_friends()
                        .iter()
                        .any(|f| f.public_key.eq_ignore_ascii_case(pk))
                })
                .collect();
            for friend_pk in subscribed_friends {
                self.dm.mailbox.mark_delegated_to_guardian(&env_id, &friend_pk);
            }
        }
    }

    /// Reage ao término de cooldown ou desbloqueio de um par (Issue #73):
    /// Limpa cooldowns locais, remove da blacklist do Gossipsub e descarrega envelopes retidos na Outbox.
    pub(super) fn on_peer_unblocked(&mut self, peer_pubkey: &str) {
        let clean_pk = peer_pubkey.trim().to_lowercase();
        if let Some(pid) = crate::api::peer_id_from_pubkey_hex(&clean_pk) {
            self.node
                .swarm
                .behaviour_mut()
                .gossipsub
                .remove_blacklisted_peer(&pid);
        }
        self.dm.remove_peer_cooldown(&clean_pk);
        let my_pk = self.identity.public_key_hex();
        let pending = self.dm.mailbox.pending_outbox_for(&my_pk, &clean_pk);
        if pending.is_empty() {
            return;
        }
        let now = super::now_secs();
        let peer_name = self.friendly_name(&clean_pk);
        let count = pending.len();
        tracing::info!(peer = %short_id(&clean_pk), count, "Descarregando envelopes retidos na outbox após desbloqueio");

        for env in pending {
            if self.dm.mailbox.get_own_topic(&env.envelope_id) == Some(FRIEND_REQUEST_MAILBOX_TOPIC) && self.is_pubkey_online(&clean_pk) {
                let req = FriendRequest::new_signed(&self.identity, &clean_pk, None, now);
                let dm_top = IdentTopic::new(dm_topic(&my_pk, &clean_pk));
                let _ = self.publish_gossip(dm_top, wire::encode(&DmWireMessage::FriendRequest(req)));
                self.send_ephemeral_key_offer(&clean_pk);
            }

            if self.is_peer_subscribed_to_mailbox(&clean_pk) {
                let msg = MailboxMessage::Deliver(env.clone());
                let _ = self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), wire::encode(&msg));
            }

            let env_id = env.envelope_id.clone();
            let msg = MailboxMessage::Store(env);
            if self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), wire::encode(&msg)).is_ok() {
                let mailbox_hash = IdentTopic::new(MAILBOX_TOPIC).hash();
                let subscribed_friends: Vec<String> = self
                    .node
                    .swarm
                    .behaviour()
                    .gossipsub
                    .all_peers()
                    .filter(|(_, topics)| topics.contains(&&mailbox_hash))
                    .filter_map(|(peer, _)| self.peer_metadata.get(peer).map(|(_, pk)| pk.to_lowercase()))
                    .filter(|pk| {
                        self.identity
                            .get_friends()
                            .iter()
                            .any(|f| f.public_key.eq_ignore_ascii_case(pk))
                    })
                    .collect();
                for friend_pk in subscribed_friends {
                    self.dm.mailbox.mark_delegated_to_guardian(&env_id, &friend_pk);
                }
            }
        }

        self.emit(CoreEvent::DirectMessage {
            peer_pubkey: clean_pk,
            peer_name,
            author: "Sistema".to_string(),
            author_pubkey: String::new(),
            text: format!("🚀 Par desbloqueado: {} mensagem(ns) retida(s) na outbox foram despachadas com sucesso.", count),
            timestamp: super::now_millis(),
            offline_delivery: false,
        });
    }

    /// Chamado quando um par Anarchord é identificado no Swarm:
    /// 1. Se tínhamos envelopes guardados para ele (`recipient == pubkey`), entregamos.
    /// 2. Se ele é nosso amigo (`pubkey` está nos amigos), delegamos envelopes da nossa outbox para ele guardar e enviamos KeyOffer de DM.
    pub(super) fn on_peer_identified_dm_and_mailbox(&mut self, peer_pubkey: &str) {
        let clean_pk = peer_pubkey.trim().to_lowercase();
        let is_friend = self
            .identity
            .get_friends()
            .iter()
            .any(|f| f.public_key.eq_ignore_ascii_case(&clean_pk));

        // Garante que estamos inscritos no tópico determinístico de DM com qualquer par Anarchord identificado
        self.subscribe_dm_with(&clean_pk);

        if is_friend {
            self.send_ephemeral_key_offer(&clean_pk);
            self.delegate_pending_to_friend(&clean_pk);
            // Propaga ACKs assinados que já recebemos para limpar a outbox/mailbox do amigo que estava offline
            for ack in self.dm.mailbox.known_acks() {
                self.publish_mailbox_ack(ack);
            }
        }

        // Entrega oportunista se guardamos envelopes destinados a este par (mesmo sem ser nosso amigo!)
        self.deliver_pending_for(&clean_pk);
    }

    /// Verifica se o par `pubkey` está inscrito no tópico determinístico de DM conosco
    fn is_peer_subscribed_to_dm(&self, pubkey: &str) -> bool {
        let topic_str = dm_topic(&self.my_pubkey(), pubkey);
        let dm_hash = IdentTopic::new(&topic_str).hash();
        self.node
            .swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .filter(|(_, topics)| topics.contains(&&dm_hash))
            .any(|(peer, _)| {
                self.peer_metadata
                    .get(peer)
                    .map(|(_, pk)| pk.eq_ignore_ascii_case(pubkey))
                    .or_else(|| {
                        crate::api::pubkey_hex_from_peer_id(peer)
                            .map(|pk| pk.eq_ignore_ascii_case(pubkey))
                    })
                    .unwrap_or(false)
            })
    }

    /// Verifica se o par `pubkey` está conectado E já anunciou inscrição no tópico `MAILBOX_TOPIC` do Gossipsub
    fn is_peer_subscribed_to_mailbox(&self, pubkey: &str) -> bool {
        let mailbox_hash = IdentTopic::new(MAILBOX_TOPIC).hash();
        self.node
            .swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .filter(|(_, topics)| topics.contains(&&mailbox_hash))
            .any(|(peer, _)| {
                self.peer_metadata
                    .get(peer)
                    .map(|(_, pk)| pk.eq_ignore_ascii_case(pubkey))
                    .or_else(|| {
                        crate::api::pubkey_hex_from_peer_id(peer)
                            .map(|pk| pk.eq_ignore_ascii_case(pubkey))
                    })
                    .unwrap_or(false)
            })
    }

    /// Orientado a eventos: quando um amigo `friend_pubkey` fica online (e está inscrito em `MAILBOX_TOPIC`),
    /// Alice verifica quais envelopes da sua outbox ainda NÃO foram pedidos para esse amigo guardar,
    /// publica `MailboxMessage::Store` uma única vez e registra que já pediu para esse amigo!
    pub(super) fn delegate_pending_to_friend(&mut self, friend_pubkey: &str) {
        let clean_friend = friend_pubkey.trim().to_lowercase();
        let is_friend = self
            .identity
            .get_friends()
            .iter()
            .any(|f| f.public_key.eq_ignore_ascii_case(&clean_friend));
        if !is_friend || !self.is_peer_subscribed_to_mailbox(&clean_friend) {
            return;
        }
        let my_pk = self.my_pubkey();
        let undelegated = self.dm.mailbox.undelegated_for_guardian(
            &my_pk,
            &clean_friend,
            super::now_secs(),
        );
        for env in undelegated {
            let env_id = env.envelope_id.clone();
            let msg = MailboxMessage::Store(env);
            let bytes = wire::encode(&msg);
            if self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), bytes).is_ok() {
                self.dm
                    .mailbox
                    .mark_delegated_to_guardian(&env_id, &clean_friend);
            }
        }
    }

    /// Chamado quando um par se inscreve no tópico `MAILBOX_TOPIC` do Gossipsub:
    /// como o `Subscribed` do Gossipsub geralmente chega alguns milissegundos *depois* do `Identify`,
    /// decidimos de forma orientada a eventos se esse par é nosso amigo (e ainda não recebeu a delegação)
    /// ou se é o destinatário de algum envelope que estamos guardando!
    pub(super) fn on_peer_subscribed_mailbox(&mut self, peer_id: libp2p::PeerId) {
        let peer_pk = self
            .peer_metadata
            .get(&peer_id)
            .map(|(_, pk)| pk.clone())
            .or_else(|| crate::api::pubkey_hex_from_peer_id(&peer_id));
        if let Some(pk) = peer_pk {
            self.delegate_pending_to_friend(&pk);
            self.deliver_pending_for(&pk);
        }
        for ack in self.dm.mailbox.known_acks() {
            self.publish_mailbox_ack(ack);
        }
    }

    pub(super) fn deliver_pending_for(&mut self, recipient_pubkey: &str) {
        if !self.is_peer_subscribed_to_mailbox(recipient_pubkey) {
            return;
        }
        let now = super::now_secs();
        let pending = self.dm.mailbox.pending_for_recipient(recipient_pubkey, now);
        for env in pending {
            let msg = MailboxMessage::Deliver(env);
            let bytes = wire::encode(&msg);
            let _ = self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), bytes);
        }
        let my_pk = self.identity.public_key_hex();
        let outbox_pending = self.dm.mailbox.pending_outbox_for(&my_pk, recipient_pubkey);
        for env in outbox_pending {
            let msg = MailboxMessage::Deliver(env);
            let bytes = wire::encode(&msg);
            let _ = self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), bytes);
        }
    }

    /// Tick periódico da Mailbox: purga envelopes expirados do disco e desbloqueios do firewall (Issue #73)
    pub(super) fn mailbox_tick(&mut self) {
        let now = super::now_secs();
        self.dm.mailbox.purge_expired(now);

        // Purga bloqueios do firewall local expirados e notifica
        let unblocked_peers = self.dm.firewall.purge_expired_blocks(now);
        for pk in unblocked_peers {
            let peer_name = self.friendly_name(&pk);
            self.emit(CoreEvent::PeerUnblocked {
                pubkey: pk.clone(),
                peer_name,
            });
            self.on_peer_unblocked(&pk);
        }

        // Purga cooldowns remotos expirados
        let expired_cooldowns: Vec<String> = self
            .dm
            .peer_cooldowns
            .iter()
            .filter(|(_, &until)| now >= until)
            .map(|(pk, _)| pk.clone())
            .collect();
        for pk in expired_cooldowns {
            self.on_peer_unblocked(&pk);
        }
    }

    /// Exibe a configuração atual e o uso da mailbox
    pub(super) fn show_config(&self) {
        self.emit(CoreEvent::ConfigStatus {
            config: self.dm.node_config.clone(),
            mailbox_used_bytes: self.dm.mailbox.total_bytes(),
            mailbox_envelope_count: self.dm.mailbox.envelope_count(),
        });
    }

    /// Altera um parâmetro da configuração local e persiste no disco
    pub(super) fn set_config(&mut self, key: &str, value: &str) {
        match self.dm.node_config.set_key(key, value) {
            Ok(()) => {
                self.dm
                    .firewall
                    .relay_access()
                    .set_friends_only(self.dm.node_config.firewall.relay_friends_only);
                let _ = self.dm.node_config.save(self.dm.config_path.as_deref());
                self.emit(CoreEvent::ConfigUpdated {
                    key: key.trim().to_string(),
                    value: value.trim().to_string(),
                });
                self.show_config();
            }
            Err(e) => self.error(CoreError::Config(e.to_string())),
        }
    }

    /// Lista os bloqueios ativos no Firewall local (`/firewall`)
    pub(super) fn list_firewall(&self) {
        let blocks = self.dm.firewall.active_blocks(super::now_secs());
        self.emit(CoreEvent::FirewallStatus(blocks));
    }

    /// Desbloqueia manualmente um par no Firewall local (`/firewall unblock <par>`)
    pub(super) fn unblock_peer(&mut self, target: &str) {
        let pubkey = self
            .resolve_dm_target(target)
            .map(|(pk, _)| pk)
            .unwrap_or_else(|| target.trim().to_lowercase());
        let peer_name = self.friendly_name(&pubkey);
        let unblocked_fw = self.dm.firewall.unblock(&pubkey);
        let unblocked_cd = self.dm.remove_peer_cooldown(&pubkey).is_some();
        if unblocked_fw || unblocked_cd {
            self.emit(CoreEvent::PeerUnblocked { pubkey: pubkey.clone(), peer_name });
            self.on_peer_unblocked(&pubkey);
        } else {
            self.error(CoreError::Friend(format!("'{}' não está bloqueado no firewall", target)));
        }
    }

    /// Envia pedido de amizade mútuo (online via DM topic ou offline via Guardiões)
    pub(super) fn send_friend_request(&mut self, who: &str, alias: Option<&str>, message: Option<&str>) {
        let (pubkey, inferred_alias) = match self.resolve_dm_target(who) {
            Some((pk, name)) => {
                let alias_opt = alias.map(str::to_string).or_else(|| {
                    if !pk.eq_ignore_ascii_case(&name) {
                        Some(name)
                    } else {
                        None
                    }
                });
                (pk, alias_opt)
            }
            None => {
                let who_trim = who.trim();
                if who_trim.len() == 64 && who_trim.chars().all(|c| c.is_ascii_hexdigit()) {
                    (who_trim.to_lowercase(), alias.map(str::to_string))
                } else {
                    return self.error(CoreError::PeerNotFound(who.to_string()));
                }
            }
        };

        if pubkey.eq_ignore_ascii_case(&self.my_pubkey()) {
            return self.error(CoreError::Friend("Você não pode adicionar a si mesmo como amigo".into()));
        }

        // Se já tínhamos um pedido recebido pendente deste par, adicionar significa aceitar!
        if self.identity.get_friend_state(&pubkey) == Some(FriendState::PendingIncoming) {
            self.accept_friend(&pubkey);
            return;
        }

        let now = super::now_secs();
        let now_ms = super::now_millis();

        // 1. Registra localmente como PendingOutgoing
        if let Err(e) = self.identity.add_or_update_friend(&pubkey, inferred_alias.as_deref(), FriendState::PendingOutgoing) {
            return self.error(CoreError::Friend(e.to_string()));
        }
        self.persist_identity();
        self.dm.firewall.unblock(&pubkey);
        self.subscribe_dm_with(&pubkey);

        // Issue #73: Se estiver sob cooldown com o destinatário, retém na outbox local sem transmitir ainda
        if let Some(until) = self.dm.is_under_cooldown(&pubkey, now) {
            let remaining = until.saturating_sub(now);
            let intro_msg = message.unwrap_or("");
            if let Ok(stored) = StoredEnvelope::create_signed_and_sealed_topic(
                &self.identity,
                &pubkey,
                FRIEND_REQUEST_MAILBOX_TOPIC,
                intro_msg,
                now_ms,
                None,
            ) {
                self.dm.mailbox.insert_own_with_topic(stored, FRIEND_REQUEST_MAILBOX_TOPIC, &self.dm.node_config, now);
                let rem_fmt = format_duration(Some(remaining));
                let peer_name = self.friendly_name(&pubkey);
                self.emit(CoreEvent::DirectMessage {
                    peer_pubkey: pubkey.clone(),
                    peer_name,
                    author: "Sistema".to_string(),
                    author_pubkey: String::new(),
                    text: format!(
                        "⏳ Você está sob cooldown temporário com este par (restam {}). Seu pedido de amizade foi retido na outbox e será enviado automaticamente após o término.",
                        rem_fmt
                    ),
                    timestamp: now_ms,
                    offline_delivery: false,
                });
            }
            self.emit(CoreEvent::FriendUpdated {
                pubkey: pubkey.to_lowercase(),
                alias: inferred_alias,
                removed: false,
            });
            self.list_friends();
            return;
        }

        // 2. Envia online via tópico mútuo
        let req = FriendRequest::new_signed(&self.identity, &pubkey, message, now);
        let dm_top = IdentTopic::new(dm_topic(&self.my_pubkey(), &pubkey));
        let wire_msg = wire::encode(&DmWireMessage::FriendRequest(req));
        let _ = self.publish_gossip(dm_top, wire_msg);

        if self.is_pubkey_online(&pubkey) {
            self.send_ephemeral_key_offer(&pubkey);
            self.delegate_pending_to_friend(&pubkey);
        }

        // 3. Enfileira na Mailbox para entrega offline via Guardiões caso o par esteja offline
        let intro_msg = message.unwrap_or("");
        if let Ok(stored) = StoredEnvelope::create_signed_and_sealed_topic(
            &self.identity,
            &pubkey,
            FRIEND_REQUEST_MAILBOX_TOPIC,
            intro_msg,
            now_ms,
            None,
        ) {
            self.broadcast_mailbox_store(stored, Some(FRIEND_REQUEST_MAILBOX_TOPIC));
        }

        self.emit(CoreEvent::FriendUpdated {
            pubkey: pubkey.to_lowercase(),
            alias: inferred_alias,
            removed: false,
        });
        self.list_friends();
    }

    /// Aceita um pedido de amizade pendente
    pub(super) fn accept_friend(&mut self, target: &str) {
        let (pubkey, _) = match self.resolve_dm_target(target) {
            Some(res) => res,
            None => {
                let t_trim = target.trim();
                if t_trim.len() == 64 && t_trim.chars().all(|c| c.is_ascii_hexdigit()) {
                    (t_trim.to_lowercase(), t_trim.to_string())
                } else {
                    return self.error(CoreError::Friend(format!("Contato '{}' não encontrado para aceitar", target)));
                }
            }
        };

        let now = super::now_secs();
        let now_ms = super::now_millis();

        if !self.identity.set_friend_state(&pubkey, FriendState::Confirmed) {
            let _ = self.identity.add_or_update_friend(&pubkey, None, FriendState::Confirmed);
        }
        self.persist_identity();
        self.dm.firewall.unblock(&pubkey);
        self.subscribe_dm_with(&pubkey);
        self.on_peer_unblocked(&pubkey);

        // Envia resposta positiva online
        let resp = FriendResponse::new_signed(&self.identity, &pubkey, true, now);
        let dm_top = IdentTopic::new(dm_topic(&self.my_pubkey(), &pubkey));
        let wire_msg = wire::encode(&DmWireMessage::FriendResponse(resp));
        let _ = self.publish_gossip(dm_top, wire_msg);

        if self.is_pubkey_online(&pubkey) {
            self.send_ephemeral_key_offer(&pubkey);
            self.delegate_pending_to_friend(&pubkey);
        }

        // Também despacha via Mailbox para entrega offline garantida (e imediata se já estiver inscrito)
        if let Ok(stored) = StoredEnvelope::create_signed_and_sealed_topic(
            &self.identity,
            &pubkey,
            FRIEND_RESPONSE_MAILBOX_TOPIC,
            "ACCEPTED",
            now_ms,
            None,
        ) {
            if self.is_pubkey_online(&pubkey) {
                let deliver = MailboxMessage::Deliver(stored.clone());
                let _ = self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), wire::encode(&deliver));
            }
            self.broadcast_mailbox_store(stored, Some(FRIEND_RESPONSE_MAILBOX_TOPIC));
        }

        self.emit(CoreEvent::FriendUpdated {
            pubkey: pubkey.clone(),
            alias: self.identity.get_friend(&pubkey).and_then(|f| f.alias.clone()),
            removed: false,
        });
        self.list_friends();
    }

    /// Rejeita um pedido de amizade pendente
    pub(super) fn reject_friend(&mut self, target: &str) {
        let (pubkey, _) = match self.resolve_dm_target(target) {
            Some(res) => res,
            None => {
                let t_trim = target.trim();
                if t_trim.len() == 64 && t_trim.chars().all(|c| c.is_ascii_hexdigit()) {
                    (t_trim.to_lowercase(), t_trim.to_string())
                } else {
                    return self.error(CoreError::Friend(format!("Contato '{}' não encontrado para rejeitar", target)));
                }
            }
        };

        let now = super::now_secs();
        let now_ms = super::now_millis();

        let _ = self.identity.set_friend_state(&pubkey, FriendState::Rejected);
        self.persist_identity();

        let _peer_name = self.friendly_name(&pubkey);

        // Envia resposta de rejeição online
        let resp = FriendResponse::new_signed(&self.identity, &pubkey, false, now);
        let dm_top = IdentTopic::new(dm_topic(&self.my_pubkey(), &pubkey));
        let wire_msg = wire::encode(&DmWireMessage::FriendResponse(resp));
        let _ = self.publish_gossip(dm_top, wire_msg);

        // Despacha via Mailbox para entrega offline
        if let Ok(stored) = StoredEnvelope::create_signed_and_sealed_topic(
            &self.identity,
            &pubkey,
            FRIEND_RESPONSE_MAILBOX_TOPIC,
            "REJECTED",
            now_ms,
            None,
        ) {
            self.broadcast_mailbox_store(stored, Some(FRIEND_RESPONSE_MAILBOX_TOPIC));
        }

        self.emit(CoreEvent::FriendUpdated {
            pubkey: pubkey.clone(),
            alias: self.identity.get_friend(&pubkey).and_then(|f| f.alias.clone()),
            removed: false,
        });
        self.list_friends();
    }

    /// Reenvia pedido de amizade a um contato
    pub(super) fn resend_friend_request(&mut self, target: &str, message: Option<&str>) {
        self.send_friend_request(target, None, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::CoreConfig;
    use crate::UserIdentity;
    use tokio::sync::mpsc::unbounded_channel;

    #[tokio::test]
    async fn test_dm_outbox_retention_under_cooldown_and_unblock_flush() {
        let (tx, mut rx) = unbounded_channel();
        let temp = std::env::temp_dir().join(format!("test_dm_cooldown_{}", rand::random::<u32>()));
        let config = CoreConfig::new(
            UserIdentity::generate_with_nick("Alice"),
            temp.join("servers"),
            temp.join("downloads"),
        );
        let mut runtime = Runtime::new(config, tx).unwrap();
        let alice_pk = runtime.my_pubkey();

        let bob = UserIdentity::generate_with_nick("Bob");
        let bob_pk = bob.public_key_hex();

        // 1. Configura cooldown para Bob
        let now = super::super::now_secs();
        runtime.dm.set_peer_cooldown(&bob_pk, now + 100);
        assert!(runtime.dm.is_under_cooldown(&bob_pk, now).is_some());

        // 2. Alice tenta enviar uma DM para Bob -> retida na outbox
        runtime.send_dm(&bob_pk, "Mensagem retida para Bob", None);

        let pending = runtime.dm.mailbox.pending_outbox_for(&alice_pk, &bob_pk);
        assert_eq!(pending.len(), 1, "Mensagem deve ser retida na outbox local");
        assert_eq!(runtime.dm.mailbox.get_own_topic(&pending[0].envelope_id), Some(crate::dm::DEFAULT_MAILBOX_TOPIC));

        // 3. Alice tenta enviar pedido de amizade para Bob enquanto sob cooldown -> também retido
        runtime.send_friend_request(&bob_pk, Some("Bobby"), Some("Olá Bob!"));
        let pending = runtime.dm.mailbox.pending_outbox_for(&alice_pk, &bob_pk);
        assert_eq!(pending.len(), 2, "Ambos envelopes devem estar na outbox");

        // 4. Dispara on_peer_unblocked -> cooldown é removido e outbox é descarregada
        runtime.on_peer_unblocked(&bob_pk);
        assert!(runtime.dm.is_under_cooldown(&bob_pk, now).is_none());

        // Consome eventos emitidos
        let mut got_cooldown_notice = false;
        let mut got_unblocked_flush = false;
        while let Ok(evt) = rx.try_recv() {
            if let CoreEvent::DirectMessage { text, .. } = evt {
                if text.contains("cooldown temporário") {
                    got_cooldown_notice = true;
                }
                if text.contains("Par desbloqueado") && text.contains("2 mensagem(ns)") {
                    got_unblocked_flush = true;
                }
            }
        }
        assert!(got_cooldown_notice);
        assert!(got_unblocked_flush);
    }

    #[tokio::test]
    async fn test_mutual_cross_friend_request_resolution_online() {
        let (tx, mut rx) = unbounded_channel();
        let temp = std::env::temp_dir().join(format!("test_cross_freq_{}", rand::random::<u32>()));
        let config = CoreConfig::new(
            UserIdentity::generate_with_nick("Alice"),
            temp.join("servers"),
            temp.join("downloads"),
        );
        let mut runtime = Runtime::new(config, tx).unwrap();
        let alice_pk = runtime.my_pubkey();

        let bob = UserIdentity::generate_with_nick("Bob");
        let bob_pk = bob.public_key_hex();

        // 1. Alice envia pedido de amizade para Bob (fica PendingOutgoing)
        runtime.send_friend_request(&bob_pk, Some("Bob"), None);
        assert_eq!(runtime.identity.get_friend_state(&bob_pk), Some(FriendState::PendingOutgoing));
        assert_eq!(runtime.dm.mailbox.pending_outbox_for(&alice_pk, &bob_pk).len(), 1);

        // 2. Bob envia pedido mútuo (Cross-Friend Request) para Alice via Wire
        let req = FriendRequest::new_signed(&bob, &alice_pk, Some("Olá Alice, também quero ser seu amigo!"), 1000);
        runtime.on_dm_wire_message(DmWireMessage::FriendRequest(req));

        // 3. Resolução automática imediata para Confirmed!
        assert_eq!(runtime.identity.get_friend_state(&bob_pk), Some(FriendState::Confirmed));

        // 4. Pedido de amizade na Outbox foi descartado (resta apenas a resposta FRIEND_RESPONSE com ACCEPTED para Bob)
        let pending = runtime.dm.mailbox.pending_outbox_for(&alice_pk, &bob_pk);
        assert_eq!(pending.len(), 1);
        assert_eq!(runtime.dm.mailbox.get_own_topic(&pending[0].envelope_id), Some(FRIEND_RESPONSE_MAILBOX_TOPIC));

        // 5. Verifica se FriendRequestAccepted foi emitido
        let mut accepted_emitted = false;
        while let Ok(evt) = rx.try_recv() {
            if let CoreEvent::FriendRequestAccepted { pubkey, offline_delivery, .. } = evt {
                if pubkey == bob_pk && !offline_delivery {
                    accepted_emitted = true;
                }
            }
        }
        assert!(accepted_emitted);
    }

    #[tokio::test]
    async fn test_mutual_cross_friend_request_resolution_offline_mailbox() {
        let (tx, mut rx) = unbounded_channel();
        let temp = std::env::temp_dir().join(format!("test_cross_offline_{}", rand::random::<u32>()));
        let config = CoreConfig::new(
            UserIdentity::generate_with_nick("Alice"),
            temp.join("servers"),
            temp.join("downloads"),
        );
        let mut runtime = Runtime::new(config, tx).unwrap();
        let alice_pk = runtime.my_pubkey();

        let bob = UserIdentity::generate_with_nick("Bob");
        let bob_pk = bob.public_key_hex();

        // 1. Alice tem pedido enviado para Bob (PendingOutgoing)
        runtime.send_friend_request(&bob_pk, Some("Bob"), None);
        assert_eq!(runtime.identity.get_friend_state(&bob_pk), Some(FriendState::PendingOutgoing));

        // 2. Bob envia pedido offline via Mailbox
        let offline_env = StoredEnvelope::create_signed_and_sealed_topic(
            &bob,
            &alice_pk,
            FRIEND_REQUEST_MAILBOX_TOPIC,
            "Pedido de Bob via Mailbox",
            1000,
            None,
        ).unwrap();

        // 3. Alice recebe o envelope
        runtime.receive_sealed_envelope(offline_env, 1000);

        // 4. Transição automática para Confirmed e outbox de pedido limpa (resta apenas a resposta FRIEND_RESPONSE)
        assert_eq!(runtime.identity.get_friend_state(&bob_pk), Some(FriendState::Confirmed));
        let pending = runtime.dm.mailbox.pending_outbox_for(&alice_pk, &bob_pk);
        assert_eq!(pending.len(), 1);
        assert_eq!(runtime.dm.mailbox.get_own_topic(&pending[0].envelope_id), Some(FRIEND_RESPONSE_MAILBOX_TOPIC));

        let mut accepted_emitted = false;
        while let Ok(evt) = rx.try_recv() {
            if let CoreEvent::FriendRequestAccepted { pubkey, offline_delivery, .. } = evt {
                if pubkey == bob_pk && offline_delivery {
                    accepted_emitted = true;
                }
            }
        }
        assert!(accepted_emitted);
    }

    #[tokio::test]
    async fn test_block_notice_triggers_cooldown_and_unblock_by_friend_add() {
        let (tx, _rx) = unbounded_channel();
        let temp = std::env::temp_dir().join(format!("test_block_notice_{}", rand::random::<u32>()));
        let config = CoreConfig::new(
            UserIdentity::generate_with_nick("Alice"),
            temp.join("servers"),
            temp.join("downloads"),
        );
        let mut runtime = Runtime::new(config, tx).unwrap();
        let alice_pk = runtime.my_pubkey();

        let bob = UserIdentity::generate_with_nick("Bob");
        let bob_pk = bob.public_key_hex();

        let now = super::super::now_secs();
        let notice = BlockNotice {
            sender_pubkey: bob_pk.clone(),
            sender_nick: "Bob".to_string(),
            recipient_pubkey: alice_pk.clone(),
            duration_secs: 60,
            blocked_until: now + 60,
            reason: "Rate limit excedido".to_string(),
            timestamp: super::super::now_millis(),
        };

        // Alice recebe BlockNotice de Bob
        runtime.on_dm_wire_message(DmWireMessage::BlockNotice(notice));
        assert!(runtime.dm.is_under_cooldown(&bob_pk, now).is_some());

        // Alice desbloqueia Bob manualmente via unblock_peer
        runtime.unblock_peer(&bob_pk);
        assert!(runtime.dm.is_under_cooldown(&bob_pk, now).is_none());
    }

    #[tokio::test]
    async fn test_dm_invite_populates_last_invite_and_emits_event() {
        let (tx, mut rx) = unbounded_channel();
        let temp = std::env::temp_dir().join(format!("test_dm_invite_{}", rand::random::<u32>()));
        let config = CoreConfig::new(
            UserIdentity::generate_with_nick("Alice"),
            temp.join("servers"),
            temp.join("downloads"),
        );
        let mut runtime = Runtime::new(config, tx).unwrap();
        let alice_pk = runtime.my_pubkey();

        let bob = UserIdentity::generate_with_nick("Bob");
        let server_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        // 1. Bob envia convite de servidor via DM online
        let invite_text = format!("📨 Convite para o servidor 'Rust': /server join {}", server_id);
        let env = DirectMessageEnvelope::seal(&bob, &alice_pk, &invite_text, 1000, None).unwrap();
        runtime.on_dm_wire_message(DmWireMessage::Message(env));

        assert_eq!(runtime.last_invite.as_deref(), Some(server_id));

        let mut got_invite_evt = false;
        let mut got_dm_evt = false;
        while let Ok(evt) = rx.try_recv() {
            match evt {
                CoreEvent::InviteReceived { from, server_id: sid, known } => {
                    assert_eq!(from, "Bob");
                    assert_eq!(sid, server_id);
                    assert!(!known);
                    got_invite_evt = true;
                }
                CoreEvent::DirectMessage { text, .. } => {
                    assert_eq!(text, invite_text);
                    got_dm_evt = true;
                }
                _ => {}
            }
        }
        assert!(got_invite_evt, "Deveria emitir CoreEvent::InviteReceived ao receber convite via DM");
        assert!(got_dm_evt, "Deveria emitir CoreEvent::DirectMessage ao receber DM");

        // 2. Convite via envelope offline da Mailbox
        let server_id2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let offline_text = format!("/server join {}", server_id2);
        let offline_env = StoredEnvelope::create_signed_and_sealed(
            &bob,
            &alice_pk,
            &offline_text,
            2000,
            None,
        ).unwrap();

        runtime.receive_sealed_envelope(offline_env, 2000);
        assert_eq!(runtime.last_invite.as_deref(), Some(server_id2));

        let mut got_offline_invite = false;
        while let Ok(evt) = rx.try_recv() {
            if let CoreEvent::InviteReceived { server_id: sid, .. } = evt {
                if sid == server_id2 {
                    got_offline_invite = true;
                }
            }
        }
        assert!(got_offline_invite, "Deveria emitir CoreEvent::InviteReceived para convite offline");

        // 3. Convite com Passaporte criptográfico embutido (Servidor Privado)
        let now = super::super::now_secs();
        let server_key = UserIdentity::generate();
        let server_id3 = server_key.public_key_hex();
        let passport = crate::community::ServerPassport::issue_root(
            &server_key,
            &alice_pk,
            crate::community::PassportPermission::member(),
            now,
            Some(now + 3600),
        );
        let token = passport.to_token();
        let invite_with_passport = format!("📨 Convite: /server join {} {}", server_id3, token);
        let env_with_passport = DirectMessageEnvelope::seal(
            &bob,
            &alice_pk,
            &invite_with_passport,
            now * 1000,
            None,
        ).unwrap();

        runtime.on_dm_wire_message(DmWireMessage::Message(env_with_passport));
        assert_eq!(runtime.last_invite.as_deref(), Some(server_id3.as_str()));
        let my_p = runtime.servers.get(&server_id3).and_then(|s| s.my_passport().cloned());
        assert_eq!(my_p, Some(passport), "Passaporte recebido no convite deve ser aceito automaticamente");
    }
}
