//! Servidores: comandos, cadeia de configuração, moderação, passaportes, carimbos de tempo e o
//! grupo cifrado (MLS).

use super::{
    BanEntry, ChannelInfo, CoreError, CoreEvent, Role, Runtime, ServerChange, ServerCommand, ServerInfo, ServerListEntry, ServerNotice,
};
use crate::api::ChatMessage;
use crate::community::{
    self,
    e2ee::{self, CommitOutcome, E2eeError},
    server_control_topic, server_dht_key,
    timestamp::{self, TimestampAttestation},
    ChannelType, CommunityError, ModKind, PassportPermission, ServerEvent, ServerMessage, Space, Submitted, TrustedTsa,
};
use base64::Engine as _;
use libp2p::gossipsub::IdentTopic;
use std::time::{Duration, Instant};


/// Resultado de um pedido de carimbo a uma TSA, feito fora do loop de eventos
pub(super) struct StampResult {
    server_id: String,
    imprint: [u8; 32],
    tsa: String,
    result: Result<TimestampAttestation, String>,
}

/// Texto do convite publicado no chat. Quem recebe usa `/server accept`.
pub fn invite_text(server_name: &str, server_id: &str) -> String {
    format!("📨 Convite para o servidor '{}'. Para entrar: /server accept  (ou /server join {})", server_name, server_id)
}

/// Se a mensagem de chat contém um convite (`/server join <id> [token]`), devolve o id do servidor e o passaporte opcional
pub fn parse_invite_details(text: &str) -> Option<(String, Option<crate::community::ServerPassport>)> {
    let rest = text.split("/server join ").nth(1)?.trim();
    let mut parts = rest.split_whitespace();
    let id_raw = parts.next()?;
    let id: String = id_raw.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if !community::is_valid_server_id(&id) {
        return None;
    }
    let passport = parts.next().and_then(crate::community::ServerPassport::from_token);
    Some((id, passport))
}

/// Se a mensagem de chat contém um convite (`/server join <id>`), devolve o id do servidor
pub fn parse_invite(text: &str) -> Option<String> {
    parse_invite_details(text).map(|(id, _)| id)
}

impl Runtime {
    pub(super) fn notice(&self, notice: ServerNotice) {
        self.emit(CoreEvent::Server(notice));
    }

    /// Passa a ouvir o tópico de controle do servidor (cadeia e moderação) e o de telas dele
    pub(super) fn follow_server(&mut self, server_id: &str) {
        let gossipsub = &mut self.node.swarm.behaviour_mut().gossipsub;
        let _ = gossipsub.subscribe(&IdentTopic::new(server_control_topic(server_id)));
        let _ = gossipsub.subscribe(&IdentTopic::new(community::screen_topic(&Space::Server(server_id.to_string()))));
    }

    /// Publica no tópico de controle do servidor. Falha (sem ninguém no tópico) é normal e ignorada.
    pub(super) fn publish_server_message(&mut self, server_id: &str, message: &ServerMessage) -> bool {
        let topic = IdentTopic::new(server_control_topic(server_id));
        self.publish_gossip(topic, crate::wire::encode(message)).is_ok()
    }

    pub(super) fn default_channel(&self, server_id: &str) -> String {
        self.servers.get(server_id).and_then(|s| s.default_text_channel()).unwrap_or_else(|| "geral".to_string())
    }

    /// Participamos do servidor: cadeia sincronizada e passaporte válido (ou somos o dono)
    fn participating(&self, server_id: &str, now: u64) -> bool {
        let me = self.my_pubkey();
        self.servers.get(server_id).is_some_and(|s| s.has_chain() && s.is_allowed(&me, now))
    }

    /// Sala atual: (servidor, canal, id do grupo cifrado). Cada sala tem o próprio grupo, líder e
    /// chave, e só participamos do grupo da sala em que estamos.
    pub(super) fn active_room(&self) -> Option<(String, String, String)> {
        let server = self.active.server_id()?.to_string();
        let channel = self.active.channel.clone();
        let room = community::room_id(&server, &channel);
        Some((server, channel, room))
    }

    /// Grupo cifrado que protege um tópico de conteúdo de servidor: o da sala do canal (texto ou voz),
    /// ou, para telas (tópico do servidor inteiro), o da nossa sala nesse servidor
    pub(super) fn room_for_topic(&self, topic: &str) -> Option<String> {
        if let Some((server_id, channel)) = community::parse_room_topic(topic) {
            return Some(community::room_id(server_id, channel));
        }
        let server_id = community::parse_server_content_topic(topic)?;
        let (active_server, _, room) = self.active_room()?;
        (active_server == server_id).then_some(room)
    }

    /// Id do grupo da sala, se ela for a atual (mensagens de grupo de outras salas são ignoradas)
    fn room_if_active(&self, server_id: &str, channel: &str) -> Option<String> {
        let (server, current, room) = self.active_room()?;
        (server == server_id && current == channel).then_some(room)
    }

    fn enter_server(&mut self, server_id: String) {
        // Sem passaporte: tópico de pedidos; com passaporte: sai dele
        self.sync_access_topics();
        let channel = self.default_channel(&server_id);
        self.enter_channel(Space::Server(server_id), channel);
    }

    /// Entra no grupo cifrado da sala atual. Entrar é anunciado sempre com o KeyPackage: se ainda
    /// constamos no grupo (saímos sem o aviso chegar, ex.: Ctrl+C), vale como "saiu e entrou". Sem
    /// resposta até o próximo tick, assumimos a liderança criando o grupo; sem ninguém no tópico, já.
    pub(super) fn enter_room_group(&mut self) {
        let now = super::now_secs();
        let Some((server_id, channel, room)) = self.active_room() else { return };
        if !self.participating(&server_id, now) || self.mls.has_group(&room) {
            return;
        }
        if !self.request_group_key(&server_id, &channel) {
            let _ = self.mls.create_group(&room);
            self.announce_mls_group();
        }
    }

    /// Sai do grupo cifrado da sala atual (troca de sala, saída do servidor ou encerramento)
    pub(super) fn leave_room_group(&mut self) {
        let Some((server_id, channel, room)) = self.active_room() else { return };
        self.announce_group_leave(&server_id, &channel);
        self.mls.drop_group(&room);
        self.last_key_package.remove(&room);
    }

    /// Publica o pacote de chave MLS da sala com o nosso passaporte. `false` = ninguém no tópico.
    fn request_group_key(&mut self, server_id: &str, channel: &str) -> bool {
        let Ok(key_package) = self.mls.key_package() else { return false };
        let passport = self.servers.get(server_id).and_then(|s| s.my_passport().cloned());
        let message = ServerMessage::KeyPackage { server_id: server_id.to_string(), room: channel.to_string(), key_package, passport };
        let sent = self.publish_server_message(server_id, &message);
        if sent {
            self.last_key_package.insert(community::room_id(server_id, channel), Instant::now());
        }
        sent
    }

    /// Avisa que saímos do grupo cifrado da sala (atalho para o líder trocar a chave já; não é garantido)
    fn announce_group_leave(&mut self, server_id: &str, channel: &str) {
        let room = community::room_id(server_id, channel);
        if self.mls.has_group(&room) && self.mls.members(&room).len() > 1 {
            self.publish_server_message(server_id, &ServerMessage::GroupLeave { server_id: server_id.to_string(), room: channel.to_string() });
        }
    }

    /// Avisa a interface quando o líder do grupo cifrado da sala atual muda
    pub(super) fn check_leader_changes(&mut self) {
        let me = self.my_pubkey();
        let active = self.active_room();
        self.last_leader.retain(|id, _| active.as_ref().is_some_and(|(_, _, room)| room == id));
        let Some((server_id, channel, room)) = active else { return };
        let leader = self.mls.leader(&room);
        if self.last_leader.get(&room) == Some(&leader) {
            return;
        }
        let known_before = self.last_leader.insert(room, leader.clone()).is_some();
        if leader.is_none() && !known_before {
            return;
        }
        self.notice(ServerNotice::LeaderChanged {
            server: format!("{} #{}", self.server_name(&server_id), channel),
            you: leader.as_deref() == Some(me.as_str()),
            leader: leader.map(|pk| self.nick_for(&pk)),
        });
    }

    /// Se somos o líder efetivo do grupo da sala atual (neste servidor), remove agora quem está
    /// banido ou sem passaporte válido. Os membros validam esse Commit como qualquer outro.
    fn enforce_now(&mut self, server_id: &str) {
        let now = super::now_secs();
        let Some((active_server, channel, room)) = self.active_room() else { return };
        if active_server != server_id || !self.mls.has_group(&room) {
            return;
        }
        // Fomos banidos ou perdemos o passaporte: saímos sozinhos do grupo da sala, sem depender do
        // líder (podemos nem estar no mesmo grupo que ele)
        if self.servers.get(server_id).is_some_and(|s| s.is_excluded(&self.my_pubkey(), now)) {
            self.leave_room_group();
            self.notice(ServerNotice::RemovedFromGroup { server: self.server_name(server_id) });
            return;
        }
        if let Ok(Some(commit)) = e2ee::enforce_membership(&mut self.mls, &self.servers, server_id, &channel, now) {
            self.publish_server_message(server_id, &commit);
            self.announce_mls_group();
        }
    }

    /// Pede carimbos de tempo para `imprint`: às TSAs da política (em threads, via HTTP) e às
    /// testemunhas da rede (pelo tópico de controle)
    pub(super) fn request_stamps(&mut self, server_id: &str, imprint: [u8; 32]) {
        let tsas = self.servers.get(server_id).map(|s| s.chain().state().timestamp_policy.tsas.clone()).unwrap_or_default();
        self.request_stamps_with(server_id, imprint, tsas);
    }

    /// Como [`Self::request_stamps`], com as autoridades informadas (ex.: servidor do qual acabamos de sair)
    pub(super) fn request_stamps_with(&mut self, server_id: &str, imprint: [u8; 32], tsas: Vec<TrustedTsa>) {
        let nonce = timestamp::hex(&rand::random::<[u8; 8]>());
        self.publish_server_message(
            server_id,
            &ServerMessage::StampRequest { server_id: server_id.to_string(), imprint: timestamp::hex(&imprint), nonce },
        );
        for tsa in tsas {
            let tx = self.stamp_tx.clone();
            let server_id = server_id.to_string();
            std::thread::spawn(move || {
                let result = timestamp::fetch_rfc3161(&tsa, &imprint).map_err(|e| e.to_string());
                let _ = tx.send(StampResult { server_id, imprint, tsa: tsa.name, result });
            });
        }
    }

    /// Carimbo de uma TSA chegou: anexa e repassa aos membros
    pub(super) fn on_stamp_result(&mut self, result: StampResult) {
        let StampResult { server_id, imprint, tsa, result } = result;
        match result {
            Ok(stamp) => {
                let now = super::now_secs();
                let before = self.my_status(&server_id, now);
                let events = self.servers.attach_stamp(&server_id, &imprint, &stamp, now);
                self.publish_server_message(&server_id, &ServerMessage::Stamp { server_id: server_id.clone(), imprint: timestamp::hex(&imprint), stamp });
                self.notice(ServerNotice::StampObtained { server: self.server_name(&server_id), source: tsa });
                self.process_server_events(&server_id, events, before, now);
            }
            Err(reason) => self.notice(ServerNotice::StampFailed { server: self.server_name(&server_id), tsa, reason }),
        }
    }

    /// Anuncia o grupo MLS da sala atual (se formos o líder determinístico) para convergência
    pub(super) fn announce_mls_group(&mut self) {
        let Some((server_id, channel, room)) = self.active_room() else { return };
        if !self.mls.is_leader(&room) {
            return;
        }
        let Some(epoch) = self.mls.epoch(&room) else { return };
        let Some(leader) = self.mls.leader(&room) else { return };
        let members: Vec<String> = self.mls.members(&room).into_iter().collect();
        self.publish_server_message(&server_id, &ServerMessage::GroupAnnounce { server_id: server_id.clone(), room: channel, epoch, leader, members });
    }

    /// Par desconectou do Swarm: se ele estava no grupo da nossa sala e somos o menor dos demais,
    /// tiramos a folha dele (chave nova)
    pub(super) fn on_peer_disconnected_mls(&mut self, disconnected_pubkey: &str) {
        if let Some((server_id, channel, room)) = self.active_room() {
            if let Ok(Some(commit)) = self.mls.member_left(&room, disconnected_pubkey) {
                self.publish_server_message(&server_id, &ServerMessage::Commit { server_id: server_id.clone(), room: channel, commit });
                self.announce_mls_group();
            }
        }
        self.check_leader_changes();
    }

    /// Pubkey de um par por nick, prefixo da pubkey (6+ caracteres) ou a pubkey completa
    fn resolve_pubkey(&self, query: &str) -> Option<String> {
        if community::is_valid_server_id(query) {
            return Some(query.to_string());
        }
        self.peer_metadata
            .values()
            .find(|(nick, pubkey)| nick.eq_ignore_ascii_case(query) || (query.len() >= 6 && pubkey.starts_with(query)))
            .map(|(_, pubkey)| pubkey.clone())
    }

    /// Ciclo periódico: pede cadeias que faltam, pede acesso, cuida do grupo
    /// cifrado e da manutenção do dono
    pub(super) fn server_sync_tick(&mut self) {
        /// Antecedência do aviso de vencimento da Chave do Servidor
        const ROOT_EXPIRY_WARNING_SECS: u64 = 7 * 86_400;
        // Quem ainda não tem a cadeia pede com espera crescente (não a cada ciclo)
        for id in self.servers.list().filter(|s| !s.has_chain()).map(|s| s.server_id.clone()).collect::<Vec<_>>() {
            if self.chain_request_due(&id) {
                if let Some(request) = self.servers.chain_request(&id) {
                    self.publish_server_message(&id, &request);
                }
            }
        }
        let now = super::now_secs();
        // Pedidos de acesso: inscrições no tópico de pedidos e republicação a cada 10 minutos
        self.sync_access_topics();
        // Grupo cifrado efêmero com líder determinístico (menor pubkey), só da sala em que o usuário
        // está: estar online (ou no mesmo servidor) não basta para participar ou liderar. O dono não
        // precisa estar online.
        if let Some((id, channel, room)) = self.active_room().filter(|(id, _, _)| self.participating(id, now)) {
            if self.mls.has_group(&room) {
                if let Ok(Some(commit)) = e2ee::enforce_membership(&mut self.mls, &self.servers, &id, &channel, now) {
                    self.publish_server_message(&id, &commit);
                }
                if self.mls.is_leader(&room) {
                    if self.mls.needs_periodic_rotation(&room, e2ee::DEFAULT_KEY_ROTATION_INTERVAL) {
                        if let Ok(commit) = self.mls.rotate_key(&room) {
                            self.publish_server_message(&id, &ServerMessage::Commit { server_id: id.clone(), room: channel.clone(), commit });
                        }
                    }
                    self.announce_mls_group();
                }
            } else {
                // Ainda sem grupo: se já pedimos entrada há >= 5s e ninguém respondeu com Welcome,
                // criamos o grupo da sala (somos os primeiros nela) e anunciamos.
                let waited_enough = self.last_key_package.get(&room).is_some_and(|t| t.elapsed() >= Duration::from_secs(5));
                if waited_enough {
                    let _ = self.mls.create_group(&room);
                    self.announce_mls_group();
                } else if self.last_key_package.get(&room).is_none_or(|t| t.elapsed() >= Duration::from_secs(10))
                    && !self.request_group_key(&id, &channel)
                {
                    // Ninguém inscrito no tópico de controle: cria o grupo imediatamente
                    let _ = self.mls.create_group(&room);
                }
            }
        }
        self.check_leader_changes();
        // Renúncias de servidores dos quais saímos: alguns reenvios na primeira hora (esforço só;
        // garantir a revogação é papel do servidor)
        for (server_id, message) in self.servers.pending_renounces(now) {
            self.publish_server_message(&server_id, &message);
        }
        // Chave do Servidor deste nó perto de vencer: avisa uma vez por execução (renovar com /server key renew)
        let expiring: Vec<(String, u64)> = self
            .servers
            .list()
            .filter(|s| s.is_owner() && s.has_chain())
            .map(|s| (s.server_id.clone(), s.chain().state().root_expires_at()))
            .filter(|(id, expires_at)| *expires_at <= now + ROOT_EXPIRY_WARNING_SECS && !self.root_expiry_warned.contains(id))
            .collect();
        for (id, expires_at) in expiring {
            self.root_expiry_warned.insert(id.clone());
            self.notice(ServerNotice::RootExpiring { server: self.server_name(&id), expires_at });
        }
        // Consolidação periódica (quem tem a permissão) e eventos da fila ainda sem carimbo: pede de novo
        for id in self.servers.list().map(|s| s.server_id.clone()).collect::<Vec<_>>() {
            if let Some(submitted) = self.servers.maintenance(&id, &self.identity, now) {
                self.request_stamps(&id, submitted.imprint);
            }
            let waiting: Vec<(String, [u8; 32])> =
                self.servers.get(&id).map(|s| s.outbox().map(|e| (e.id(), e.imprint())).collect()).unwrap_or_default();
            for (event_id, imprint) in waiting {
                let due = self.outbox_retry.get(&event_id).is_none_or(|t| t.elapsed() >= Duration::from_secs(60));
                if due {
                    self.outbox_retry.insert(event_id, std::time::Instant::now());
                    self.request_stamps(&id, imprint);
                }
            }
        }
    }

    /// Entra (ou volta) num servidor pelo id. Sem a cadeia ainda, pede aos membros e entra quando chegar.
    fn join_server(&mut self, query: &str) {
        let mut parts = query.split_whitespace();
        let server_id = parts.next().unwrap_or(query);
        let token = parts.next();
        if let Err(e) = self.servers.join(server_id) {
            return self.error(CoreError::Server(e.to_string()));
        }
        if let Some(token) = token {
            if let Some(passport) = crate::community::ServerPassport::from_token(token) {
                let my_pk = self.my_pubkey();
                let now = super::now_secs();
                self.servers.accept_my_passport(server_id, &my_pk, &passport, now);
                let _ = self.servers.persist(server_id);
            }
        }
        self.follow_server(server_id);
        if self.servers.get(server_id).is_some_and(|s| s.has_chain()) {
            self.enter_server(server_id.to_string());
        } else {
            self.pending_switch = Some(server_id.to_string());
            self.node.dht_find(server_dht_key(server_id));
            // Entrar de novo pelo comando recomeça a espera do pedido de cadeia
            self.reset_chain_backoff(server_id);
            if self.chain_request_due(server_id) {
                if let Some(request) = self.servers.chain_request(server_id) {
                    self.publish_server_message(server_id, &request);
                }
            }
            self.notice(ServerNotice::Searching { id: server_id.to_string() });
        }
        // Sem passaporte: entra no tópico de pedidos e pede acesso uma vez
        self.sync_access_topics();
    }

    /// Convite com passaporte embutido: só vale se o passaporte for deste nó (em mensagem pública,
    /// o token de outra pessoa não pode nos fazer passar a acompanhar um servidor)
    pub(super) fn accept_invite_passport(&mut self, server_id: &str, passport: &crate::community::ServerPassport) -> bool {
        let me = self.my_pubkey();
        if passport.body.holder != me || passport.body.server_id != server_id {
            return false;
        }
        if self.servers.join(server_id).is_err() {
            return false;
        }
        self.servers.accept_my_passport(server_id, &me, passport, super::now_secs())
    }

    /// Publica uma alteração bem-sucedida e atualiza o espaço
    /// Evento de governança criado: pede o carimbo (entra no registro e é publicado quando chegar)
    fn publish_change(&mut self, id: &str, result: Result<Submitted, CommunityError>, change: ServerChange) {
        match result {
            Ok(submitted) => {
                // O aviso sai quando o evento for aplicado (com o carimbo)
                self.pending_changes.insert(submitted.event_id.clone(), change);
                self.request_stamps(id, submitted.imprint);
            }
            Err(e) => self.error(CoreError::Server(e.to_string())),
        }
    }

    pub(super) fn server_name(&self, id: &str) -> String {
        self.servers.get(id).map(|s| s.name()).unwrap_or_else(|| community::short_id(id).to_string())
    }

    /// Emite um passaporte (pela chave do servidor ou pelo nosso passaporte), entrega ao titular e
    /// pede carimbo de tempo para ele
    fn issue_and_offer(&mut self, id: &str, target_pk: &str, permissions: Vec<PassportPermission>, duration: Option<u64>) -> Result<(), CommunityError> {
        let now = super::now_secs();
        let passport = self.servers.issue_passport(id, &self.identity, target_pk, permissions, duration, now)?;
        if let Some(server) = self.servers.get_mut(id) {
            server.remember_issued(&passport, now);
        }
        let _ = self.servers.persist(id);
        self.publish_server_message(id, &ServerMessage::PassportOffer { server_id: id.to_string(), target: target_pk.to_string(), passport: passport.clone() });
        self.request_stamps(id, passport.imprint());
        Ok(())
    }

    pub(super) fn run_server_command(&mut self, command: ServerCommand) {
        let now = super::now_secs();
        let current = self.active.server_id().map(str::to_string);
        // Comandos que só fazem sentido dentro de um servidor
        macro_rules! need_server {
            () => {
                match current.clone() {
                    Some(id) => id,
                    None => return self.error(CoreError::InLobby),
                }
            };
        }
        macro_rules! need_peer {
            ($target:expr) => {
                match self.resolve_pubkey(&$target) {
                    Some(pubkey) => pubkey,
                    None => return self.error(CoreError::PeerNotFound($target.to_string())),
                }
            };
        }

        match command {
            ServerCommand::Help => self.notice(ServerNotice::Help),
            ServerCommand::Create(name) => match self.servers.create(&name, &self.my_pubkey(), now) {
                Ok(id) => {
                    self.follow_server(&id);
                    self.notice(ServerNotice::Created { id: id.clone(), name });
                    // Ao entrar no canal padrão, o grupo cifrado da sala é criado (somos os primeiros)
                    self.enter_server(id);
                }
                Err(e) => self.error(CoreError::Server(e.to_string())),
            },
            ServerCommand::Join(id) => self.join_server(id.trim()),
            ServerCommand::Accept => match self.last_invite.clone() {
                Some(id) => self.join_server(&id),
                None => self.error(CoreError::NoInvite),
            },
            ServerCommand::Leave => {
                let id = need_server!();
                let name = self.server_name(&id);
                let was_owner = self.servers.get(&id).is_some_and(|s| s.is_owner());
                if self.active.server_id() == Some(id.as_str()) {
                    self.leave_room_group();
                }
                // Sair renuncia ao passaporte (exceto o dono); publicado quando o carimbo chegar
                if let Some((imprint, tsas)) = self.servers.leave_renouncing(&id, &self.identity, now) {
                    self.request_stamps_with(&id, imprint, tsas);
                }
                let gossipsub = &mut self.node.swarm.behaviour_mut().gossipsub;
                let _ = gossipsub.unsubscribe(&IdentTopic::new(server_control_topic(&id)));
                let _ = gossipsub.unsubscribe(&IdentTopic::new(community::screen_topic(&Space::Server(id.clone()))));
                self.enter_channel(Space::Lobby, "geral".to_string());
                self.notice(ServerNotice::Left { name, was_owner });
            }
            ServerCommand::List => {
                let me = self.my_pubkey();
                let servers = self
                    .servers
                    .list()
                    .map(|s| ServerListEntry {
                        id: s.server_id.clone(),
                        name: s.name(),
                        current: current.as_deref() == Some(s.server_id.as_str()),
                        owner: s.is_owner(),
                        moderator: !s.is_owner() && s.has_chain() && s.is_moderator(&me, now),
                        pending: !s.has_chain(),
                        closed: s.has_chain() && s.chain().state().closed,
                        banned: s.has_chain() && s.is_banned(&me, now),
                    })
                    .collect();
                self.notice(ServerNotice::List { lobby_current: current.is_none(), servers });
            }
            ServerCommand::Info => {
                let id = need_server!();
                let Some(server) = self.servers.get(&id) else { return };
                let state = server.effective_state(now);
                let me = self.my_pubkey();
                let role = if server.is_owner() || state.is_owner_key(&me) {
                    Role::Owner
                } else if server.is_moderator(&me, now) {
                    Role::Moderator
                } else {
                    Role::Member
                };
                let info = ServerInfo {
                    id: id.clone(),
                    name: server.name(),
                    safety_number: crate::identity::safety_number(&id),
                    mls_leader: self.active_room().and_then(|(_, _, room)| self.mls.leader(&room)).map(|pk| self.nick_for(&pk)),
                    mls_epoch: self.active_room().and_then(|(_, _, room)| self.mls.epoch(&room)),
                    height: server.chain().events().count() as u64,
                    updated_at: state.last_event.as_ref().map(|(_, at)| *at),
                    channels: server.channels().into_iter().map(|c| ChannelInfo { voice: c.channel_type == ChannelType::Voice, name: c.name }).collect(),
                    role,
                    closed: state.closed,
                    passports_known: server.known_passports(),
                    moderators: server
                        .moderators(now)
                        .iter()
                        .map(|(pk, perms, until)| (self.nick_for(pk), perms.iter().map(|p| format!("{:?}", p)).collect(), *until))
                        .collect(),
                    bans: state.active_bans(now).iter().map(|(pk, ban)| (self.nick_for(pk), ban.until, self.nick_for(&ban.by))).collect(),
                    tsas: state.timestamp_policy.tsas.iter().map(|t| (t.name.clone(), t.url.clone())).collect(),
                    passport_validity_secs: state.passport_validity_secs,
                    renewal_window_secs: state.renewal_window_secs,
                    pending_actions: server.outbox().count(),
                };
                self.notice(ServerNotice::Info(info));
            }
            ServerCommand::History => {
                let id = need_server!();
                let history = self.servers.history(&id);
                self.notice(ServerNotice::History(history));
            }
            ServerCommand::Bans => {
                let id = need_server!();
                let name = self.server_name(&id);
                let bans: Vec<BanEntry> = if let Some(server) = self.servers.get(&id) {
                    if server.has_chain() {
                        server
                            .chain()
                            .state()
                            .active_bans(now)
                            .into_iter()
                            .map(|(pk, b)| BanEntry {
                                target: pk.clone(),
                                target_nick: self.nick_for(pk),
                                until: b.until,
                                reason: b.reason.clone(),
                                by: self.nick_for(&b.by),
                            })
                            .collect()
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };
                self.notice(ServerNotice::Bans { server: name, bans });
            }
            ServerCommand::Switch(query) => {
                if query.eq_ignore_ascii_case("lobby") {
                    return self.enter_channel(Space::Lobby, "geral".to_string());
                }
                match self.servers.find(&query).map(|s| (s.server_id.clone(), s.has_chain())) {
                    Some((id, true)) => self.enter_server(id),
                    Some((id, false)) => {
                        self.pending_switch = Some(id.clone());
                        self.notice(ServerNotice::WaitingConfig { id });
                    }
                    None => self.error(CoreError::ServerNotFound(query)),
                }
            }
            ServerCommand::Invite { target, server_id } => {
                let id = match server_id {
                    Some(id) => id,
                    None => need_server!(),
                };
                let name = self.server_name(&id);
                match target {
                    Some(target_nick) => {
                        let target_pk = need_peer!(target_nick);
                        let is_closed = self.servers.get(&id).is_some_and(|s| s.has_chain() && s.chain().state().closed);
                        let can_issue = self.servers.get(&id).is_some_and(|s| {
                            s.is_owner() || s.my_passport().is_some_and(|p| p.allows(PassportPermission::IssueMember))
                        });
                        let passport_token = if is_closed && can_issue {
                            let validity = self.servers.get(&id).map_or(0, |s| s.chain().state().passport_validity_secs).max(3600);
                            match self.servers.issue_passport(&id, &self.identity, &target_pk, PassportPermission::member(), Some(validity), now) {
                                Ok(passport) => {
                                    if let Some(s) = self.servers.get_mut(&id) {
                                        s.remember_issued(&passport, now);
                                    }
                                    let _ = self.servers.persist(&id);
                                    self.publish_server_message(&id, &ServerMessage::PassportOffer {
                                        server_id: id.clone(),
                                        target: target_pk.clone(),
                                        passport: passport.clone(),
                                    });
                                    self.request_stamps(&id, passport.imprint());
                                    Some(passport.to_token())
                                }
                                Err(e) => {
                                    tracing::warn!("Não foi possível emitir passaporte automático: {}", e);
                                    None
                                }
                            }
                        } else {
                            None
                        };

                        let text = match passport_token {
                            Some(token) => format!("📨 Convite para o servidor '{}': /server join {} {}", name, id, token),
                            None => format!("📨 Convite para o servidor '{}': /server join {}", name, id),
                        };
                        self.send_dm(&target_pk, &text, None);
                        self.notice(ServerNotice::InviteSent { server: name });
                    }
                    None => {
                        let invite = ChatMessage::new_signed(&self.identity, "geral", &invite_text(&name, &id), now);
                        let lobby = IdentTopic::new(community::channel_topic(&Space::Lobby, "geral"));
                        let sent = self.publish_gossip(lobby, crate::wire::encode(&invite)).is_ok();
                        self.notice(if sent { ServerNotice::InviteSent { server: name } } else { ServerNotice::InviteManual { id: id.clone() } });
                        if self.servers.get(&id).is_some_and(|s| s.chain().state().closed) {
                            self.notice(ServerNotice::InviteNeedsPassport);
                        }
                    }
                }
            }
            ServerCommand::AddChannel { name, voice } => {
                let id = need_server!();
                let kind = if voice { ChannelType::Voice } else { ChannelType::Text };
                let result = self.servers.add_channel(&id, &self.identity, &name, kind, now);
                self.publish_change(&id, result, ServerChange::ChannelAdded { name, voice });
            }
            ServerCommand::RemoveChannel(name) => {
                let id = need_server!();
                let result = self.servers.remove_channel(&id, &self.identity, &name, now);
                self.publish_change(&id, result, ServerChange::ChannelRemoved(name));
            }
            ServerCommand::AddModerator { target, permissions } => {
                let id = need_server!();
                let pubkey = need_peer!(target);
                let validity_secs = self.servers.get(&id).map_or(0, |s| s.chain().state().passport_validity_secs);
                let who = self.nick_for(&pubkey);
                let mut perms = permissions.unwrap_or_else(PassportPermission::default_moderator);
                if !perms.is_empty() && !perms.contains(&PassportPermission::EnterServer) {
                    perms.insert(0, PassportPermission::EnterServer);
                }
                match self.issue_and_offer(&id, &pubkey, perms, None) {
                    Ok(()) => self.notice(ServerNotice::Changed { server: self.server_name(&id), change: ServerChange::ModeratorAdded { who, validity_secs } }),
                    Err(e) => self.error(CoreError::Server(e.to_string())),
                }
            }
            ServerCommand::RemoveModerator(target) => {
                let id = need_server!();
                let pubkey = need_peer!(target);
                let result = self.servers.remove_moderator(&id, &self.identity, &pubkey, now);
                let who = self.nick_for(&pubkey);
                self.publish_change(&id, result, ServerChange::ModeratorRemoved { who });
            }
            ServerCommand::Close | ServerCommand::Open => {
                let id = need_server!();
                let closing = matches!(command, ServerCommand::Close);
                let result = self.servers.set_closed(&id, &self.identity, closing, now);
                self.publish_change(&id, result, if closing { ServerChange::Closed } else { ServerChange::Opened });
            }
            ServerCommand::Policy { validity, renewal_window } => {
                let id = need_server!();
                let result = self.servers.set_passport_policy(&id, &self.identity, validity, renewal_window, now);
                self.publish_change(&id, result, ServerChange::Policy { validity_secs: validity, renewal_window_secs: renewal_window });
            }
            ServerCommand::AddTsa { name, url, public_key_b64 } => {
                let id = need_server!();
                let Ok(spki_der) = base64::engine::general_purpose::STANDARD.decode(public_key_b64.trim()) else {
                    return self.error(CoreError::Server("Chave pública da TSA deve estar em base64 (SubjectPublicKeyInfo DER)".into()));
                };
                let result = self.servers.add_tsa(&id, &self.identity, TrustedTsa { name: name.clone(), url, spki_der }, now);
                self.publish_change(&id, result, ServerChange::TsaAdded(name));
            }
            ServerCommand::RemoveTsa(name) => {
                let id = need_server!();
                let result = self.servers.remove_tsa(&id, &self.identity, &name, now);
                self.publish_change(&id, result, ServerChange::TsaRemoved(name));
            }
            ServerCommand::Ban { target, duration, reason } => self.moderate(ModKind::Ban { until: duration.map(|d| now + d) }, &target, &reason),
            ServerCommand::Unban(target) => self.moderate(ModKind::Unban, &target, ""),
            ServerCommand::AccessPow(bits) => {
                let id = need_server!();
                let result = self.servers.set_access_pow(&id, &self.identity, bits, now);
                self.publish_change(&id, result, ServerChange::AccessPow(bits));
            }
            ServerCommand::Requests => {
                need_server!();
                self.show_access_requests();
            }
            ServerCommand::DismissRequest(target) => {
                let id = need_server!();
                let pubkey = self.resolve_pubkey(&target).unwrap_or(target);
                self.dismiss_access_request(&id, &pubkey);
            }
            ServerCommand::Revoke(target) => {
                let id = need_server!();
                let pubkey = need_peer!(target);
                let Some(serial) = self.servers.get(&id).and_then(|s| s.passport_of(&pubkey)).map(|p| p.body.serial.clone()) else {
                    return self.error(CoreError::Server("Nenhum passaporte conhecido desse participante".into()));
                };
                self.moderate(ModKind::Revoke { serial }, &pubkey, "");
            }
            ServerCommand::RotateKey => {
                let id = need_server!();
                let Some((_, channel, room)) = self.active_room() else { return };
                match self.mls.rotate_key(&room) {
                    Ok(commit) => {
                        self.publish_server_message(&id, &ServerMessage::Commit { server_id: id.clone(), room: channel, commit });
                        self.announce_mls_group();
                        let epoch = self.mls.epoch(&room).unwrap_or(0);
                        self.notice(ServerNotice::KeyRotated { server: self.server_name(&id), epoch });
                    }
                    Err(e) => self.error(CoreError::Server(e.to_string())),
                }
            }
            ServerCommand::IssuePassport { target, moderator, duration } => {
                let id = need_server!();
                let target_pk = need_peer!(target);
                let perms = if moderator { PassportPermission::default_moderator() } else { PassportPermission::member() };
                match self.issue_and_offer(&id, &target_pk, perms, duration) {
                    Ok(()) => self.notice(ServerNotice::PassportUpdated { server: self.server_name(&id) }),
                    Err(e) => self.error(CoreError::Server(e.to_string())),
                }
            }
            ServerCommand::ShowPassport => {
                let id = need_server!();
                let Some(server) = self.servers.get(&id) else { return };
                if let Some(p) = server.my_passport() {
                    let perms = p.body.permissions.iter().map(|p| format!("{:?}", p)).collect();
                    self.notice(ServerNotice::PassportInfo {
                        server: self.server_name(&id),
                        holder: p.body.holder.clone(),
                        issuer: p.body.issuer.clone(),
                        chain_depth: p.chain_depth(),
                        stamps: p.stamps.len(),
                        expires_at: p.effective_expires_at(),
                        permissions: perms,
                    });
                } else {
                    self.error(CoreError::Server("Você ainda não possui um passaporte registrado neste servidor".into()));
                }
            }
            ServerCommand::KeyShow => {
                let id = need_server!();
                let Some(server) = self.servers.get(&id).filter(|s| s.has_chain()) else { return };
                let roots = server
                    .chain()
                    .state()
                    .roots
                    .iter()
                    .map(|r| (r.pubkey.clone(), r.since, r.until, r.expires_at))
                    .collect();
                let mine = server.is_owner();
                self.notice(ServerNotice::KeyChain { server: self.server_name(&id), roots, mine });
            }
            ServerCommand::KeyRenew => {
                let id = need_server!();
                match self.servers.renew_root(&id, now) {
                    Ok(submitted) => {
                        self.request_stamps(&id, submitted.imprint);
                        self.notice(ServerNotice::KeyLinkRequested { server: self.server_name(&id), transfer: false });
                    }
                    Err(e) => self.error(CoreError::Server(e.to_string())),
                }
            }
            ServerCommand::KeyTransfer(target) => {
                let id = need_server!();
                let pubkey = need_peer!(target);
                match self.servers.offer_transfer(&id, &self.identity, &pubkey) {
                    Ok(offer) => {
                        self.publish_server_message(&id, &offer);
                        self.notice(ServerNotice::TransferOffered { server: self.server_name(&id), target: self.nick_for(&pubkey) });
                    }
                    Err(e) => self.error(CoreError::Server(e.to_string())),
                }
            }
            ServerCommand::KeyAccept => {
                let Some((id, offer)) = self.pending_transfer_offer.take() else {
                    return self.error(CoreError::Server("Nenhuma proposta de transferência pendente".into()));
                };
                match self.servers.accept_transfer_offer(&id, &self.identity, &offer, now) {
                    Ok(accept) => {
                        self.publish_server_message(&id, &accept);
                        self.notice(ServerNotice::TransferAccepted { server: self.server_name(&id) });
                    }
                    Err(e) => self.error(CoreError::Server(e.to_string())),
                }
            }
            ServerCommand::FlattenPassport => {
                let id = need_server!();
                let Some(server) = self.servers.get(&id) else { return };
                if let Some(p) = server.my_passport().cloned() {
                    if p.chain_depth() > 1 {
                        self.publish_server_message(&id, &ServerMessage::FlattenRequest { server_id: id.clone(), passport: p });
                    }
                    self.notice(ServerNotice::PassportUpdated { server: self.server_name(&id) });
                } else {
                    self.error(CoreError::Server("Você não possui passaporte neste servidor".into()));
                }
            }
        }
    }

    /// Ban, desban e revogação: evento assinado com o nosso passaporte, publicado quando chegar o
    /// carimbo de tempo
    fn moderate(&mut self, kind: ModKind, target: &str, reason: &str) {
        let Some(id) = self.active.server_id().map(str::to_string) else { return self.error(CoreError::InLobby) };
        let Some(pubkey) = self.resolve_pubkey(target) else { return self.error(CoreError::PeerNotFound(target.to_string())) };
        if pubkey == self.my_pubkey() {
            return self.error(CoreError::SelfModeration);
        }
        let now = super::now_secs();
        let who = self.nick_for(&pubkey);
        match self.servers.moderate(&id, &self.identity, kind.clone(), &pubkey, reason, now) {
            Ok(submitted) => {
                self.request_stamps(&id, submitted.imprint);
                self.notice(ServerNotice::Moderated { server: self.server_name(&id), target: who, kind, at: now });
            }
            Err(e) => self.error(CoreError::Server(e.to_string())),
        }
    }

    /// Mensagem do tópico de controle de um servidor
    pub(super) fn handle_server_network_message(&mut self, topic_server_id: &str, message: ServerMessage, from_pubkey: Option<&str>) {
        let now = super::now_secs();
        let me = self.my_pubkey();

        // Grupo cifrado (MLS), passaportes e carimbos
        match &message {
            ServerMessage::KeyPackage { server_id, room, key_package, passport } => {
                let Some(from) = from_pubkey else { return };
                // O passaporte serve para o servidor todo, mesmo que o pedido seja de outra sala
                if let (Some(p), Some(server)) = (passport, self.servers.get_mut(server_id)) {
                    if p.body.holder == from && server.learn_passport(p, now) {
                        let _ = self.servers.persist(server_id);
                    }
                }
                if self.room_if_active(server_id, room).is_none() {
                    return;
                }
                match e2ee::admit_from_key_package(&mut self.mls, &self.servers, server_id, room, from, key_package, passport.as_ref(), now) {
                    Ok(messages) => {
                        for m in &messages {
                            self.publish_server_message(server_id, m);
                        }
                        self.announce_mls_group();
                        self.notice(ServerNotice::KeyGranted { to: self.nick_for(from) });
                    }
                    Err(E2eeError::NotOwner | E2eeError::NotInGroup) => {}
                    Err(e) => tracing::debug!("Pedido de entrada no grupo recusado: {}", e),
                }
                return;
            }
            ServerMessage::AccessRequest { server_id, proof } => {
                if let Some(from) = from_pubkey {
                    self.note_access_request(server_id, from, proof.as_ref(), true);
                }
                return;
            }
            ServerMessage::AccessPolicy { server_id, pow_bits, tsas } => {
                self.on_access_policy(server_id, *pow_bits, tsas.clone());
                return;
            }
            // Carimbo de uma semente nossa (prova de trabalho sem TSA): não é para o registro
            ServerMessage::Stamp { imprint, stamp, .. } if self.on_access_stamp(imprint, stamp) => {
                return;
            }
            ServerMessage::GroupLeave { server_id, room } => {
                let (Some(from), Some(group)) = (from_pubkey, self.room_if_active(server_id, room)) else { return };
                if let Ok(Some(commit)) = self.mls.member_left(&group, from) {
                    self.publish_server_message(server_id, &ServerMessage::Commit { server_id: server_id.clone(), room: room.clone(), commit });
                    self.announce_mls_group();
                }
                return;
            }
            ServerMessage::StampRequest { server_id, imprint, nonce } => {
                let Some(from) = from_pubkey.filter(|pk| *pk != me) else { return };
                // Quem ainda não é membro (semente de prova de trabalho): limite de taxa e uma
                // testemunha só, para não virar amplificação
                let member = self.servers.get(server_id).is_some_and(|s| s.is_allowed(from, now));
                if !self.may_stamp_for_stranger(server_id, from) {
                    return;
                }
                if let Some(stamp) = self.servers.witness_stamp(server_id, &self.identity, imprint, nonce, now) {
                    if member {
                        self.publish_server_message(server_id, &stamp);
                    } else {
                        // Quem não é membro está no tópico de pedidos (talvez sem o de controle)
                        let access = IdentTopic::new(community::access_topic(server_id));
                        let _ = self.publish_gossip(access, crate::wire::encode(&stamp));
                    }
                }
                return;
            }
            ServerMessage::Commit { server_id, room, commit } => {
                let Some(group) = self.room_if_active(server_id, room) else { return };
                let Some(server) = self.servers.get(server_id).filter(|s| s.has_chain()) else { return };
                let current_leader = self.mls.leader(&group);
                let outcome = self.mls.process_commit_with_validator(&group, commit, "", |pk| !server.is_excluded(pk, now), |pk| server.is_allowed(pk, now));
                match outcome {
                    Ok(CommitOutcome::Applied { epoch }) => {
                        if let Some(from) = from_pubkey {
                            if current_leader.as_deref() == Some(from) && from != me {
                                let name = self.server_name(server_id);
                                self.notice(ServerNotice::KeyRotated { server: name, epoch });
                            }
                        }
                    }
                    Ok(CommitOutcome::Removed) => self.notice(ServerNotice::RemovedFromGroup { server: self.server_name(server_id) }),
                    // Perdemos algum Commit: descarta e pede entrada de novo se veio de um membro válido
                    Ok(CommitOutcome::OutOfSync)
                        if from_pubkey.is_some_and(|pk| !server.is_excluded(pk, now) && current_leader.as_deref() == Some(pk)) =>
                    {
                        self.mls.drop_group(&group);
                        let _ = self.request_group_key(server_id, room);
                    }
                    Ok(CommitOutcome::OutOfSync) => tracing::debug!("Commit fora de sincronia de não-líder ignorado"),
                    Ok(_) => {}
                    Err(e) => tracing::debug!("Commit MLS inválido: {}", e),
                }
                return;
            }
            ServerMessage::Welcome { server_id, room, target, welcome, member_passports } => {
                if let (true, Some(group)) = (*target == me, self.room_if_active(server_id, room)) {
                    // Passaportes dos membros: com eles validamos o grupo e os Commits seguintes do líder
                    if let Some(server) = self.servers.get_mut(server_id) {
                        for p in member_passports {
                            server.learn_passport(p, now);
                        }
                    }
                    let _ = self.servers.persist(server_id);
                    let Some(server) = self.servers.get(server_id).filter(|s| s.has_chain()) else { return };
                    let had_group = self.mls.has_group(&group);
                    let res = self.mls.join_with_validator(&group, welcome, |sender_pk, members| {
                        server.is_allowed(sender_pk, now) && members.iter().all(|pk| server.is_allowed(pk, now))
                    });
                    match res {
                        Ok(()) => {
                            if !had_group {
                                self.notice(ServerNotice::KeyReceived { server: self.server_name(server_id) });
                            }
                            let needs_flatten = self.servers.get(server_id).and_then(|s| s.my_passport()).map(|p| (p.chain_depth() > 1, p.clone()));
                            if let Some((true, my_p)) = needs_flatten {
                                self.publish_server_message(server_id, &ServerMessage::FlattenRequest { server_id: server_id.clone(), passport: my_p });
                            }
                        }
                        Err(e) => tracing::debug!("Welcome MLS recusado: {}", e),
                    }
                }
                return;
            }
            ServerMessage::PassportOffer { server_id, target, passport } => {
                if *target == me {
                    let was_moderator = self.servers.get(server_id).is_some_and(|s| s.has_chain() && s.is_moderator(&me, now));
                    if self.servers.accept_my_passport(server_id, &me, passport, now) {
                        // Recebeu passaporte: sai do tópico de pedidos
                        self.sync_access_topics();
                        self.notice(ServerNotice::PassportUpdated { server: self.server_name(server_id) });
                        let server = self.servers.get(server_id);
                        let moderator = server.is_some_and(|s| s.has_chain() && s.is_moderator(&me, now));
                        if moderator != was_moderator && !server.is_some_and(|s| s.is_owner()) {
                            self.notice(ServerNotice::Role { server: self.server_name(server_id), moderator });
                        }
                        if let Some(request) = self.servers.chain_request(server_id).filter(|_| !self.servers.get(server_id).is_some_and(|s| s.has_chain())) {
                            self.publish_server_message(server_id, &request);
                        }
                        if self.active.server_id() == Some(server_id.as_str()) {
                            self.enter_server(server_id.clone());
                        }
                    }
                } else if let Some(server) = self.servers.get_mut(server_id) {
                    if server.learn_passport(passport, now) {
                        let _ = self.servers.persist(server_id);
                    }
                }
                return;
            }
            ServerMessage::KeyTransferOffer { server_id, target, .. } => {
                if *target == me {
                    if let Some(from) = from_pubkey {
                        self.pending_transfer_offer = Some((server_id.clone(), message.clone()));
                        self.notice(ServerNotice::TransferOfferReceived { server: self.server_name(server_id), from: self.nick_for(from) });
                    }
                }
                return;
            }
            ServerMessage::KeyTransferAccept { server_id, body, new_key_signature } => {
                if self.servers.get(server_id).is_some_and(|s| s.is_owner()) {
                    match self.servers.complete_transfer(server_id, &self.identity, body.clone(), new_key_signature.clone()) {
                        Ok(submitted) => {
                            self.request_stamps(server_id, submitted.imprint);
                            self.notice(ServerNotice::KeyLinkRequested { server: self.server_name(server_id), transfer: true });
                        }
                        Err(e) => self.error(CoreError::Server(e.to_string())),
                    }
                }
                return;
            }
            ServerMessage::FlattenRequest { server_id, passport } => {
                if let Some(server) = self.servers.get(server_id) {
                    let flattened = if let Some(owner_key) = server.owner_key() {
                        passport.flatten_with_server_key(owner_key, now).ok()
                    } else if let Some(my_p) = server.my_passport() {
                        let can_issue = my_p.allows(PassportPermission::IssueMember) || my_p.allows(PassportPermission::Delegate);
                        can_issue.then(|| passport.flatten_with_superior(&self.identity, my_p, now).ok()).flatten()
                    } else {
                        None
                    };
                    if let Some(flattened) = flattened.filter(|p| server.effective_state(now).verify_passport(p, now).is_ok()) {
                        let imprint = flattened.imprint();
                        self.publish_server_message(server_id, &ServerMessage::PassportOffer {
                            server_id: server_id.clone(),
                            target: passport.body.holder.clone(),
                            passport: flattened,
                        });
                        self.request_stamps(server_id, imprint);
                    }
                }
                return;
            }
            ServerMessage::GroupAnnounce { server_id, room, epoch, leader, members } => {
                let (Some(from), Some(group)) = (from_pubkey, self.room_if_active(server_id, room)) else { return };
                let Some(server) = self.servers.get(server_id).filter(|s| s.has_chain()) else { return };
                if from != leader || !server.is_allowed(&me, now) || server.is_excluded(from, now) {
                    return;
                }
                let candidate_set: std::collections::BTreeSet<String> =
                    members.iter().filter(|pk| !server.is_excluded(pk, now)).cloned().collect();
                if candidate_set.iter().min().map(String::as_str) != Some(leader.as_str()) {
                    return;
                }
                let current_set = self.mls.members(&group);
                // Membro do nosso grupo anunciando um grupo sem nós e de época anterior à nossa (recém-criado):
                // perdeu o estado, saiu e voltou sem ninguém perceber (ex.: Ctrl+C). Uma remoção legítima
                // chega com época maior. O menor dos demais tira a folha velha e anuncia o grupo, e quem
                // voltou converge para ele (grupo maior vence).
                let stale_epoch = self.mls.epoch(&group).is_some_and(|ours| *epoch < ours);
                if current_set.contains(from)
                    && !candidate_set.contains(&me)
                    && stale_epoch
                    && !server.is_excluded(&me, now)
                    && self.mls.is_leader_without(&group, from)
                {
                    if let Ok(Some(commit)) = self.mls.remove_members_unchecked(&group, &[from.to_string()]) {
                        self.publish_server_message(server_id, &ServerMessage::Commit { server_id: server_id.clone(), room: room.clone(), commit });
                    }
                    self.announce_mls_group();
                    return;
                }
                // Se não estamos no grupo anunciado (ou se nosso grupo local perder na convergência),
                // enviamos KeyPackage para convergir para o grupo vencedor!
                // Pedimos entrada há pouco e ainda não temos grupo: o Welcome está a caminho (o anúncio pode
                // chegar antes dele, ou ser anterior à nossa admissão). Pedir de novo faria o líder readmitir à toa.
                let welcome_on_the_way = !self.mls.has_group(&group)
                    && self.last_key_package.get(&group).is_some_and(|t| t.elapsed() < Duration::from_secs(5));
                if welcome_on_the_way {
                    return;
                }
                if !current_set.contains(&me) || (!candidate_set.contains(&me) && e2ee::should_adopt_group(&current_set, &candidate_set)) {
                    // O OpenMLS não aceita o Welcome com outro grupo de mesmo id guardado: o grupo
                    // local (que perdeu a convergência) sai antes de pedirmos a entrada no vencedor
                    self.mls.drop_group(&group);
                    let _ = self.request_group_key(server_id, room);
                }
                return;
            }
            _ => {}
        }
        let before = self.my_status(topic_server_id, now);
        let events = self.servers.handle_message(message, from_pubkey, now);
        self.process_server_events(topic_server_id, events, before, now);
    }

    /// (banido, moderador) deste usuário no servidor, para avisar quando mudar
    fn my_status(&self, server_id: &str, now: u64) -> Option<(bool, bool)> {
        let me = self.my_pubkey();
        self.servers.get(server_id).map(|s| (s.has_chain() && s.is_banned(&me, now), s.has_chain() && s.is_moderator(&me, now)))
    }

    /// Reage ao que o registro de governança devolveu (sincronização, eventos aplicados, respostas)
    pub(super) fn process_server_events(&mut self, topic_server_id: &str, events: Vec<ServerEvent>, before: Option<(bool, bool)>, now: u64) {
        let me = self.my_pubkey();
        let mut governance_changed = false;
        for event in events {
            governance_changed |= matches!(
                event,
                ServerEvent::ChainUpdated { .. } | ServerEvent::EventApplied { .. } | ServerEvent::StampAttached { .. }
            );
            match event {
                ServerEvent::ChainUpdated { server_id, name, events } => {
                    self.notice(ServerNotice::Synced { id: server_id.clone(), name, height: events as u64 });
                    if self.pending_switch.as_deref() == Some(server_id.as_str()) {
                        self.pending_switch = None;
                        self.enter_server(server_id);
                    } else if self.active.server_id() == Some(server_id.as_str()) {
                        self.refresh_space();
                    }
                }
                ServerEvent::EventApplied { server_id, event, at } => {
                    if let Some(change) = self.pending_changes.remove(&event.id()) {
                        self.refresh_space();
                        self.notice(ServerNotice::Changed { server: self.server_name(&server_id), change });
                    }
                    if let Some((target, kind)) = ModKind::from_entry(&event.body.entry, event.author()) {
                        let reason = match &event.body.entry {
                            community::Entry::Ban { reason, .. } => reason.clone(),
                            _ => String::new(),
                        };
                        self.notice(ServerNotice::ModerationReceived {
                            server: self.server_name(&server_id),
                            by: self.nick_for(event.author()),
                            target: self.nick_for(&target),
                            kind,
                            at,
                            reason,
                        });
                    }
                }
                ServerEvent::EventRejected { server_id, entry, reason } => self.notice(ServerNotice::EventRejected {
                    server: self.server_name(&server_id),
                    description: community::describe_entry(&entry),
                    reason: reason.to_string(),
                }),
                ServerEvent::Reply { server_id, messages } => {
                    for m in &messages {
                        self.publish_server_message(&server_id, m);
                    }
                }
                ServerEvent::OwnershipChanged { server_id } => {
                    if let Some(server) = self.servers.get(&server_id) {
                        let (owner, expires_at) = (server.is_owner(), server.chain().state().root_expires_at());
                        self.root_expiry_warned.remove(&server_id);
                        self.notice(ServerNotice::OwnershipChanged { server: self.server_name(&server_id), owner, expires_at });
                    }
                }
                ServerEvent::StampAttached { server_id } => tracing::debug!("Carimbo de tempo anexado em {}", community::short_id(&server_id)),
                ServerEvent::Ignored(reason) => tracing::debug!("Mensagem de servidor ignorada: {}", reason),
            }
        }

        // Ban, revogação ou ação nova: o líder tira do grupo cifrado na hora quem perdeu o direito
        if governance_changed {
            self.enforce_now(topic_server_id);
            // Cadeia ou moderação mudou: quem pede ou quem emite pode ter mudado
            self.sync_access_topics();
            if self.active.server_id() == Some(topic_server_id) {
                self.publish_channel_members();
                self.emit_access_requests();
            }
        }

        // Mudanças que afetam este usuário
        let (Some((was_banned, was_moderator)), Some(server)) = (before, self.servers.get(topic_server_id)) else { return };
        let name = server.name();
        let banned = server.has_chain() && server.is_banned(&me, now);
        let moderator = server.has_chain() && server.is_moderator(&me, now);
        let owner = server.is_owner();
        if banned != was_banned {
            self.notice(ServerNotice::BanStatus { server: name.clone(), banned });
        }
        if moderator != was_moderator && !owner {
            self.notice(ServerNotice::Role { server: name, moderator });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invite_roundtrip() {
        let id = "ab".repeat(32);
        assert_eq!(parse_invite(&invite_text("Rust Guild", &id)), Some(id.clone()));
        assert_eq!(parse_invite(&format!("entra aí: /server join {} valeu", id)), Some(id));
        assert_eq!(parse_invite("/server join abc"), None, "id curto não é convite");
        assert_eq!(parse_invite("bom dia"), None);
    }
}
