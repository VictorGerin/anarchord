//! Espaços de conversa: o Lobby público e os servidores (comunidades).
//!
//! - **Lobby**: sem dono e sem moderação; qualquer nome vira canal. É onde as pessoas se
//!   encontram pela primeira vez e trocam convites de servidor.
//! - **Servidor**: uma Genesis assinada pela Chave do Servidor e um registro de eventos de
//!   governança ([`chain`]), cada um assinado por quem age com o próprio passaporte ([`passport`])
//!   e carimbado no tempo ([`timestamp`]). Moderadores agem sem o dono online: todos os membros
//!   aplicam as mesmas regras. Os canais de cada servidor ficam num namespace próprio de tópicos.
//!
//! Este módulo contém só lógica (sem rede nem interface): o loop de eventos publica as
//! mensagens que ele devolve e repassa a ele as que chegam.

pub mod access_proof;
pub mod cert;
pub mod chain;
pub mod e2ee;
pub mod keychain;
pub mod passport;
pub mod timestamp;

pub use cert::{format_duration, parse_duration, ModKind, UtcSecs};
pub use chain::{AddResult, BanState, Channel, ChannelType, Entry, Genesis, GovEvent, Rejection, ServerChain, ServerState};
pub use keychain::{KeyLink, KeyLinkBody, KeyLinkKind, RootKey};
pub use passport::{PassportError, PassportPermission, ServerPassport};
pub use timestamp::{PeerTimestampToken, TimestampAttestation, TimestampPolicy, TrustedTsa};

use crate::identity::{hex_decode_32, UserIdentity};
use libp2p::kad;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use thiserror::Error;

const TOPIC_PREFIX: &str = "p2p-anarchord";
/// Eventos por mensagem (cada um leva o passaporte completo do autor; mantém a mensagem bem abaixo de 1 MB)
const EVENTS_PER_MESSAGE: usize = 16;

/// Onde o usuário está conversando
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Space {
    Lobby,
    Server(String),
}

/// Tópico Gossipsub de um canal de texto. No Lobby mantém o formato original
/// (`p2p-anarchord/channel/<canal>`), compatível com nós anteriores.
pub fn channel_topic(space: &Space, channel: &str) -> String {
    match space {
        Space::Lobby => format!("{}/channel/{}", TOPIC_PREFIX, channel),
        Space::Server(id) => format!("{}/server/{}/channel/{}", TOPIC_PREFIX, id, channel),
    }
}

/// Tópico Gossipsub de uma sala de voz
pub fn voice_topic(space: &Space, channel: &str) -> String {
    match space {
        Space::Lobby => format!("{}/voice/{}", TOPIC_PREFIX, channel),
        Space::Server(id) => format!("{}/server/{}/voice/{}", TOPIC_PREFIX, id, channel),
    }
}

/// Tópico de compartilhamento de tela do espaço
pub fn screen_topic(space: &Space) -> String {
    match space {
        Space::Lobby => format!("{}/screens", TOPIC_PREFIX),
        Space::Server(id) => format!("{}/server/{}/screens", TOPIC_PREFIX, id),
    }
}

/// Tópico dos quadros de uma transmissão de tela: só quem assiste se inscreve
pub fn screen_stream_topic(space: &Space, stream_id: &str) -> String {
    format!("{}/{}", screen_topic(space), stream_id)
}

/// Se o tópico é de conteúdo de um servidor (canal, voz ou tela), devolve o id do servidor.
/// Esse conteúdo trafega cifrado com MLS.
pub fn parse_server_content_topic(topic: &str) -> Option<&str> {
    let rest = topic.strip_prefix(TOPIC_PREFIX)?.strip_prefix("/server/")?;
    let (id, tail) = rest.split_at(rest.find('/')?);
    let content = tail.starts_with("/channel/") || tail.starts_with("/voice/") || tail.starts_with("/screens");
    (content && is_valid_server_id(id)).then_some(id)
}

/// Id do grupo cifrado (MLS) de uma sala. Cada canal do servidor tem o próprio grupo, líder e chave:
/// trocar de canal é sair de um grupo e entrar em outro.
pub fn room_id(server_id: &str, channel: &str) -> String {
    format!("{}/{}", server_id, channel)
}

/// Sala de um tópico de conteúdo de servidor (canal de texto ou de voz): (id do servidor, canal).
/// O tópico de telas é do servidor inteiro e não tem sala própria.
pub fn parse_room_topic(topic: &str) -> Option<(&str, &str)> {
    let rest = topic.strip_prefix(TOPIC_PREFIX)?.strip_prefix("/server/")?;
    let (id, channel) = rest.split_once("/channel/").or_else(|| rest.split_once("/voice/"))?;
    (is_valid_server_id(id) && !channel.is_empty()).then_some((id, channel))
}

/// Se o tópico é de um canal de texto de servidor, devolve (id do servidor, canal)
pub fn parse_server_channel_topic(topic: &str) -> Option<(&str, &str)> {
    let rest = topic.strip_prefix(TOPIC_PREFIX)?.strip_prefix("/server/")?;
    let (id, channel) = rest.split_once("/channel/")?;
    is_valid_server_id(id).then_some((id, channel))
}

/// Tópico de controle de um servidor: blocos da cadeia, ações de moderação e pedidos de cadeia
pub fn server_control_topic(server_id: &str) -> String {
    format!("{}/server/{}", TOPIC_PREFIX, server_id)
}

/// Tópico de pedidos de acesso de um servidor: quem quer entrar e quem pode emitir passaporte se
/// inscrevem nele; a própria inscrição é o pedido, e o `AccessRequest` é publicado uma vez
pub fn access_topic(server_id: &str) -> String {
    format!("{}/server/{}/access", TOPIC_PREFIX, server_id)
}

/// Se o tópico é o de pedidos de acesso de um servidor, devolve o id do servidor
pub fn parse_server_access_topic(topic: &str) -> Option<&str> {
    let id = topic.strip_prefix(TOPIC_PREFIX)?.strip_prefix("/server/")?.strip_suffix("/access")?;
    is_valid_server_id(id).then_some(id)
}

/// Se o tópico é o de controle de um servidor, devolve o id do servidor
pub fn parse_server_control_topic(topic: &str) -> Option<&str> {
    let id = topic.strip_prefix(TOPIC_PREFIX)?.strip_prefix("/server/")?;
    is_valid_server_id(id).then_some(id)
}

/// Chave de descoberta do servidor na DHT: membros a anunciam, quem entra procura por ela
pub fn server_dht_key(server_id: &str) -> kad::RecordKey {
    let digest = Sha256::digest(format!("anarchord-server:{}", server_id).as_bytes());
    let mut multihash = Vec::with_capacity(34);
    multihash.extend_from_slice(&[0x12, 0x20]);
    multihash.extend_from_slice(&digest);
    kad::RecordKey::new(&multihash)
}

/// O id de um servidor é a pubkey Ed25519 dele em hex (64 caracteres)
pub fn is_valid_server_id(id: &str) -> bool {
    hex_decode_32(id).is_ok()
}

/// Início do id, para exibição
pub fn short_id(id: &str) -> &str {
    &id[..id.len().min(8)]
}

/// Canais criados junto com um servidor novo
pub fn default_channels() -> Vec<Channel> {
    vec![
        Channel { name: "geral".into(), channel_type: ChannelType::Text },
        Channel { name: "voz".into(), channel_type: ChannelType::Voice },
    ]
}

/// Mensagens trocadas no tópico de controle de um servidor
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ServerMessage {
    /// Genesis e eventos de governança (novos ou em resposta a um inventário)
    Events {
        server_id: String,
        #[serde(default)]
        genesis: Option<Genesis>,
        events: Vec<GovEvent>,
        /// Elos da corrente de chaves (#99)
        #[serde(default)]
        keys: Vec<KeyLink>,
    },
    /// Inventário de quem publica: quem tiver o que falta responde com `Events`.
    /// Em servidor privado só é atendido com passaporte.
    Inventory {
        server_id: String,
        has_genesis: bool,
        have: Vec<String>,
        #[serde(default)]
        passport: Option<ServerPassport>,
    },
    /// Pedido de entrada no grupo cifrado (MLS) da sala `room`: pacote de chave de quem publicou com o passaporte
    KeyPackage {
        server_id: String,
        /// Sala (canal) do grupo cifrado
        room: String,
        #[serde(with = "crate::b64")]
        key_package: Vec<u8>,
        #[serde(default)]
        passport: Option<ServerPassport>,
    },
    /// Commit MLS do líder da sala (adiciona/remove membros ou rotaciona a chave do grupo)
    Commit {
        server_id: String,
        /// Sala (canal) do grupo cifrado
        room: String,
        #[serde(with = "crate::b64")]
        commit: Vec<u8>,
    },
    /// Welcome MLS para quem foi admitido no grupo, com os passaportes dos membros atuais
    /// (quem entra valida o grupo e os Commits seguintes do líder com eles)
    Welcome {
        server_id: String,
        /// Sala (canal) do grupo cifrado
        room: String,
        target: String,
        #[serde(with = "crate::b64")]
        welcome: Vec<u8>,
        #[serde(default)]
        member_passports: Vec<ServerPassport>,
    },
    /// Anúncio do grupo MLS da sala (líder, época e membros) para convergência determinística
    GroupAnnounce {
        server_id: String,
        /// Sala (canal) do grupo cifrado
        room: String,
        epoch: u64,
        leader: String,
        members: Vec<String>,
    },
    /// Oferta/entrega de Passaporte (emissão, renovação ou achatamento de cadeia)
    PassportOffer {
        server_id: String,
        target: String,
        passport: ServerPassport,
    },
    /// Solicitação de Achatamento Oportunista de Cadeia
    FlattenRequest {
        server_id: String,
        passport: ServerPassport,
    },
    /// Quem publica saiu do grupo cifrado da sala (trocou de sala, `/server leave` ou encerramento).
    /// É só um atalho: quem volta sem esse aviso ter chegado é readmitido pelo próprio `KeyPackage`.
    GroupLeave { server_id: String, room: String },
    /// Quem não tem passaporte pede um. Em servidor público, moderadores com `IssueMember`
    /// online emitem automaticamente. Se o servidor exige prova de trabalho, ela vem junto.
    AccessRequest {
        server_id: String,
        #[serde(default)]
        proof: Option<access_proof::AccessProof>,
    },
    /// Resposta a pedido sem prova válida num servidor que a exige: a dificuldade e as autoridades
    /// de tempo aceitas (quem pede ainda não tem o registro para saber)
    AccessPolicy { server_id: String, pow_bits: u8, tsas: Vec<TrustedTsa> },
    /// Quem tem a Chave do Servidor propõe transferi-la a `target` (identidade pessoal). Quem recebe
    /// aceita gerando a chave nova na própria máquina.
    KeyTransferOffer {
        server_id: String,
        target: String,
        /// Identidade pessoal de quem entrega (sai da lista de protegidos)
        previous_owner: String,
        /// Chave em vigor e último elo aceito da corrente de chaves
        key: String,
        previous: String,
    },
    /// Aceitação: o corpo do elo de transferência assinado pela chave nova
    KeyTransferAccept {
        server_id: String,
        body: KeyLinkBody,
        #[serde(with = "crate::b64")]
        new_key_signature: Vec<u8>,
    },
    /// Pedido de carimbo de tempo a testemunhas da rede (só o hash viaja)
    StampRequest { server_id: String, imprint: String, nonce: String },
    /// Carimbo sobre `imprint` (de uma TSA ou de uma testemunha) para anexar ao objeto correspondente
    Stamp { server_id: String, imprint: String, stamp: TimestampAttestation },
}

impl ServerMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::wire::encode(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::wire::WireError> {
        crate::wire::decode_as(bytes)
    }
}

#[derive(Error, Debug)]
pub enum CommunityError {
    #[error("ID de servidor inválido (esperado: 64 caracteres hexadecimais)")]
    InvalidServerId,
    #[error("Você não está nesse servidor")]
    UnknownServer,
    #[error("A configuração desse servidor ainda não chegou; aguarde algum membro online")]
    NoChainYet,
    #[error("Só quem tem a Chave do Servidor pode fazer isso")]
    NotOwner,
    #[error("Seu passaporte não dá essa permissão neste servidor")]
    NotModerator,
    #[error("Você não possui passaporte válido neste servidor")]
    NoPassport,
    #[error("Ação recusada: {0}")]
    Rejected(Rejection),
    #[error("Passaporte recusado: {0}")]
    Passport(#[from] PassportError),
    #[error("Já existe um canal com esse nome")]
    ChannelExists,
    #[error("Canal inexistente")]
    UnknownChannel,
    #[error("Autoridade de tempo inválida: {0}")]
    InvalidTsa(String),
    #[error("Nada a consolidar")]
    NothingToConsolidate,
    #[error("Transferência inválida: {0}")]
    InvalidTransfer(String),
    #[error("{0}")]
    Identity(#[from] crate::identity::IdentityError),
    #[error("Erro de E/S: {0}")]
    Io(#[from] std::io::Error),
    #[error("Erro de serialização: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<Rejection> for CommunityError {
    fn from(rejection: Rejection) -> Self {
        match rejection {
            Rejection::MissingPermission => CommunityError::NotModerator,
            other => CommunityError::Rejected(other),
        }
    }
}

/// Evento criado por este nó, aguardando carimbo para entrar no registro e ser publicado
#[derive(Debug, Clone, PartialEq)]
pub struct Submitted {
    pub event_id: String,
    /// Hash a carimbar (TSAs da política e testemunhas)
    pub imprint: [u8; 32],
}

/// Um servidor que este nó acompanha
pub struct KnownServer {
    pub server_id: String,
    chain: ServerChain,
    /// Chave raiz em vigor (a do servidor, ou a recebida por transferência), se este nó a tem
    owner_key: Option<UserIdentity>,
    /// Chaves de servidor guardadas em disco que ainda não conferem com a raiz (o registro não chegou)
    stored_keys: Vec<UserIdentity>,
    /// Passaporte do nó local neste servidor (emitido pela raiz ou por moderador)
    my_passport: Option<ServerPassport>,
    /// Passaportes que os outros participantes apresentaram (por titular). Só em memória: cada
    /// passaporte fica guardado em disco apenas com o próprio titular, que o reapresenta ao voltar.
    passports: BTreeMap<String, ServerPassport>,
    /// Elos da corrente de chaves deste nó aguardando carimbo de TSA (por id)
    key_outbox: BTreeMap<String, KeyLink>,
    /// Eventos deste nó aguardando carimbo (por id)
    outbox: BTreeMap<String, GovEvent>,
    /// Ids de eventos já avaliados e descartados (não são pedidos de novo)
    discarded: BTreeSet<String>,
}

impl KnownServer {
    fn new(server_id: &str) -> Self {
        Self {
            server_id: server_id.to_string(),
            chain: ServerChain::new(server_id),
            owner_key: None,
            stored_keys: Vec::new(),
            my_passport: None,
            passports: BTreeMap::new(),
            outbox: BTreeMap::new(),
            key_outbox: BTreeMap::new(),
            discarded: BTreeSet::new(),
        }
    }

    pub fn has_chain(&self) -> bool {
        !self.chain.is_empty()
    }

    pub fn chain(&self) -> &ServerChain {
        &self.chain
    }

    pub fn name(&self) -> String {
        if self.has_chain() {
            self.chain.state().name.clone()
        } else {
            format!("(aguardando configuração) {}", short_id(&self.server_id))
        }
    }

    /// Este nó tem a Chave do Servidor em vigor
    pub fn is_owner(&self) -> bool {
        self.owner_key.is_some()
    }

    pub fn owner_key(&self) -> Option<&UserIdentity> {
        self.owner_key.as_ref()
    }

    /// Adota a chave guardada que for a raiz em vigor (após sincronizar ou transferir)
    fn refresh_owner_key(&mut self) {
        if !self.has_chain() {
            return;
        }
        let root = self.chain.state().current_root().to_string();
        if self.owner_key.as_ref().is_some_and(|k| k.public_key_hex() != root) {
            let old = self.owner_key.take().expect("verificado acima");
            self.stored_keys.push(old);
        }
        if self.owner_key.is_none() {
            if let Some(pos) = self.stored_keys.iter().position(|k| k.public_key_hex() == root) {
                self.owner_key = Some(self.stored_keys.remove(pos));
            }
        }
    }

    pub fn my_passport(&self) -> Option<&ServerPassport> {
        self.my_passport.as_ref()
    }

    pub fn set_my_passport(&mut self, passport: ServerPassport) {
        self.passports.insert(passport.body.holder.clone(), passport.clone());
        self.my_passport = Some(passport);
    }

    /// Quantos passaportes de participantes este nó conhece
    pub fn known_passports(&self) -> usize {
        self.passports.len()
    }

    /// Passaporte conhecido de uma pubkey
    pub fn passport_of(&self, pubkey: &str) -> Option<&ServerPassport> {
        self.passports.get(pubkey)
    }

    /// Guarda o passaporte de outro participante se ele for válido e mais novo que o conhecido.
    /// Devolve `true` se mudou algo.
    pub fn learn_passport(&mut self, passport: &ServerPassport, now: UtcSecs) -> bool {
        if !self.has_chain() || self.chain.state().verify_passport(passport, now).is_err() {
            return false;
        }
        let state = self.chain.state();
        let replace = match self.passports.get(&passport.body.holder) {
            None => true,
            Some(known) if known == passport => false,
            Some(known) => {
                state.verify_passport(known, now).is_err()
                    || passport.body.issued_at > known.body.issued_at
                    // Mesmo passaporte com mais carimbos; um diferente emitido no mesmo segundo não substitui
                    || (passport.body.serial == known.body.serial && passport.stamps.len() > known.stamps.len())
            }
        };
        if replace {
            self.passports.insert(passport.body.holder.clone(), passport.clone());
        }
        replace
    }

    /// Guarda um passaporte que este nó acabou de emitir: é o mais recente do titular por definição,
    /// mesmo emitido no mesmo segundo de outro (onde `learn_passport` não sabe desempatar)
    pub fn remember_issued(&mut self, passport: &ServerPassport, now: UtcSecs) -> bool {
        if !self.has_chain() || self.chain.state().verify_passport(passport, now).is_err() {
            return false;
        }
        self.passports.insert(passport.body.holder.clone(), passport.clone());
        true
    }

    pub fn channels(&self) -> Vec<Channel> {
        self.chain.state().channels.clone()
    }

    pub fn has_channel(&self, name: &str, kind: ChannelType) -> bool {
        self.chain.state().channels.iter().any(|c| c.name == name && c.channel_type == kind)
    }

    /// Verifica se existe qualquer canal (texto ou voz) com este nome no servidor
    pub fn has_any_channel(&self, name: &str) -> bool {
        self.chain.state().channels.iter().any(|c| c.name == name)
    }

    /// Primeiro canal de texto (onde o usuário cai ao entrar no servidor)
    pub fn default_text_channel(&self) -> Option<String> {
        self.channels()
            .into_iter()
            .find(|c| c.channel_type == ChannelType::Text)
            .or_else(|| self.channels().into_iter().next())
            .map(|c| c.name)
    }

    /// Eventos deste nó aguardando carimbo
    pub fn outbox(&self) -> impl Iterator<Item = &GovEvent> {
        self.outbox.values()
    }

    /// Estado do servidor (Genesis ou última consolidação mais os eventos aplicados)
    pub fn effective_state(&self, _now: UtcSecs) -> &ServerState {
        self.chain.state()
    }

    /// Deve ficar fora (do grupo cifrado, do chat): banido sem passaporte que o reabilite, ou com
    /// passaporte conhecido inválido. Quem ainda não anunciou passaporte não é excluído por isso.
    pub fn is_excluded(&self, pubkey: &str, now: UtcSecs) -> bool {
        let state = self.chain.state();
        if state.is_owner_key(pubkey) {
            return false;
        }
        match self.passports.get(pubkey) {
            Some(p) => !state.is_allowed_with_passport(pubkey, Some(p), now),
            None => state.is_banned(pubkey, now),
        }
    }

    /// Há ban em vigor sobre a pubkey e nenhum passaporte conhecido que a reabilite
    pub fn is_banned(&self, pubkey: &str, now: UtcSecs) -> bool {
        let state = self.chain.state();
        state.is_banned(pubkey, now) && !state.is_allowed_with_passport(pubkey, self.passports.get(pubkey), now)
    }

    /// Participa: chave do servidor ou passaporte válido conhecido
    pub fn is_allowed(&self, pubkey: &str, now: UtcSecs) -> bool {
        self.chain.state().is_allowed_with_passport(pubkey, self.passports.get(pubkey), now)
    }

    pub fn is_allowed_with_passport(&self, pubkey: &str, passport: Option<&ServerPassport>, now: UtcSecs) -> bool {
        let state = self.chain.state();
        state.is_allowed_with_passport(pubkey, passport, now)
            || state.is_allowed_with_passport(pubkey, self.passports.get(pubkey), now)
    }

    /// Pubkey é moderador agora (passaporte válido com algum poder além de participar)
    pub fn is_moderator(&self, pubkey: &str, now: UtcSecs) -> bool {
        let state = self.chain.state();
        state.is_owner_key(pubkey)
            || self.passports.get(pubkey).is_some_and(|p| p.is_moderator() && state.verify_passport(p, now).is_ok())
    }

    /// Moderadores conhecidos: (pubkey, permissões, expira em)
    pub fn moderators(&self, now: UtcSecs) -> Vec<(String, Vec<PassportPermission>, Option<UtcSecs>)> {
        let state = self.chain.state();
        self.passports
            .values()
            .filter(|p| p.is_moderator() && state.verify_passport(p, now).is_ok())
            .map(|p| (p.body.holder.clone(), p.body.permissions.clone(), p.effective_expires_at()))
            .collect()
    }

    /// Passaporte que este nó usa para agir. Quem tem a Chave do Servidor e ainda não tem um,
    /// emite para a própria identidade pessoal (vitalício, todas as permissões).
    fn acting_passport(&mut self, personal: &UserIdentity, now: UtcSecs) -> Result<ServerPassport, CommunityError> {
        let me = personal.public_key_hex();
        let usable = self
            .my_passport
            .as_ref()
            .filter(|p| p.body.holder == me && self.chain.state().verify_passport(p, now).is_ok())
            .cloned();
        if let Some(passport) = usable {
            return Ok(passport);
        }
        let key = self.owner_key.as_ref().ok_or(CommunityError::NoPassport)?;
        let passport = ServerPassport::issue_root_for(&self.server_id, key, &me, PassportPermission::all(), now, None);
        self.set_my_passport(passport.clone());
        Ok(passport)
    }

    /// Cria um evento assinado por `personal`, confere contra o estado (como se carimbado agora) e
    /// guarda na fila até chegar o carimbo
    fn submit(&mut self, personal: &UserIdentity, entry: Entry, now: UtcSecs) -> Result<Submitted, CommunityError> {
        if !self.has_chain() {
            return Err(CommunityError::NoChainYet);
        }
        let passport = self.acting_passport(personal, now)?;
        if entry.permission().is_some_and(|p| !passport.allows(p)) {
            return Err(CommunityError::NotModerator);
        }
        let event = GovEvent::create(personal, &passport, entry);
        self.chain.state().check_event(&event, now.max(self.chain.state().base_time + 1))?;
        let submitted = Submitted { event_id: event.id(), imprint: event.imprint() };
        self.outbox.insert(submitted.event_id.clone(), event);
        Ok(submitted)
    }

    /// Anexa um carimbo ao objeto com este hash (evento na fila, evento do registro, meu passaporte
    /// ou conhecido). Eventos da fila que passam a ter carimbo aceito entram no registro e voltam
    /// em `ready` para publicar; os recusados voltam em `rejected`.
    fn attach_stamp(&mut self, imprint: &[u8; 32], stamp: &TimestampAttestation, now: UtcSecs) -> StampOutcome {
        let mut outcome = StampOutcome::default();
        let ids: Vec<String> = self.outbox.iter().filter(|(_, e)| &e.imprint() == imprint).map(|(id, _)| id.clone()).collect();
        for id in ids {
            let event = self.outbox.get_mut(&id).expect("listado acima");
            if !event.add_stamp(stamp.clone()) {
                continue;
            }
            outcome.changed = true;
            let event = event.clone();
            match self.chain.add_event(event.clone(), now) {
                AddResult::Added | AddResult::Consolidated | AddResult::Duplicate => {
                    self.outbox.remove(&id);
                    outcome.ready.push(event);
                }
                // Carimbo não aceito pela política (ex.: testemunha inválida): continua esperando
                AddResult::Rejected(Rejection::NoTimestamp) | AddResult::NoGenesis => {}
                AddResult::Rejected(rejection) => {
                    self.outbox.remove(&id);
                    outcome.rejected.push((event.body.entry.clone(), rejection));
                }
            }
        }
        // Carimbos atrasados de eventos já publicados
        let published = self.chain.events().find(|e| &e.imprint() == imprint).cloned();
        if let Some(mut event) = published {
            if !event.stamps.contains(stamp) {
                event.add_stamp(stamp.clone());
                self.chain.add_event(event, now);
                outcome.changed = true;
            }
        }
        // Elos da corrente de chaves: entram (e são publicados) quando a posse os aceita
        let key_ids: Vec<String> = self.key_outbox.iter().filter(|(_, l)| &l.imprint() == imprint).map(|(id, _)| id.clone()).collect();
        for id in key_ids {
            let link = self.key_outbox.get_mut(&id).expect("listado acima");
            if !link.add_stamp(stamp.clone()) {
                continue;
            }
            outcome.changed = true;
            let link = link.clone();
            self.chain.add_key_links(vec![link.clone()]);
            if self.chain.key_link_accepted(&id) {
                self.key_outbox.remove(&id);
                outcome.ready_keys.push(link);
            }
        }
        let known_link = self.chain.key_links().find(|l| &l.imprint() == imprint && !l.stamps.contains(stamp)).cloned();
        if let Some(mut link) = known_link {
            link.add_stamp(stamp.clone());
            self.chain.add_key_links(vec![link]);
            outcome.changed = true;
        }
        if let Some(mine) = self.my_passport.as_mut() {
            outcome.changed |= mine.add_stamp_to_link(imprint, stamp);
        }
        for passport in self.passports.values_mut() {
            outcome.changed |= passport.add_stamp_to_link(imprint, stamp);
        }
        if !outcome.ready.is_empty() || !outcome.ready_keys.is_empty() {
            self.refresh_owner_key();
        }
        outcome
    }

    /// Mensagens com o que falta a quem tem `have` (tudo, se `with_genesis`)
    fn sync_messages(&self, with_genesis: bool, have: &BTreeSet<String>) -> Vec<ServerMessage> {
        let events = self.chain.missing_for(have);
        let genesis = with_genesis.then(|| self.chain.genesis().cloned()).flatten();
        // A corrente de chaves é pequena: vai inteira (o que falta) na primeira mensagem
        let keys: Vec<KeyLink> = self.chain.key_links().filter(|l| !have.contains(&l.id())).cloned().collect();
        if events.is_empty() {
            if genesis.is_none() && keys.is_empty() {
                return Vec::new();
            }
            return vec![ServerMessage::Events { server_id: self.server_id.clone(), genesis, events: Vec::new(), keys }];
        }
        let (mut genesis, mut keys) = (genesis, Some(keys));
        events
            .chunks(EVENTS_PER_MESSAGE)
            .map(|chunk| ServerMessage::Events {
                server_id: self.server_id.clone(),
                genesis: genesis.take(),
                events: chunk.to_vec(),
                keys: keys.take().unwrap_or_default(),
            })
            .collect()
    }

    /// Inventário deste nó (para pedir o que falta)
    fn inventory(&self) -> ServerMessage {
        let mut have = self.chain.inventory();
        have.extend(self.discarded.iter().cloned());
        ServerMessage::Inventory {
            server_id: self.server_id.clone(),
            has_genesis: self.has_chain(),
            have: have.into_iter().collect(),
            passport: self.my_passport.clone(),
        }
    }
}

/// Resultado de anexar um carimbo
#[derive(Default, Debug)]
struct StampOutcome {
    changed: bool,
    ready: Vec<GovEvent>,
    ready_keys: Vec<KeyLink>,
    rejected: Vec<(Entry, Rejection)>,
}

/// O que aconteceu ao processar uma mensagem de servidor recebida da rede
#[derive(Debug)]
pub enum ServerEvent {
    /// O registro mudou (Genesis chegou, eventos aplicados ou consolidação)
    ChainUpdated { server_id: String, name: String, events: usize },
    /// Evento de governança aplicado (recebido ou deste nó, depois de carimbado)
    EventApplied { server_id: String, event: Box<GovEvent>, at: UtcSecs },
    /// Evento deste nó recusado ao receber o carimbo
    EventRejected { server_id: String, entry: Box<Entry>, reason: Rejection },
    /// Publicar estas mensagens no tópico de controle
    Reply { server_id: String, messages: Vec<ServerMessage> },
    /// Carimbo anexado a algo que este nó guarda
    StampAttached { server_id: String },
    /// A corrente de chaves mudou (renovação ou transferência da Chave do Servidor)
    OwnershipChanged { server_id: String },
    /// Mensagem descartada (inválida, antiga ou de servidor que não acompanhamos)
    Ignored(String),
}

#[derive(Serialize, Deserialize)]
struct StoredServer {
    server_id: String,
    genesis: Option<Genesis>,
    /// Consolidação que é o ponto de partida
    #[serde(default)]
    base: Option<StoredEvent>,
    #[serde(default)]
    events: Vec<StoredEvent>,
    #[serde(default)]
    outbox: Vec<StoredEvent>,
    /// Corrente de chaves (todos os elos conhecidos) e os deste nó aguardando carimbo
    #[serde(default)]
    keys: Vec<KeyLink>,
    #[serde(default)]
    key_outbox: Vec<KeyLink>,
    /// Passaportes usados pelos eventos acima, uma vez cada (por hash). Nenhum outro passaporte de
    /// terceiros é guardado.
    #[serde(default)]
    event_passports: BTreeMap<String, ServerPassport>,
}

/// Evento em disco: o passaporte do autor vai por referência (hash) para a tabela do arquivo,
/// evitando repeti-lo em cada evento do mesmo autor
#[derive(Serialize, Deserialize)]
struct StoredEvent {
    body: chain::GovEventBody,
    passport_ref: String,
    #[serde(with = "crate::b64")]
    signature: Vec<u8>,
    #[serde(default)]
    stamps: Vec<TimestampAttestation>,
}

/// Hash do passaporte completo (com carimbos), para a referência em disco
fn passport_ref(passport: &ServerPassport) -> String {
    Sha256::digest(crate::wire::to_bytes(passport))[..16].iter().map(|b| format!("{:02x}", b)).collect()
}

impl StoredEvent {
    fn store(event: &GovEvent, table: &mut BTreeMap<String, ServerPassport>) -> Self {
        let passport_ref = passport_ref(&event.passport);
        table.entry(passport_ref.clone()).or_insert_with(|| event.passport.clone());
        Self { body: event.body.clone(), passport_ref, signature: event.signature.clone(), stamps: event.stamps.clone() }
    }

    /// Evento completo de volta (descartado se o passaporte referenciado faltar)
    fn restore(self, table: &BTreeMap<String, ServerPassport>) -> Option<GovEvent> {
        let passport = table.get(&self.passport_ref)?.clone();
        Some(GovEvent { body: self.body, passport, signature: self.signature, stamps: self.stamps })
    }
}

/// Uma linha do histórico de alterações (para exibição)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Posição no histórico (0 = criação ou última consolidação)
    pub height: u64,
    pub timestamp: UtcSecs,
    pub description: String,
}

/// Servidores que este nó acompanha, com persistência opcional em disco:
/// - `<dir>/<id>.server.json`: Genesis, eventos e fila de eventos (nenhum passaporte de terceiros)
/// - `<dir>/<id>.owner-key.json`: chave do servidor (só no nó do dono; nunca é apagada)
/// - `<dir>/<id>.passport.json`: passaporte deste nó
#[derive(Default)]
pub struct ServerRegistry {
    dir: Option<PathBuf>,
    servers: BTreeMap<String, KnownServer>,
    /// Renúncias de quem saiu, reenviadas algumas vezes na primeira hora (ninguém pode ter visto a saída)
    renounces: Vec<PendingRenounce>,
}

/// Renúncia ao passaporte de um servidor do qual este nó saiu
#[derive(Serialize, Deserialize, Clone, Debug)]
struct PendingRenounce {
    server_id: String,
    event: GovEvent,
    /// Quando a renúncia foi feita (saída)
    left_at: UtcSecs,
    /// Tentativas de reenvio já feitas
    #[serde(default)]
    retries: u32,
}

/// Reenvios da renúncia, em segundos depois da saída. É só um esforço: sair é voluntário, e quem
/// precisa garantir a revogação é o servidor. Depois do último, a pendência é apagada.
const RENOUNCE_RETRY_AFTER: [UtcSecs; 4] = [60, 5 * 60, 15 * 60, 30 * 60];

impl ServerRegistry {
    /// Registro sem persistência (testes)
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Carrega os servidores salvos em `dir` (cria a pasta se não existir).
    /// Tudo é revalidado ao carregar: eventos adulterados são descartados.
    pub fn load(dir: impl AsRef<Path>, now: UtcSecs) -> Result<Self, CommunityError> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let renounces = std::fs::read(dir.join("renounces.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let mut registry = Self { dir: Some(dir.clone()), servers: BTreeMap::new(), renounces };

        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let Some(file) = path.file_name().and_then(|n| n.to_str()) else { continue };
            let Some(id) = file.strip_suffix(".server.json") else { continue };
            if !is_valid_server_id(id) {
                continue;
            }
            let Ok(stored) = serde_json::from_slice::<StoredServer>(&std::fs::read(&path)?) else {
                tracing::warn!("Servidor salvo ilegível (formato antigo?): {:?}", path);
                continue;
            };
            let mut server = KnownServer::new(id);
            if let Some(genesis) = stored.genesis {
                if server.chain.set_genesis(genesis) {
                    server.chain.add_key_links(stored.keys);
                    let table = &stored.event_passports;
                    let events: Vec<GovEvent> = stored.base.into_iter().chain(stored.events).filter_map(|e| e.restore(table)).collect();
                    server.chain.add_events(events, now);
                }
            }
            for event in stored.outbox.into_iter().filter_map(|e| e.restore(&stored.event_passports)) {
                if event.verify_signature(id) {
                    server.outbox.insert(event.id(), event);
                }
            }
            for link in stored.key_outbox {
                if link.verify_signatures(id) {
                    server.key_outbox.insert(link.id(), link);
                }
            }
            server.stored_keys = load_server_keys(&dir, id)?;
            server.refresh_owner_key();
            let passport_path = dir.join(format!("{}.passport.json", id));
            if passport_path.exists() {
                if let Ok(passport) = serde_json::from_slice::<ServerPassport>(&std::fs::read(&passport_path)?) {
                    server.set_my_passport(passport);
                }
            }
            registry.servers.insert(id.to_string(), server);
        }
        Ok(registry)
    }

    pub fn get(&self, server_id: &str) -> Option<&KnownServer> {
        self.servers.get(server_id)
    }

    pub fn get_mut(&mut self, server_id: &str) -> Option<&mut KnownServer> {
        self.servers.get_mut(server_id)
    }

    pub fn list(&self) -> impl Iterator<Item = &KnownServer> {
        self.servers.values()
    }

    /// Procura por id completo, prefixo do id (4+ caracteres) ou nome (sem diferenciar maiúsculas)
    pub fn find(&self, query: &str) -> Option<&KnownServer> {
        self.servers.get(query).or_else(|| {
            self.servers
                .values()
                .find(|s| (query.len() >= 4 && s.server_id.starts_with(query)) || s.name().eq_ignore_ascii_case(query))
        })
    }

    /// Cria um servidor com chave própria e a política de tempo sugerida (FreeTSA). Este nó vira o
    /// dono, e `owner_pubkey` (a identidade pessoal de quem cria) recebe um passaporte vitalício
    /// e entra na lista de protegidos.
    pub fn create(&mut self, name: &str, owner_pubkey: &str, now: UtcSecs) -> Result<String, CommunityError> {
        self.create_with_policy(name, owner_pubkey, TimestampPolicy::default(), now)
    }

    pub fn create_with_policy(&mut self, name: &str, owner_pubkey: &str, policy: TimestampPolicy, now: UtcSecs) -> Result<String, CommunityError> {
        let key = UserIdentity::generate_with_nick(name);
        let id = key.public_key_hex();
        if let Some(dir) = &self.dir {
            key.save_to(dir.join(format!("{}.owner-key.json", id)))?;
        }
        let mut server = KnownServer::new(&id);
        let config = chain::default_config(name, owner_pubkey, default_channels(), policy);
        server.chain.set_genesis(Genesis::create(&key, config, now));
        let passport = ServerPassport::issue_root(&key, owner_pubkey, PassportPermission::all(), now, None);
        server.set_my_passport(passport);
        server.owner_key = Some(key);
        self.servers.insert(id.clone(), server);
        self.persist(&id)?;
        Ok(id)
    }

    /// Passa a acompanhar um servidor pelo id. Retorna `false` se já acompanhava.
    /// O registro chega depois, de algum membro online.
    pub fn join(&mut self, server_id: &str) -> Result<bool, CommunityError> {
        if !is_valid_server_id(server_id) {
            return Err(CommunityError::InvalidServerId);
        }
        if self.servers.contains_key(server_id) {
            return Ok(false);
        }
        let mut server = KnownServer::new(server_id);
        // Voltando a um servidor do qual somos donos (`leave` mantém a chave em disco): a posse volta
        // quando o registro confirmar que a chave ainda é a raiz em vigor
        if let Some(dir) = &self.dir {
            server.stored_keys = load_server_keys(dir, server_id)?;
            if let Some(pos) = server.stored_keys.iter().position(|k| k.public_key_hex() == server_id) {
                server.owner_key = Some(server.stored_keys.remove(pos));
            }
        }
        self.servers.insert(server_id.to_string(), server);
        self.persist(server_id)?;
        Ok(true)
    }

    /// Sair do servidor por vontade própria: renuncia ao passaporte (vira uma revogação no registro,
    /// e quem saiu só volta com passaporte novo) e deixa de acompanhar o servidor. Quem tem a Chave
    /// do Servidor não renuncia: o passaporte dele vem dela, que fica no disco.
    /// Devolve o hash a carimbar e as autoridades de tempo; a renúncia é publicada quando o carimbo
    /// chegar (e republicada algumas vezes depois).
    pub fn leave_renouncing(&mut self, server_id: &str, personal: &UserIdentity, _now: UtcSecs) -> Option<([u8; 32], Vec<TrustedTsa>)> {
        let server = self.servers.get(server_id)?;
        let tsas = server.chain.state().timestamp_policy.tsas.clone();
        let renounce = (!server.is_owner())
            .then(|| server.my_passport().cloned())
            .flatten()
            .filter(|p| p.body.holder == personal.public_key_hex())
            .map(|passport| {
                let event = GovEvent::create(personal, &passport, Entry::Renounce { serial: passport.body.serial.clone() });
                PendingRenounce { server_id: server_id.to_string(), event, left_at: _now, retries: 0 }
            });
        self.leave(server_id);
        let renounce = renounce?;
        let imprint = renounce.event.imprint();
        self.renounces.push(renounce);
        self.persist_renounces();
        Some((imprint, tsas))
    }

    /// Renúncias com reenvio vencido (até 4, na primeira hora depois da saída). Só as já carimbadas
    /// são publicadas (sem carimbo, ninguém aceitaria).
    pub fn pending_renounces(&mut self, now: UtcSecs) -> Vec<(String, ServerMessage)> {
        let mut due = Vec::new();
        for renounce in &mut self.renounces {
            let Some(after) = RENOUNCE_RETRY_AFTER.get(renounce.retries as usize) else { continue };
            if now >= renounce.left_at + after {
                renounce.retries += 1;
                if !renounce.event.stamps.is_empty() {
                    due.push((renounce.server_id.clone(), events_message(&renounce.server_id, vec![renounce.event.clone()])));
                }
            }
        }
        // Depois do último reenvio, desiste
        self.renounces.retain(|r| (r.retries as usize) < RENOUNCE_RETRY_AFTER.len());
        if !due.is_empty() {
            self.persist_renounces();
        }
        due
    }

    fn persist_renounces(&self) {
        if let Some(dir) = &self.dir {
            if let Ok(bytes) = serde_json::to_vec_pretty(&self.renounces) {
                let _ = std::fs::write(dir.join("renounces.json"), bytes);
            }
        }
    }

    /// Deixa de acompanhar o servidor. A chave de dono, se existir, é mantida em disco.
    pub fn leave(&mut self, server_id: &str) -> bool {
        let removed = self.servers.remove(server_id).is_some();
        if let (true, Some(dir)) = (removed, &self.dir) {
            let _ = std::fs::remove_file(dir.join(format!("{}.server.json", server_id)));
            let _ = std::fs::remove_file(dir.join(format!("{}.passport.json", server_id)));
        }
        removed
    }

    /// Recebe um passaporte destinado a este nó. Sem o registro ainda (servidor privado recém-aceito),
    /// guarda depois de conferir só a assinatura da cadeia; ele acompanha o inventário.
    pub fn accept_my_passport(&mut self, server_id: &str, me: &str, passport: &ServerPassport, now: UtcSecs) -> bool {
        let Some(server) = self.servers.get_mut(server_id) else { return false };
        if passport.body.holder != me {
            return false;
        }
        let ok = if server.has_chain() {
            server.chain.state().verify_passport(passport, now).is_ok()
        } else {
            passport.verify_at(server_id, now).is_ok()
        };
        if !ok || server.my_passport.as_ref() == Some(passport) {
            return false;
        }
        // Reenvios atrasados não trocam um passaporte mais novo (ex.: o de moderador) por um antigo
        // ou equivalente/inferior emitido no mesmo segundo
        if let Some(current) = &server.my_passport {
            let current_valid = if server.has_chain() {
                server.chain.state().verify_passport(current, now).is_ok()
            } else {
                current.verify_at(server_id, now).is_ok()
            };
            if current_valid {
                if passport.body.issued_at < current.body.issued_at {
                    return false;
                }
                if passport.body.issued_at == current.body.issued_at
                    && passport.body.permissions.iter().all(|p| current.body.permissions.contains(p))
                    && passport.body.expires_at <= current.body.expires_at
                {
                    return false;
                }
            }
        }
        server.set_my_passport(passport.clone());
        let _ = self.persist(server_id);
        true
    }

    /// Processa uma mensagem do tópico de controle. `from_pubkey` é quem publicou (do PeerId),
    /// usado para não entregar o registro de um servidor privado a quem está fora dele.
    pub fn handle_message(&mut self, message: ServerMessage, from_pubkey: Option<&str>, now: UtcSecs) -> Vec<ServerEvent> {
        match message {
            ServerMessage::Events { server_id, genesis, events, keys } => self.receive_events(&server_id, genesis, events, keys, now),
            ServerMessage::Inventory { server_id, has_genesis, have, passport } => {
                let Some(server) = self.servers.get_mut(&server_id).filter(|s| s.has_chain()) else {
                    return vec![ServerEvent::Ignored("sem registro para responder".into())];
                };
                if let Some(p) = &passport {
                    server.learn_passport(p, now);
                }
                if server.chain.state().closed && !from_pubkey.is_some_and(|pk| server.is_allowed_with_passport(pk, passport.as_ref(), now)) {
                    return vec![ServerEvent::Ignored("servidor privado: pedido de quem não tem passaporte".into())];
                }
                let have: BTreeSet<String> = have.into_iter().collect();
                let mut messages = server.sync_messages(!has_genesis, &have);
                // Quem pediu tem algo que este nó não conhece: pede também (o outro responde só o que falta)
                let mine = server.chain.inventory();
                if has_genesis && have.iter().any(|id| !mine.contains(id) && !server.discarded.contains(id)) {
                    messages.push(server.inventory());
                }
                if messages.is_empty() {
                    return Vec::new();
                }
                vec![ServerEvent::Reply { messages, server_id }]
            }
            ServerMessage::Stamp { server_id, imprint, stamp } => {
                let Some(imprint) = parse_imprint(&imprint) else {
                    return vec![ServerEvent::Ignored("carimbo com hash inválido".into())];
                };
                self.attach_stamp(&server_id, &imprint, &stamp, now)
            }
            ServerMessage::KeyPackage { .. }
            | ServerMessage::Commit { .. }
            | ServerMessage::Welcome { .. }
            | ServerMessage::GroupAnnounce { .. }
            | ServerMessage::PassportOffer { .. }
            | ServerMessage::FlattenRequest { .. }
            | ServerMessage::AccessRequest { .. }
            | ServerMessage::AccessPolicy { .. }
            | ServerMessage::GroupLeave { .. }
            | ServerMessage::KeyTransferOffer { .. }
            | ServerMessage::KeyTransferAccept { .. }
            | ServerMessage::StampRequest { .. } => {
                vec![ServerEvent::Ignored("mensagem do grupo cifrado, passaporte ou carimbo (tratada pelo runtime)".into())]
            }
        }
    }

    fn receive_events(&mut self, server_id: &str, genesis: Option<Genesis>, events: Vec<GovEvent>, keys: Vec<KeyLink>, now: UtcSecs) -> Vec<ServerEvent> {
        let Some(server) = self.servers.get_mut(server_id) else {
            return vec![ServerEvent::Ignored("servidor não acompanhado".into())];
        };
        let mut out = Vec::new();
        let mut changed = false;
        if let Some(genesis) = genesis {
            changed |= server.chain.set_genesis(genesis);
        }
        if !server.has_chain() {
            return vec![ServerEvent::Ignored("eventos sem a Genesis".into())];
        }
        // Posse primeiro: os eventos são validados contra as raízes resolvidas
        if !keys.is_empty() {
            let before = server.chain.ownership().clone();
            server.chain.add_key_links(keys);
            if *server.chain.ownership() != before {
                changed = true;
                out.push(ServerEvent::OwnershipChanged { server_id: server_id.to_string() });
            }
        }
        for (event, result) in server.chain.add_events(events, now) {
            match result {
                AddResult::Added | AddResult::Consolidated => {
                    changed = true;
                    server.learn_passport(&event.passport, now);
                    let at = server.chain.state().event_times.get(&event.id()).copied().unwrap_or(now);
                    out.push(ServerEvent::EventApplied { server_id: server_id.to_string(), event: Box::new(event), at });
                }
                AddResult::Duplicate => {}
                AddResult::Rejected(rejection) => {
                    if !rejection.depends_on_order() {
                        server.discarded.insert(event.id());
                    }
                    out.push(ServerEvent::Ignored(format!("evento recusado: {}", rejection)));
                }
                AddResult::NoGenesis => {}
            }
        }
        if changed {
            server.refresh_owner_key();
            out.insert(0, ServerEvent::ChainUpdated { server_id: server_id.to_string(), name: server.name(), events: server.chain.events().count() });
            let _ = self.persist(server_id);
        }
        out
    }

    /// Inventário deste nó (pede o que falta, com o passaporte, para servidores privados)
    pub fn chain_request(&self, server_id: &str) -> Option<ServerMessage> {
        Some(self.servers.get(server_id)?.inventory())
    }

    /// Tudo que este nó sabe do servidor, para entregar a quem acabou de entrar no tópico
    pub fn snapshot(&self, server_id: &str) -> Vec<ServerMessage> {
        self.servers.get(server_id).filter(|s| s.has_chain()).map(|s| s.sync_messages(true, &BTreeSet::new())).unwrap_or_default()
    }

    // ---------- Passaportes ----------

    /// Emite um passaporte para `holder`: pela Chave do Servidor (se este nó a tem) ou como
    /// subordinado do passaporte deste nó. A validade padrão vem da política do servidor.
    pub fn issue_passport(
        &self,
        server_id: &str,
        issuer: &UserIdentity,
        holder: &str,
        permissions: Vec<PassportPermission>,
        duration: Option<u64>,
        now: UtcSecs,
    ) -> Result<ServerPassport, CommunityError> {
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        if !server.has_chain() {
            return Err(CommunityError::NoChainYet);
        }
        let validity = server.chain.state().passport_validity_secs.max(3600);
        if let Some(key) = server.owner_key() {
            return Ok(ServerPassport::issue_root_for(server_id, key, holder, permissions, now, duration.map(|d| now + d)));
        }
        let mine = server.my_passport().ok_or(CommunityError::NoPassport)?;
        server.chain.state().verify_passport(mine, now)?;
        Ok(mine.issue_subordinate(issuer, holder, permissions, now, now + duration.unwrap_or(validity))?)
    }

    /// Pedido de acesso de `requester`. Em servidor público, quem pode emitir passaporte de membro
    /// responde com um passaporte novo — que não fura um ban em vigor (a janela o invalida, e a
    /// Chave do Servidor não emite automaticamente para quem está banido).
    pub fn answer_access_request(&self, server_id: &str, issuer: &UserIdentity, requester: &str, now: UtcSecs) -> Option<ServerMessage> {
        let server = self.servers.get(server_id).filter(|s| s.has_chain())?;
        let state = server.chain.state();
        // Já tem passaporte válido conhecido (a entrega anterior pode ter se perdido, ex.: pedido
        // feito antes de a malha do tópico se formar): reenvia o mesmo, em vez de ignorar ou emitir outro
        if server.is_allowed(requester, now) {
            let passport = server.passport_of(requester)?.clone();
            return Some(ServerMessage::PassportOffer { server_id: server_id.to_string(), target: requester.to_string(), passport });
        }
        if state.closed || state.is_banned(requester, now) {
            return None;
        }
        let can_issue = server.is_owner() || server.my_passport().is_some_and(|p| p.allows(PassportPermission::IssueMember));
        if !can_issue {
            return None;
        }
        let validity = state.passport_validity_secs.max(3600);
        let passport = self.issue_passport(server_id, issuer, requester, PassportPermission::member(), Some(validity), now).ok()?;
        state.verify_passport(&passport, now).ok()?;
        Some(ServerMessage::PassportOffer { server_id: server_id.to_string(), target: requester.to_string(), passport })
    }

    /// O pedido de acesso de `from` cumpre a prova de trabalho exigida pelo servidor? `None` = o
    /// servidor não exige. Confere dificuldade, assinatura, autoridade do carimbo (política do
    /// servidor; testemunha não pode ser quem pede) e se o carimbo é recente.
    pub fn access_proof_ok(&self, server_id: &str, from: &str, proof: Option<&access_proof::AccessProof>, now: UtcSecs) -> Option<bool> {
        let server = self.servers.get(server_id).filter(|s| s.has_chain())?;
        let state = server.chain.state();
        let bits = state.access_pow_bits;
        if bits == 0 {
            return None;
        }
        let Some(proof) = proof else { return Some(false) };
        if !proof.verify_work(server_id, from, bits) {
            return Some(false);
        }
        let imprint = access_proof::seed_imprint(server_id, from, &proof.body.seed);
        Some(
            state
                .stamp_time(&proof.body.freshness, &imprint, from, 3)
                .is_some_and(|at| access_proof::AccessProof::fresh_at(at, now)),
        )
    }

    /// Política de acesso para mandar a quem pede sem prova (dificuldade e autoridades de tempo)
    pub fn access_policy(&self, server_id: &str, _now: UtcSecs) -> Option<ServerMessage> {
        let server = self.servers.get(server_id).filter(|s| s.has_chain())?;
        let state = server.chain.state();
        (state.access_pow_bits > 0).then(|| ServerMessage::AccessPolicy {
            server_id: server_id.to_string(),
            pow_bits: state.access_pow_bits,
            tsas: state.timestamp_policy.tsas.clone(),
        })
    }

    /// Anexa um carimbo a quem tiver esse hash (evento na fila ou no registro, passaportes,
    /// renúncias). Eventos que ficam prontos voltam em `Reply` para publicar.
    pub fn attach_stamp(&mut self, server_id: &str, imprint: &[u8; 32], stamp: &TimestampAttestation, now: UtcSecs) -> Vec<ServerEvent> {
        let mut out = Vec::new();
        // Renúncia de quem já saiu (o servidor não é mais acompanhado): publica no primeiro carimbo
        let mut renounced = Vec::new();
        for renounce in self.renounces.iter_mut().filter(|r| r.server_id == server_id && &r.event.imprint() == imprint) {
            let first = renounce.event.stamps.is_empty();
            if renounce.event.add_stamp(stamp.clone()) && first {
                renounced.push(renounce.event.clone());
            }
        }
        if !renounced.is_empty() {
            self.persist_renounces();
            out.push(ServerEvent::Reply { server_id: server_id.to_string(), messages: vec![events_message(server_id, renounced)] });
        }
        let Some(server) = self.servers.get_mut(server_id) else { return out };
        let outcome = server.attach_stamp(imprint, stamp, now);
        for (entry, reason) in outcome.rejected {
            out.push(ServerEvent::EventRejected { server_id: server_id.to_string(), entry: Box::new(entry), reason });
        }
        if !outcome.ready.is_empty() {
            let name = server.name();
            let events = server.chain.events().count();
            out.push(ServerEvent::ChainUpdated { server_id: server_id.to_string(), name, events });
            for event in &outcome.ready {
                let at = server.chain.state().event_times.get(&event.id()).copied().unwrap_or(now);
                out.push(ServerEvent::EventApplied { server_id: server_id.to_string(), event: Box::new(event.clone()), at });
            }
            let messages = outcome.ready.chunks(EVENTS_PER_MESSAGE).map(|c| events_message(server_id, c.to_vec())).collect();
            out.push(ServerEvent::Reply { server_id: server_id.to_string(), messages });
        }
        if !outcome.ready_keys.is_empty() {
            out.push(ServerEvent::OwnershipChanged { server_id: server_id.to_string() });
            let message = ServerMessage::Events { server_id: server_id.to_string(), genesis: None, events: Vec::new(), keys: outcome.ready_keys };
            out.push(ServerEvent::Reply { server_id: server_id.to_string(), messages: vec![message] });
        }
        if outcome.changed {
            let _ = self.persist(server_id);
            out.push(ServerEvent::StampAttached { server_id: server_id.to_string() });
        }
        out
    }

    /// Carimbo de testemunha deste nó para `imprint`, se ele participa do servidor
    pub fn witness_stamp(&self, server_id: &str, witness: &UserIdentity, imprint: &str, nonce: &str, now: UtcSecs) -> Option<ServerMessage> {
        let server = self.servers.get(server_id).filter(|s| s.has_chain())?;
        let digest = parse_imprint(imprint)?;
        let passport = server.my_passport()?;
        server.chain.state().verify_passport(passport, now).ok()?;
        let token = PeerTimestampToken::issue(witness, passport, &digest, nonce, now);
        Some(ServerMessage::Stamp {
            server_id: server_id.to_string(),
            imprint: imprint.to_string(),
            stamp: TimestampAttestation::Peer(Box::new(token)),
        })
    }

    // ---------- Governança (eventos assinados com o passaporte de quem age) ----------

    /// Cria um evento de governança assinado por `personal`. Ele fica na fila até chegar um carimbo
    /// de tempo aceito (pedir em [`Submitted::imprint`]); aí entra no registro e é publicado.
    pub fn submit(&mut self, server_id: &str, personal: &UserIdentity, entry: Entry, now: UtcSecs) -> Result<Submitted, CommunityError> {
        let server = self.servers.get_mut(server_id).ok_or(CommunityError::UnknownServer)?;
        let submitted = server.submit(personal, entry, now)?;
        self.persist(server_id)?;
        Ok(submitted)
    }

    pub fn add_channel(&mut self, server_id: &str, personal: &UserIdentity, name: &str, kind: ChannelType, now: UtcSecs) -> Result<Submitted, CommunityError> {
        if self.get(server_id).is_some_and(|s| s.channels().iter().any(|c| c.name == name)) {
            return Err(CommunityError::ChannelExists);
        }
        self.submit(server_id, personal, Entry::AddChannel(Channel { name: name.to_string(), channel_type: kind }), now)
    }

    pub fn remove_channel(&mut self, server_id: &str, personal: &UserIdentity, name: &str, now: UtcSecs) -> Result<Submitted, CommunityError> {
        if !self.get(server_id).is_some_and(|s| s.channels().iter().any(|c| c.name == name)) {
            return Err(CommunityError::UnknownChannel);
        }
        self.submit(server_id, personal, Entry::RemoveChannel(name.to_string()), now)
    }

    pub fn set_closed(&mut self, server_id: &str, personal: &UserIdentity, closed: bool, now: UtcSecs) -> Result<Submitted, CommunityError> {
        self.submit(server_id, personal, Entry::SetClosed(closed), now)
    }

    pub fn set_passport_policy(
        &mut self,
        server_id: &str,
        personal: &UserIdentity,
        validity_secs: u64,
        renewal_window_secs: u64,
        now: UtcSecs,
    ) -> Result<Submitted, CommunityError> {
        self.submit(server_id, personal, Entry::SetPassportPolicy { validity_secs, renewal_window_secs }, now)
    }

    /// Dificuldade da prova de trabalho dos pedidos de acesso; 0 desliga
    pub fn set_access_pow(&mut self, server_id: &str, personal: &UserIdentity, bits: u8, now: UtcSecs) -> Result<Submitted, CommunityError> {
        self.submit(server_id, personal, Entry::SetAccessPow { bits: bits.min(access_proof::MAX_POW_BITS) }, now)
    }

    /// Acrescenta (ou substitui pelo nome) uma autoridade de tempo na política do servidor
    pub fn add_tsa(&mut self, server_id: &str, personal: &UserIdentity, tsa: TrustedTsa, now: UtcSecs) -> Result<Submitted, CommunityError> {
        if spki::SubjectPublicKeyInfoRef::try_from(tsa.spki_der.as_slice()).is_err() {
            return Err(CommunityError::InvalidTsa("chave pública (SubjectPublicKeyInfo DER) ilegível".into()));
        }
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        let mut policy = server.chain.state().timestamp_policy.clone();
        policy.tsas.retain(|t| t.name != tsa.name);
        policy.tsas.push(tsa);
        self.submit(server_id, personal, Entry::SetTimestampPolicy(policy), now)
    }

    pub fn remove_tsa(&mut self, server_id: &str, personal: &UserIdentity, name: &str, now: UtcSecs) -> Result<Submitted, CommunityError> {
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        let mut policy = server.chain.state().timestamp_policy.clone();
        let before = policy.tsas.len();
        policy.tsas.retain(|t| !t.name.eq_ignore_ascii_case(name));
        if policy.tsas.len() == before {
            return Err(CommunityError::InvalidTsa(format!("'{}' não está na política", name)));
        }
        self.submit(server_id, personal, Entry::SetTimestampPolicy(policy), now)
    }

    /// Protege (ou deixa de proteger) uma pubkey contra ban e revogação por moderador
    pub fn set_protected(&mut self, server_id: &str, personal: &UserIdentity, pubkey: &str, protected: bool, now: UtcSecs) -> Result<Submitted, CommunityError> {
        self.submit(server_id, personal, Entry::SetProtected { pubkey: pubkey.to_string(), protected }, now)
    }

    /// Revoga o passaporte de moderação conhecido de uma pubkey
    pub fn remove_moderator(&mut self, server_id: &str, personal: &UserIdentity, pubkey: &str, now: UtcSecs) -> Result<Submitted, CommunityError> {
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        let serial = server
            .passports
            .get(pubkey)
            .filter(|p| p.is_moderator() && !server.chain.state().revoked.contains(&p.body.serial))
            .map(|p| p.body.serial.clone())
            .ok_or(CommunityError::NotModerator)?;
        self.submit(server_id, personal, Entry::Revoke { target: pubkey.to_string(), serial }, now)
    }

    /// Bane, desbane ou revoga
    pub fn moderate(
        &mut self,
        server_id: &str,
        personal: &UserIdentity,
        kind: ModKind,
        target: &str,
        reason: &str,
        now: UtcSecs,
    ) -> Result<Submitted, CommunityError> {
        self.submit(server_id, personal, kind.into_entry(target, reason), now)
    }

    /// Consolida o estado atual numa nova Genesis (#52)
    pub fn consolidate(&mut self, server_id: &str, personal: &UserIdentity, now: UtcSecs) -> Result<Submitted, CommunityError> {
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        if server.chain.events().next().is_none() {
            return Err(CommunityError::NothingToConsolidate);
        }
        let consolidation = server.chain.consolidation();
        self.submit(server_id, personal, Entry::Consolidate(Box::new(consolidation)), now)
    }

    // ---------- Corrente de chaves (#99) ----------

    /// Renova a validade da chave raiz em vigor (só quem a tem). O elo é publicado quando chegar o
    /// carimbo de TSA.
    pub fn renew_root(&mut self, server_id: &str, now: UtcSecs) -> Result<Submitted, CommunityError> {
        let server = self.servers.get_mut(server_id).ok_or(CommunityError::UnknownServer)?;
        if !server.has_chain() {
            return Err(CommunityError::NoChainYet);
        }
        let key = server.owner_key.as_ref().ok_or(CommunityError::NotOwner)?;
        let valid_until = now + server.chain.state().root_validity_secs;
        let link = KeyLink::renew(key, server_id, &server.chain.ownership().head(), valid_until);
        let submitted = Submitted { event_id: link.id(), imprint: link.imprint() };
        server.key_outbox.insert(submitted.event_id.clone(), link);
        self.persist(server_id)?;
        Ok(submitted)
    }

    /// Passo 1 da transferência (quem tem a chave): proposta a `target` (identidade pessoal)
    pub fn offer_transfer(&self, server_id: &str, personal: &UserIdentity, target: &str) -> Result<ServerMessage, CommunityError> {
        let server = self.servers.get(server_id).ok_or(CommunityError::UnknownServer)?;
        let key = server.owner_key.as_ref().ok_or(CommunityError::NotOwner)?;
        if target == personal.public_key_hex() {
            return Err(CommunityError::InvalidTransfer("não é possível transferir para si mesmo".into()));
        }
        Ok(ServerMessage::KeyTransferOffer {
            server_id: server_id.to_string(),
            target: target.to_string(),
            previous_owner: personal.public_key_hex(),
            key: key.public_key_hex(),
            previous: server.chain.ownership().head(),
        })
    }

    /// Passo 2 (quem recebe): gera a chave nova **nesta máquina**, guarda e assina a aceitação.
    /// A chave vira a do dono quando a transferência entrar na corrente de chaves.
    pub fn accept_transfer_offer(
        &mut self,
        server_id: &str,
        me: &UserIdentity,
        offer: &ServerMessage,
        now: UtcSecs,
    ) -> Result<ServerMessage, CommunityError> {
        let ServerMessage::KeyTransferOffer { server_id: offer_server, target, previous_owner, key, previous } = offer else {
            return Err(CommunityError::InvalidTransfer("não é uma proposta de transferência".into()));
        };
        if offer_server != server_id || *target != me.public_key_hex() {
            return Err(CommunityError::InvalidTransfer("proposta para outro servidor ou pessoa".into()));
        }
        let server = self.servers.get(server_id).filter(|s| s.has_chain()).ok_or(CommunityError::NoChainYet)?;
        let state = server.chain.state();
        if state.current_root() != key || server.chain.ownership().head() != *previous {
            return Err(CommunityError::InvalidTransfer("a proposta não parte da chave em vigor".into()));
        }
        let new_key = UserIdentity::generate_with_nick(&state.name);
        let body = KeyLinkBody {
            server_id: server_id.to_string(),
            previous: previous.clone(),
            key: key.clone(),
            kind: KeyLinkKind::Transfer {
                new_key: new_key.public_key_hex(),
                valid_until: now + state.root_validity_secs,
                previous_owner: Some(previous_owner.clone()),
                new_owner: Some(me.public_key_hex()),
            },
        };
        let new_key_signature = new_key.sign(&keychain::signing_bytes(&body));
        self.store_server_key(server_id, new_key)?;
        Ok(ServerMessage::KeyTransferAccept { server_id: server_id.to_string(), body, new_key_signature })
    }

    /// Passo 3 (quem tem a chave): confere a aceitação, assina o elo e o põe na fila do carimbo de TSA
    pub fn complete_transfer(
        &mut self,
        server_id: &str,
        personal: &UserIdentity,
        body: KeyLinkBody,
        new_key_signature: Vec<u8>,
    ) -> Result<Submitted, CommunityError> {
        let server = self.servers.get_mut(server_id).ok_or(CommunityError::UnknownServer)?;
        let key = server.owner_key.as_ref().ok_or(CommunityError::NotOwner)?;
        let KeyLinkKind::Transfer { previous_owner, .. } = &body.kind else {
            return Err(CommunityError::InvalidTransfer("elo não é de transferência".into()));
        };
        if body.server_id != server_id
            || body.key != key.public_key_hex()
            || body.previous != server.chain.ownership().head()
            || previous_owner.as_deref() != Some(personal.public_key_hex().as_str())
        {
            return Err(CommunityError::InvalidTransfer("a aceitação não corresponde à proposta".into()));
        }
        let link = KeyLink::transfer(key, body, new_key_signature);
        if !link.verify_signatures(server_id) {
            return Err(CommunityError::InvalidTransfer("assinatura de aceitação inválida".into()));
        }
        let submitted = Submitted { event_id: link.id(), imprint: link.imprint() };
        server.key_outbox.insert(submitted.event_id.clone(), link);
        self.persist(server_id)?;
        Ok(submitted)
    }

    /// Guarda a chave recebida numa transferência; vira a chave do dono quando o registro confirmar
    pub fn store_server_key(&mut self, server_id: &str, key: UserIdentity) -> Result<(), CommunityError> {
        if let Some(dir) = &self.dir {
            key.save_to(dir.join(format!("{}.owner-key.{}.json", server_id, short_id(&key.public_key_hex()))))?;
        }
        let server = self.servers.get_mut(server_id).ok_or(CommunityError::UnknownServer)?;
        server.stored_keys.push(key);
        server.refresh_owner_key();
        Ok(())
    }

    /// Manutenção periódica: fecha a janela de acomodação das consolidações e, para quem tem
    /// `Consolidate`, consolida quando o intervalo configurado venceu. Devolve o evento a carimbar.
    pub fn maintenance(&mut self, server_id: &str, personal: &UserIdentity, now: UtcSecs) -> Option<Submitted> {
        let server = self.servers.get_mut(server_id)?;
        server.chain.settle(now);
        if !server.has_chain() {
            return None;
        }
        let interval = server.chain.state().consolidation_interval_secs;
        let due = interval > 0
            && now >= server.chain.base_time() + interval
            && server.chain.events().next().is_some()
            && !server.outbox.values().any(|e| matches!(e.body.entry, Entry::Consolidate(_)))
            && server.my_passport().is_some_and(|p| p.allows(PassportPermission::Consolidate));
        if !due {
            return None;
        }
        self.consolidate(server_id, personal, now).ok()
    }

    /// Histórico de alterações, do mais antigo ao mais novo (a partir da criação ou da última consolidação)
    pub fn history(&self, server_id: &str) -> Vec<HistoryEntry> {
        let Some(server) = self.servers.get(server_id) else { return Vec::new() };
        let mut out = Vec::new();
        if let Some(base) = server.chain.base_consolidation() {
            if let Entry::Consolidate(c) = &base.body.entry {
                out.push(HistoryEntry {
                    height: 0,
                    timestamp: server.chain.base_time(),
                    description: format!("consolidação {} por {} ({} eventos)", c.generation, short_id(base.author()), c.included.len()),
                });
            }
        } else if let Some(genesis) = server.chain.genesis() {
            let config = &genesis.body.config;
            out.push(HistoryEntry {
                height: 0,
                timestamp: genesis.body.created_at,
                description: format!("criado '{}'{}", config.name, if config.closed { " (privado)" } else { "" }),
            });
        }
        for (event, at) in server.chain.ordered_events() {
            out.push(HistoryEntry { height: out.len() as u64, timestamp: at, description: describe_event(event) });
        }
        out
    }

    pub fn persist(&self, server_id: &str) -> Result<(), CommunityError> {
        let (Some(dir), Some(server)) = (&self.dir, self.servers.get(server_id)) else { return Ok(()) };
        let mut table = BTreeMap::new();
        let stored = StoredServer {
            server_id: server_id.to_string(),
            genesis: server.chain.genesis().cloned(),
            base: server.chain.base_consolidation().map(|e| StoredEvent::store(e, &mut table)),
            events: server.chain.events().map(|e| StoredEvent::store(e, &mut table)).collect(),
            outbox: server.outbox.values().map(|e| StoredEvent::store(e, &mut table)).collect(),
            event_passports: table,
            keys: server.chain.key_links().cloned().collect(),
            key_outbox: server.key_outbox.values().cloned().collect(),
        };
        std::fs::write(dir.join(format!("{}.server.json", server_id)), serde_json::to_vec_pretty(&stored)?)?;
        if let Some(passport) = &server.my_passport {
            std::fs::write(dir.join(format!("{}.passport.json", server_id)), serde_json::to_vec_pretty(passport)?)?;
        }
        Ok(())
    }
}

/// Chaves de servidor guardadas para `server_id`: a original (`<id>.owner-key.json`) e as
/// recebidas por transferência (`<id>.owner-key.<prefixo>.json`)
fn load_server_keys(dir: &Path, server_id: &str) -> Result<Vec<UserIdentity>, CommunityError> {
    let mut keys = Vec::new();
    let prefix = format!("{}.owner-key", server_id);
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let Some(file) = path.file_name().and_then(|n| n.to_str()) else { continue };
        if file.starts_with(&prefix) && file.ends_with(".json") {
            keys.push(UserIdentity::load_or_create(&path)?);
        }
    }
    Ok(keys)
}

fn events_message(server_id: &str, events: Vec<GovEvent>) -> ServerMessage {
    ServerMessage::Events { server_id: server_id.to_string(), genesis: None, events, keys: Vec::new() }
}

/// Hash de carimbo em hex (64 caracteres) para bytes
pub fn parse_imprint(hex: &str) -> Option<[u8; 32]> {
    hex_decode_32(hex).ok()
}

/// Descrição curta de um evento (pubkeys abreviadas)
pub fn describe_event(event: &GovEvent) -> String {
    format!("{} {}", short_id(event.author()), describe_entry(&event.body.entry))
}

/// Descrição curta de uma ação de governança
pub fn describe_entry(entry: &Entry) -> String {
    match entry {
        Entry::SetName(name) => format!("renomeou para '{}'", name),
        Entry::AddChannel(c) => format!("criou o canal {}{}", if c.channel_type == ChannelType::Voice { "🔊 " } else { "#" }, c.name),
        Entry::RemoveChannel(name) => format!("removeu o canal {}", name),
        Entry::SetClosed(true) => "tornou o servidor privado (passaporte emitido por moderador)".into(),
        Entry::SetClosed(false) => "tornou o servidor público (passaporte automático)".into(),
        Entry::SetPassportPolicy { validity_secs, renewal_window_secs } => format!(
            "definiu passaportes: validade {}, renovação nos últimos {}",
            format_duration(Some(*validity_secs)),
            format_duration(Some(*renewal_window_secs))
        ),
        Entry::SetTimestampPolicy(policy) => format!(
            "definiu as autoridades de tempo: {}",
            if policy.tsas.is_empty() { "só testemunhas da rede".to_string() } else { policy.tsas.iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join(", ") }
        ),
        Entry::SetAccessPow { bits: 0 } => "dispensou a prova de trabalho nos pedidos de acesso".into(),
        Entry::SetAccessPow { bits } => format!("exigiu prova de trabalho nos pedidos de acesso ({} bits)", bits),
        Entry::SetConsolidationInterval { secs: 0 } => "desligou a consolidação automática".into(),
        Entry::SetConsolidationInterval { secs } => format!("definiu a consolidação a cada {}", format_duration(Some(*secs))),
        Entry::SetProtected { pubkey, protected: true } => format!("protegeu {}", short_id(pubkey)),
        Entry::SetProtected { pubkey, protected: false } => format!("tirou a proteção de {}", short_id(pubkey)),
        Entry::Ban { target, until, .. } => format!(
            "baniu {} ({})",
            short_id(target),
            until.map_or("permanente".to_string(), |u| format!("até {}", u))
        ),
        Entry::Unban { target } => format!("desfez o ban de {}", short_id(target)),
        Entry::Revoke { target, serial } => format!("revogou o passaporte {} de {}", serial, short_id(target)),
        Entry::Renounce { .. } => "saiu do servidor (renunciou ao passaporte)".into(),
        Entry::SetRootValidity { secs } => format!("definiu a validade da Chave do Servidor em {}", format_duration(Some(*secs))),
        Entry::Consolidate(c) => format!("consolidou o servidor (geração {})", c.generation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use timestamp::test_tsa::LocalTsa;

    const T0: u64 = 1_800_000_000;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("anarchord_test_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn pk(id: &UserIdentity) -> String {
        id.public_key_hex()
    }

    /// Entrega mensagens de um registro a outro, como a rede faria
    fn deliver(to: &mut ServerRegistry, messages: Vec<ServerMessage>, from: Option<&str>, now: u64) -> Vec<ServerEvent> {
        messages.into_iter().flat_map(|m| to.handle_message(m, from, now)).collect()
    }

    /// Mensagens a publicar nos eventos devolvidos
    fn replies(events: &[ServerEvent]) -> Vec<ServerMessage> {
        events
            .iter()
            .filter_map(|e| match e {
                ServerEvent::Reply { messages, .. } => Some(messages.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// Servidor de teste: TSA local na política, dono e a identidade pessoal dele
    struct Fixture {
        tsa: LocalTsa,
        owner_id: UserIdentity,
        owner: ServerRegistry,
        id: String,
    }

    impl Fixture {
        fn new() -> Self {
            let tsa = LocalTsa::new();
            let policy = TimestampPolicy { tsas: vec![tsa.trusted("local")], max_delay_secs: 600 };
            let owner_id = UserIdentity::generate();
            let mut owner = ServerRegistry::in_memory();
            let id = owner.create_with_policy("Rust Guild", &pk(&owner_id), policy, T0).unwrap();
            Self { tsa, owner_id, owner, id }
        }

        /// Carimba um evento da fila de `reg` em `at` e devolve as mensagens a publicar
        fn stamp(&self, reg: &mut ServerRegistry, submitted: Submitted, at: u64) -> Vec<ServerMessage> {
            let stamp = self.tsa.stamp(&submitted.imprint, at);
            replies(&reg.attach_stamp(&self.id, &submitted.imprint, &stamp, at))
        }

        /// Carimba um evento da fila do dono
        fn stamp_owner(&mut self, submitted: Submitted, at: u64) -> Vec<ServerMessage> {
            let stamp = self.tsa.stamp(&submitted.imprint, at);
            replies(&self.owner.attach_stamp(&self.id, &submitted.imprint, &stamp, at))
        }

        /// Novo registro sincronizado com o do dono
        fn member(&self, at: u64) -> ServerRegistry {
            let mut reg = ServerRegistry::in_memory();
            reg.join(&self.id).unwrap();
            sync(&self.owner, &mut reg, &self.id, at);
            reg
        }

        /// Passaporte emitido pelo dono, aceito no registro `to`
        fn passport(&self, to: &mut ServerRegistry, who: &UserIdentity, permissions: Vec<PassportPermission>, at: u64) -> ServerPassport {
            let passport = self.owner.issue_passport(&self.id, &self.owner_id, &pk(who), permissions, None, at).unwrap();
            assert!(to.accept_my_passport(&self.id, &pk(who), &passport, at));
            passport
        }
    }

    /// `to` pede o que falta a `from` pelo inventário
    fn sync(from: &ServerRegistry, to: &mut ServerRegistry, id: &str, at: u64) {
        let request = to.chain_request(id).unwrap();
        let mut from = clone_registry(from);
        let messages = replies(&from.handle_message(request, None, at));
        deliver(to, messages, None, at);
    }

    /// Cópia do registro em memória (para responder sem mutar o original nos testes)
    fn clone_registry(reg: &ServerRegistry) -> ServerRegistry {
        let mut copy = ServerRegistry::in_memory();
        for server in reg.list() {
            copy.join(&server.server_id).unwrap();
            let messages = server.sync_messages(true, &BTreeSet::new());
            deliver(&mut copy, messages, None, T0);
        }
        copy
    }

    #[test]
    fn test_topics_keep_lobby_compatible_and_namespace_servers() {
        assert_eq!(channel_topic(&Space::Lobby, "geral"), "p2p-anarchord/channel/geral");
        assert_eq!(voice_topic(&Space::Lobby, "sala"), "p2p-anarchord/voice/sala");
        let id = "ab".repeat(32);
        let space = Space::Server(id.clone());
        assert_eq!(channel_topic(&space, "geral"), format!("p2p-anarchord/server/{}/channel/geral", id));
        assert_eq!(parse_server_control_topic(&server_control_topic(&id)), Some(id.as_str()));
        assert_eq!(parse_server_control_topic(&channel_topic(&space, "geral")), None);
        assert_eq!(parse_server_content_topic(&channel_topic(&space, "geral")), Some(id.as_str()));
        assert_eq!(parse_server_channel_topic(&channel_topic(&space, "geral")), Some((id.as_str(), "geral")));
        assert_eq!(parse_server_channel_topic(&voice_topic(&space, "voz")), None, "voz não é canal de texto");
        assert_eq!(parse_server_access_topic(&access_topic(&id)), Some(id.as_str()));
        assert_eq!(parse_server_control_topic(&access_topic(&id)), None, "pedidos de acesso têm tópico próprio");
        assert_eq!(parse_server_content_topic(&access_topic(&id)), None, "pedidos de acesso não são cifrados");
        assert_eq!(parse_room_topic(&channel_topic(&space, "geral")), Some((id.as_str(), "geral")));
        assert_eq!(parse_room_topic(&voice_topic(&space, "voz")), Some((id.as_str(), "voz")));
        assert_eq!(parse_room_topic(&screen_topic(&space)), None, "tela não tem sala própria");
        assert_ne!(room_id(&id, "geral"), room_id(&id, "voz"), "cada sala tem o próprio grupo");
        assert_eq!(parse_server_channel_topic(&channel_topic(&Space::Lobby, "geral")), None);
        assert_eq!(parse_server_content_topic(&voice_topic(&space, "voz")), Some(id.as_str()));
        assert_eq!(parse_server_content_topic(&screen_topic(&space)), Some(id.as_str()));
        assert_eq!(parse_server_content_topic(&server_control_topic(&id)), None);
        assert_eq!(parse_server_content_topic(&channel_topic(&Space::Lobby, "geral")), None);
        assert_eq!(screen_topic(&Space::Lobby), "p2p-anarchord/screens");
        assert_eq!(screen_stream_topic(&Space::Lobby, "screen:ab12cd34"), "p2p-anarchord/screens/screen:ab12cd34");
        assert_eq!(parse_server_content_topic(&screen_stream_topic(&space, "screen:ab12cd34")), Some(id.as_str()), "quadros de servidor são cifrados");
    }

    #[test]
    fn test_member_syncs_genesis_and_policy_from_owner() {
        let mut owner = ServerRegistry::in_memory();
        let owner_pk = pk(&UserIdentity::generate());
        let id = owner.create("Rust Guild", &owner_pk, T0).unwrap();
        let mut member = ServerRegistry::in_memory();
        member.join(&id).unwrap();
        sync(&owner, &mut member, &id, T0);
        let server = member.get(&id).unwrap();
        assert!(server.has_chain());
        assert!(!server.is_owner());
        assert_eq!(server.name(), "Rust Guild");
        assert_eq!(server.default_text_channel().as_deref(), Some("geral"));
        assert!(server.is_allowed(&id, T0), "a chave do servidor sempre participa");
        let state = server.chain().state();
        assert_eq!(state.timestamp_policy.tsas[0].name, "FreeTSA", "FreeTSA sugerida na criação");
        assert!(state.protected.contains(&owner_pk), "o dono nasce protegido");
    }

    #[test]
    fn test_participation_requires_passport() {
        let f = Fixture::new();
        let mut member = f.member(T0);
        let guest = UserIdentity::generate();
        assert!(!member.get(&f.id).unwrap().is_allowed(&pk(&guest), T0), "sem passaporte não participa, nem em servidor público");
        let passport = f.owner.issue_passport(&f.id, &f.owner_id, &pk(&guest), PassportPermission::member(), None, T0).unwrap();
        assert!(member.get_mut(&f.id).unwrap().learn_passport(&passport, T0));
        assert!(member.get(&f.id).unwrap().is_allowed(&pk(&guest), T0 + 1));
    }

    /// Sem carimbo aceito, o evento não entra: nem na fila de quem cria, nem em quem recebe
    #[test]
    fn test_event_without_accepted_stamp_is_refused() {
        let mut f = Fixture::new();
        let mut member = f.member(T0);
        let submitted = f.owner.add_channel(&f.id.clone(), &f.owner_id, "jogos", ChannelType::Text, T0 + 1).unwrap();
        assert!(!f.owner.get(&f.id).unwrap().has_channel("jogos", ChannelType::Text), "na fila até o carimbo");
        assert_eq!(f.owner.get(&f.id).unwrap().outbox().count(), 1);

        // O evento publicado sem carimbo é recusado
        let raw = f.owner.get(&f.id).unwrap().outbox().next().unwrap().clone();
        let events = deliver(&mut member, vec![events_message(&f.id, vec![raw.clone()])], None, T0 + 2);
        assert!(events.iter().any(|e| matches!(e, ServerEvent::Ignored(r) if r.contains("carimbo"))), "{:?}", events);
        // Carimbo de TSA fora da política também não vale
        let mut foreign = raw.clone();
        foreign.add_stamp(LocalTsa::new().stamp(&raw.imprint(), T0 + 2));
        deliver(&mut member, vec![events_message(&f.id, vec![foreign])], None, T0 + 2);
        assert!(!member.get(&f.id).unwrap().has_channel("jogos", ChannelType::Text));

        let messages = f.stamp_owner(submitted, T0 + 2);
        assert!(f.owner.get(&f.id).unwrap().has_channel("jogos", ChannelType::Text));
        assert_eq!(f.owner.get(&f.id).unwrap().outbox().count(), 0);
        deliver(&mut member, messages, None, T0 + 3);
        assert!(member.get(&f.id).unwrap().has_channel("jogos", ChannelType::Text));
    }

    /// Moderador com ManageChannels cria canal com o dono offline; os outros membros aplicam
    #[test]
    fn test_moderator_manages_channels_without_owner() {
        let f = Fixture::new();
        let mut moderator_reg = f.member(T0);
        let mut member = f.member(T0);
        let moderator = UserIdentity::generate();
        f.passport(&mut moderator_reg, &moderator, vec![PassportPermission::EnterServer, PassportPermission::ManageChannels], T0);

        let submitted = moderator_reg.add_channel(&f.id, &moderator, "jogos", ChannelType::Text, T0 + 10).unwrap();
        let messages = f.stamp(&mut moderator_reg, submitted, T0 + 10);
        let events = deliver(&mut member, messages, None, T0 + 11);
        assert!(events.iter().any(|e| matches!(e, ServerEvent::EventApplied { .. })), "{:?}", events);
        assert!(member.get(&f.id).unwrap().has_channel("jogos", ChannelType::Text));

        // Sem a permissão de configuração, não muda o nome nem a política de tempo
        let result = moderator_reg.submit(&f.id, &moderator, Entry::SetName("x".into()), T0 + 12);
        assert!(matches!(result, Err(CommunityError::NotModerator)), "{:?}", result);
        let result = moderator_reg.submit(&f.id, &moderator, Entry::SetTimestampPolicy(TimestampPolicy::default()), T0 + 12);
        assert!(matches!(result, Err(CommunityError::NotModerator)));
    }

    /// Dois moderadores agem ao mesmo tempo: os dois eventos valem, e todos convergem
    #[test]
    fn test_simultaneous_moderators_converge() {
        let f = Fixture::new();
        let (a, b) = (UserIdentity::generate(), UserIdentity::generate());
        let mut reg_a = f.member(T0);
        let mut reg_b = f.member(T0);
        let perms = vec![PassportPermission::EnterServer, PassportPermission::ManageChannels];
        f.passport(&mut reg_a, &a, perms.clone(), T0);
        f.passport(&mut reg_b, &b, perms, T0);
        let sa = reg_a.add_channel(&f.id, &a, "a", ChannelType::Text, T0 + 5).unwrap();
        let sb = reg_b.add_channel(&f.id, &b, "b", ChannelType::Voice, T0 + 5).unwrap();
        let ma = f.stamp(&mut reg_a, sa, T0 + 5);
        let mb = f.stamp(&mut reg_b, sb, T0 + 5);
        deliver(&mut reg_a, mb, None, T0 + 6);
        deliver(&mut reg_b, ma, None, T0 + 6);
        for reg in [&reg_a, &reg_b] {
            let server = reg.get(&f.id).unwrap();
            assert!(server.has_channel("a", ChannelType::Text) && server.has_channel("b", ChannelType::Voice));
        }
        assert_eq!(reg_a.get(&f.id).unwrap().chain().inventory(), reg_b.get(&f.id).unwrap().chain().inventory());
    }

    /// Rede partida: em cada lado um moderador bane o outro. Ao juntar, vale o ban comprovado
    /// primeiro, em qualquer ordem de chegada; o do banido é anulado
    #[test]
    fn test_partition_merges_and_first_proven_ban_wins() {
        let f = Fixture::new();
        let (a, b) = (UserIdentity::generate(), UserIdentity::generate());
        let mut reg_a = f.member(T0);
        let mut reg_b = f.member(T0);
        let pa = f.passport(&mut reg_a, &a, PassportPermission::default_moderator(), T0);
        let pb = f.passport(&mut reg_b, &b, PassportPermission::default_moderator(), T0);
        reg_a.get_mut(&f.id).unwrap().learn_passport(&pb, T0);
        reg_b.get_mut(&f.id).unwrap().learn_passport(&pa, T0);

        let sa = reg_a.moderate(&f.id, &a, ModKind::Ban { until: None }, &pk(&b), "", T0 + 10).unwrap();
        let ma = f.stamp(&mut reg_a, sa, T0 + 10);
        let sb = reg_b.moderate(&f.id, &b, ModKind::Ban { until: None }, &pk(&a), "", T0 + 20).unwrap();
        let mb = f.stamp(&mut reg_b, sb, T0 + 20);

        let mut first = f.member(T0);
        deliver(&mut first, ma.clone(), None, T0 + 30);
        deliver(&mut first, mb.clone(), None, T0 + 30);
        let mut second = f.member(T0);
        deliver(&mut second, mb.clone(), None, T0 + 30);
        deliver(&mut second, ma.clone(), None, T0 + 30);
        deliver(&mut reg_b, ma, None, T0 + 30);
        for reg in [&first, &second, &reg_b] {
            let state = reg.get(&f.id).unwrap().chain().state();
            assert!(state.is_banned(&pk(&b), T0 + 31), "o ban mais antigo vale");
            assert!(!state.is_banned(&pk(&a), T0 + 31), "o ban de quem já estava banido é anulado");
        }
    }

    #[test]
    fn test_member_cannot_moderate_or_configure() {
        let f = Fixture::new();
        let mut member = f.member(T0);
        let nobody = UserIdentity::generate();
        assert!(matches!(member.add_channel(&f.id, &nobody, "x", ChannelType::Text, T0), Err(CommunityError::NoPassport)));
        let result = member.moderate(&f.id, &nobody, ModKind::Ban { until: None }, &"cd".repeat(32), "", T0);
        assert!(matches!(result, Err(CommunityError::NoPassport)));
        f.passport(&mut member, &nobody, PassportPermission::member(), T0);
        let result = member.moderate(&f.id, &nobody, ModKind::Ban { until: None }, &"cd".repeat(32), "", T0);
        assert!(matches!(result, Err(CommunityError::NotModerator)));
        assert!(matches!(member.add_channel(&f.id, &nobody, "x", ChannelType::Text, T0), Err(CommunityError::NotModerator)));
    }

    /// Protegidos (o dono, de início) e a chave do servidor não são banidos nem revogados por moderador
    #[test]
    fn test_protected_cannot_be_banned() {
        let mut f = Fixture::new();
        let mut member = f.member(T0);
        let moderator = UserIdentity::generate();
        f.passport(&mut member, &moderator, PassportPermission::default_moderator(), T0);
        let owner_pk = pk(&f.owner_id);
        let result = member.moderate(&f.id, &moderator, ModKind::Ban { until: None }, &owner_pk, "", T0 + 1);
        assert!(matches!(result, Err(CommunityError::Rejected(Rejection::ProtectedTarget))), "{:?}", result);
        let result = member.moderate(&f.id, &moderator, ModKind::Ban { until: None }, &f.id.clone(), "", T0 + 1);
        assert!(matches!(result, Err(CommunityError::Rejected(Rejection::ProtectedTarget))));

        // O dono protege outra pessoa; depois disso o ban do moderador é recusado por todos
        let vip = pk(&UserIdentity::generate());
        let id = f.id.clone();
        let s = f.owner.set_protected(&id, &f.owner_id.clone(), &vip, true, T0 + 2).unwrap();
        let messages = f.stamp_owner(s, T0 + 2);
        deliver(&mut member, messages, None, T0 + 3);
        let result = member.moderate(&f.id, &moderator, ModKind::Ban { until: None }, &vip, "", T0 + 4);
        assert!(matches!(result, Err(CommunityError::Rejected(Rejection::ProtectedTarget))));
        // Moderador comum não mexe na lista
        let result = member.set_protected(&f.id, &moderator, &vip, false, T0 + 5);
        assert!(matches!(result, Err(CommunityError::NotModerator)));
    }

    /// Desfazer um ban antes do prazo: só quem aplicou
    #[test]
    fn test_only_ban_author_unbans() {
        let f = Fixture::new();
        let (a, b) = (UserIdentity::generate(), UserIdentity::generate());
        let mut reg_a = f.member(T0);
        let mut reg_b = f.member(T0);
        f.passport(&mut reg_a, &a, PassportPermission::default_moderator(), T0);
        f.passport(&mut reg_b, &b, PassportPermission::default_moderator(), T0);
        let target = pk(&UserIdentity::generate());
        let s = reg_a.moderate(&f.id, &a, ModKind::Ban { until: None }, &target, "", T0 + 1).unwrap();
        let messages = f.stamp(&mut reg_a, s, T0 + 1);
        deliver(&mut reg_b, messages, None, T0 + 2);
        let result = reg_b.moderate(&f.id, &b, ModKind::Unban, &target, "", T0 + 3);
        assert!(matches!(result, Err(CommunityError::Rejected(Rejection::NotBanAuthor))), "{:?}", result);
        let s = reg_a.moderate(&f.id, &a, ModKind::Unban, &target, "", T0 + 3).unwrap();
        let messages = f.stamp(&mut reg_a, s, T0 + 3);
        deliver(&mut reg_b, messages, None, T0 + 4);
        assert!(!reg_b.get(&f.id).unwrap().is_banned(&target, T0 + 5));
    }

    /// O desban chega antes do ban (ordem de entrega trocada): fica guardado e vale quando o ban chega
    #[test]
    fn test_unban_arriving_before_ban_is_kept() {
        let f = Fixture::new();
        let a = UserIdentity::generate();
        let mut reg_a = f.member(T0);
        f.passport(&mut reg_a, &a, PassportPermission::default_moderator(), T0);
        let target = pk(&UserIdentity::generate());
        let s = reg_a.moderate(&f.id, &a, ModKind::Ban { until: None }, &target, "", T0 + 1).unwrap();
        let ban = f.stamp(&mut reg_a, s, T0 + 1);
        let s = reg_a.moderate(&f.id, &a, ModKind::Unban, &target, "", T0 + 2).unwrap();
        let unban = f.stamp(&mut reg_a, s, T0 + 2);
        let mut other = f.member(T0);
        deliver(&mut other, unban, None, T0 + 3);
        deliver(&mut other, ban, None, T0 + 3);
        assert!(!other.get(&f.id).unwrap().is_banned(&target, T0 + 4));
        assert_eq!(other.get(&f.id).unwrap().chain().inventory(), reg_a.get(&f.id).unwrap().chain().inventory());
    }

    #[test]
    fn test_public_server_answers_access_requests_but_not_for_banned() {
        let mut f = Fixture::new();
        let id = f.id.clone();
        let issuer = f.owner_id.clone();
        let guest = pk(&UserIdentity::generate());
        let Some(ServerMessage::PassportOffer { passport, .. }) = f.owner.answer_access_request(&id, &issuer, &guest, T0 + 1) else { panic!() };
        assert_eq!(passport.body.expires_at, Some(T0 + 1 + 7 * 86_400), "passaporte automático usa a validade da política");
        f.owner.get_mut(&id).unwrap().learn_passport(&passport, T0 + 1);
        let Some(ServerMessage::PassportOffer { passport: again, .. }) = f.owner.answer_access_request(&id, &issuer, &guest, T0 + 30) else { panic!() };
        assert_eq!(again.body.serial, passport.body.serial, "reenvia, não emite outro");

        let banned = pk(&UserIdentity::generate());
        let s = f.owner.moderate(&id, &issuer, ModKind::Ban { until: Some(T0 + 3600) }, &banned, "", T0 + 2).unwrap();
        f.stamp_owner(s, T0 + 2);
        assert!(f.owner.answer_access_request(&id, &issuer, &banned, T0 + 3).is_none(), "ban em vigor: sem passaporte automático");
        assert!(f.owner.answer_access_request(&id, &issuer, &banned, T0 + 3600).is_some(), "prazo acabou: volta a receber");

        let s = f.owner.set_closed(&id, &issuer, true, T0 + 4).unwrap();
        f.stamp_owner(s, T0 + 4);
        assert!(f.owner.answer_access_request(&id, &issuer, &pk(&UserIdentity::generate()), T0 + 5).is_none(), "privado: só emissão manual");
    }

    #[test]
    fn test_moderator_without_issue_member_does_not_answer_access_requests() {
        let f = Fixture::new();
        let mut member = f.member(T0);
        let plain = UserIdentity::generate();
        f.passport(&mut member, &plain, PassportPermission::member(), T0);
        assert!(member.answer_access_request(&f.id, &plain, &pk(&UserIdentity::generate()), T0 + 1).is_none());
        let moderator = UserIdentity::generate();
        f.passport(&mut member, &moderator, PassportPermission::default_moderator(), T0);
        assert!(member.answer_access_request(&f.id, &moderator, &pk(&UserIdentity::generate()), T0 + 1).is_some());
    }

    #[test]
    fn test_private_server_does_not_serve_outsiders() {
        let mut f = Fixture::new();
        let id = f.id.clone();
        let s = f.owner.set_closed(&id, &f.owner_id.clone(), true, T0 + 1).unwrap();
        f.stamp_owner(s, T0 + 1);
        let insider = UserIdentity::generate();
        let passport = f.owner.issue_passport(&id, &f.owner_id, &pk(&insider), PassportPermission::member(), None, T0 + 2).unwrap();

        let outsider = pk(&UserIdentity::generate());
        let request = ServerMessage::Inventory { server_id: id.clone(), has_genesis: false, have: Vec::new(), passport: None };
        assert!(matches!(f.owner.handle_message(request.clone(), Some(&outsider), T0 + 3)[0], ServerEvent::Ignored(_)));
        assert!(matches!(f.owner.handle_message(request, None, T0 + 3)[0], ServerEvent::Ignored(_)), "sem autor conhecido");
        let with_passport = ServerMessage::Inventory { server_id: id.clone(), has_genesis: false, have: Vec::new(), passport: Some(passport) };
        assert!(matches!(f.owner.handle_message(with_passport, Some(&pk(&insider)), T0 + 3)[0], ServerEvent::Reply { .. }));
    }

    /// Inventário: quem já tem tudo não recebe nada; quem tem a mais faz o outro pedir também
    #[test]
    fn test_inventory_sends_only_what_is_missing() {
        let mut f = Fixture::new();
        let id = f.id.clone();
        let mut member = f.member(T0);
        let request = member.chain_request(&id).unwrap();
        assert!(f.owner.handle_message(request, None, T0).is_empty(), "nada a mandar");

        let moderator = UserIdentity::generate();
        f.passport(&mut member, &moderator, vec![PassportPermission::EnterServer, PassportPermission::ManageChannels], T0);
        let s = member.add_channel(&id, &moderator, "novo", ChannelType::Text, T0 + 1).unwrap();
        f.stamp(&mut member, s, T0 + 1);
        // O membro tem um evento que o dono não viu: o dono responde pedindo
        let request = member.chain_request(&id).unwrap();
        let reply = replies(&f.owner.handle_message(request, None, T0 + 2));
        assert!(matches!(reply.as_slice(), [ServerMessage::Inventory { .. }]), "{:?}", reply);
        let missing = replies(&deliver(&mut member, reply, None, T0 + 2));
        deliver(&mut f.owner, missing, None, T0 + 2);
        assert!(f.owner.get(&id).unwrap().has_channel("novo", ChannelType::Text));
    }

    #[test]
    fn test_member_without_chain_keeps_offered_passport_for_inventory() {
        let f = Fixture::new();
        let newcomer = UserIdentity::generate();
        let mut fresh = ServerRegistry::in_memory();
        fresh.join(&f.id).unwrap();
        let passport = f.owner.issue_passport(&f.id, &f.owner_id, &pk(&newcomer), PassportPermission::member(), None, T0).unwrap();
        assert!(fresh.accept_my_passport(&f.id, &pk(&newcomer), &passport, T0), "aceito só pela assinatura");
        let older = f.owner.issue_passport(&f.id, &f.owner_id, &pk(&newcomer), PassportPermission::member(), None, T0 - 10).unwrap();
        assert!(!fresh.accept_my_passport(&f.id, &pk(&newcomer), &older, T0), "reenvio antigo não substitui o atual");
        let Some(ServerMessage::Inventory { passport: Some(sent), has_genesis: false, .. }) = fresh.chain_request(&f.id) else { panic!() };
        assert_eq!(sent, passport);
    }

    /// Testemunha da rede carimba o evento da fila: ele entra no registro e é publicado
    #[test]
    fn test_witness_stamp_completes_queued_event() {
        let f = Fixture::new();
        let mut member = f.member(T0);
        let moderator = UserIdentity::generate();
        f.passport(&mut member, &moderator, PassportPermission::default_moderator(), T0);
        let s = member.moderate(&f.id, &moderator, ModKind::Ban { until: None }, &pk(&UserIdentity::generate()), "", T0 + 1).unwrap();

        let imprint = timestamp::hex(&s.imprint);
        let witness = UserIdentity::generate();
        let mut witness_registry = f.member(T0);
        assert!(witness_registry.witness_stamp(&f.id, &witness, &imprint, "n", T0 + 2).is_none(), "sem passaporte não testemunha");
        f.passport(&mut witness_registry, &witness, PassportPermission::member(), T0);
        let stamp = witness_registry.witness_stamp(&f.id, &witness, &imprint, "n", T0 + 2).unwrap();
        let events = deliver(&mut member, vec![stamp], Some(&pk(&witness)), T0 + 3);
        assert!(events.iter().any(|e| matches!(e, ServerEvent::EventApplied { .. })), "{:?}", events);
        assert_eq!(member.get(&f.id).unwrap().outbox().count(), 0);
        assert!(!replies(&events).is_empty(), "pronto para publicar");

        // O próprio autor não testemunha por si
        let s = member.moderate(&f.id, &moderator, ModKind::Ban { until: None }, &pk(&UserIdentity::generate()), "", T0 + 4).unwrap();
        let mut self_reg = f.member(T0);
        f.passport(&mut self_reg, &moderator, PassportPermission::default_moderator(), T0);
        let own = self_reg.witness_stamp(&f.id, &moderator, &timestamp::hex(&s.imprint), "n", T0 + 5).unwrap();
        deliver(&mut member, vec![own], None, T0 + 5);
        assert_eq!(member.get(&f.id).unwrap().outbox().count(), 1, "continua esperando carimbo aceito");
    }

    #[test]
    fn test_temporary_ban_expires() {
        let mut f = Fixture::new();
        let id = f.id.clone();
        let mut member = f.member(T0);
        let target = pk(&UserIdentity::generate());
        let s = f.owner.moderate(&id, &f.owner_id.clone(), ModKind::Ban { until: Some(T0 + 3600) }, &target, "1h", T0).unwrap();
        let messages = f.stamp_owner(s, T0);
        deliver(&mut member, messages, None, T0 + 1);
        assert!(member.get(&id).unwrap().is_banned(&target, T0 + 10));
        assert!(!member.get(&id).unwrap().is_banned(&target, T0 + 3600));
    }

    /// A política de tempo vale para os carimbos da época: trocar de TSA não invalida o passado
    #[test]
    fn test_tsa_policy_change_keeps_past_events() {
        let mut f = Fixture::new();
        let id = f.id.clone();
        let owner = f.owner_id.clone();
        let s = f.owner.add_channel(&id, &owner, "antigo", ChannelType::Text, T0 + 1).unwrap();
        let old_event = f.stamp_owner(s, T0 + 1);

        let other = LocalTsa::new();
        let s = f.owner.add_tsa(&id, &owner, other.trusted("Minha TSA"), T0 + 2).unwrap();
        f.stamp_owner(s, T0 + 2);
        let names: Vec<String> = f.owner.get(&id).unwrap().chain().state().timestamp_policy.tsas.iter().map(|t| t.name.clone()).collect();
        assert_eq!(names, vec!["local".to_string(), "Minha TSA".to_string()]);
        let s = f.owner.remove_tsa(&id, &owner, "local", T0 + 3).unwrap();
        f.stamp_owner(s, T0 + 3);
        assert_eq!(f.owner.get(&id).unwrap().chain().state().timestamp_policy.tsas.len(), 1);

        // Quem sincroniza depois aceita o evento antigo, carimbado pela TSA que valia na época
        let mut late = f.member(T0 + 10);
        deliver(&mut late, old_event, None, T0 + 10);
        assert!(late.get(&id).unwrap().has_channel("antigo", ChannelType::Text));
        // Evento novo com a TSA removida não vale mais
        let s = f.owner.add_channel(&id, &owner, "novo", ChannelType::Text, T0 + 20).unwrap();
        assert!(f.stamp_owner(s.clone(), T0 + 20).is_empty());
        let stamp = other.stamp(&s.imprint, T0 + 21);
        assert!(!replies(&f.owner.attach_stamp(&id, &s.imprint, &stamp, T0 + 21)).is_empty());

        let bad = TrustedTsa { name: "x".into(), url: "http://x".into(), spki_der: vec![1, 2, 3] };
        assert!(matches!(f.owner.add_tsa(&id, &owner, bad, T0 + 30), Err(CommunityError::InvalidTsa(_))));
    }

    #[test]
    fn test_history_lists_every_change() {
        let mut f = Fixture::new();
        let id = f.id.clone();
        let owner = f.owner_id.clone();
        let s = f.owner.add_channel(&id, &owner, "jogos", ChannelType::Text, T0 + 1).unwrap();
        f.stamp_owner(s, T0 + 1);
        let s = f.owner.set_closed(&id, &owner, true, T0 + 2).unwrap();
        f.stamp_owner(s, T0 + 2);
        let history = f.owner.history(&id);
        assert_eq!(history.len(), 3);
        assert!(history[0].description.contains("criado 'Rust Guild'"));
        assert!(history[1].description.contains("#jogos"));
        assert!(history[2].description.contains("privado"));
        assert!(history.windows(2).all(|w| w[0].timestamp <= w[1].timestamp));
    }

    #[test]
    fn test_persistence_restores_events_outbox_ownership_and_passports() {
        let dir = temp_dir("events_persist");
        let tsa = LocalTsa::new();
        let policy = TimestampPolicy { tsas: vec![tsa.trusted("local")], max_delay_secs: 600 };
        let owner = UserIdentity::generate();
        let target = pk(&UserIdentity::generate());
        let id = {
            let mut reg = ServerRegistry::load(&dir, T0).unwrap();
            let id = reg.create_with_policy("Persistente", &pk(&owner), policy, T0).unwrap();
            let s = reg.add_channel(&id, &owner, "jogos", ChannelType::Voice, T0 + 1).unwrap();
            reg.attach_stamp(&id, &s.imprint, &tsa.stamp(&s.imprint, T0 + 1), T0 + 1);
            let s = reg.moderate(&id, &owner, ModKind::Ban { until: None }, &target, "", T0 + 2).unwrap();
            reg.attach_stamp(&id, &s.imprint, &tsa.stamp(&s.imprint, T0 + 2), T0 + 2);
            // Fica na fila (sem carimbo ainda)
            reg.add_channel(&id, &owner, "fila", ChannelType::Text, T0 + 3).unwrap();
            id
        };
        let mut reg = ServerRegistry::load(&dir, T0 + 5).unwrap();
        let server = reg.get(&id).unwrap();
        assert!(server.is_owner(), "chave de dono continua no disco");
        assert!(server.has_channel("jogos", ChannelType::Voice));
        assert!(server.is_banned(&target, T0 + 5));
        assert_eq!(server.outbox().count(), 1, "a fila sobrevive");
        assert!(server.my_passport().is_some(), "o próprio passaporte persiste");
        let stored = std::fs::read_to_string(dir.join(format!("{}.server.json", id))).unwrap();
        assert!(!stored.contains("\"passports\""), "passaportes de terceiros não vão para o disco");
        let parsed: StoredServer = serde_json::from_str(&stored).unwrap();
        assert_eq!(parsed.event_passports.len(), 1, "o passaporte do autor aparece uma vez só, referenciado pelos eventos");
        assert_eq!(parsed.events.len() + parsed.outbox.len(), 3);
        assert_eq!(reg.find("persistente").map(|s| s.server_id.clone()), Some(id.clone()));

        assert!(reg.leave(&id));
        assert!(dir.join(format!("{}.owner-key.json", id)).exists(), "sair nunca apaga a chave");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Sair renuncia ao passaporte: publicado quando o carimbo chega, com alguns reenvios na
    /// primeira hora. Servidor público emite outro; privado não.
    #[test]
    fn test_leaving_renounces_passport() {
        let mut f = Fixture::new();
        let id = f.id.clone();
        let issuer = f.owner_id.clone();
        let carol = UserIdentity::generate();
        let mut carol_reg = f.member(T0);
        let Some(ServerMessage::PassportOffer { passport, .. }) = f.owner.answer_access_request(&id, &issuer, &pk(&carol), T0) else { panic!() };
        f.owner.get_mut(&id).unwrap().remember_issued(&passport, T0);
        assert!(carol_reg.accept_my_passport(&id, &pk(&carol), &passport, T0));

        let (imprint, tsas) = carol_reg.leave_renouncing(&id, &carol, T0 + 10).expect("membro renuncia ao sair");
        assert_eq!(tsas.len(), 1, "quem sai ainda sabe a quem pedir o carimbo");
        assert!(carol_reg.get(&id).is_none(), "deixou de acompanhar");
        assert!(carol_reg.pending_renounces(T0 + 10 + 60).is_empty(), "sem carimbo, nada a reenviar");
        let renounce = replies(&carol_reg.attach_stamp(&id, &imprint, &f.tsa.stamp(&imprint, T0 + 11), T0 + 11));
        assert_eq!(renounce.len(), 1, "publica no primeiro carimbo");
        let late: usize = [5 * 60, 15 * 60, 30 * 60].iter().map(|after| carol_reg.pending_renounces(T0 + 10 + after).len()).sum();
        assert_eq!(late, 3);
        assert!(carol_reg.pending_renounces(T0 + 10 + 86_400).is_empty(), "depois da primeira hora, desistiu");

        deliver(&mut f.owner, renounce, Some(&pk(&carol)), T0 + 12);
        assert!(!f.owner.get(&id).unwrap().is_allowed(&pk(&carol), T0 + 13), "passaporte renunciado não vale");
        let Some(ServerMessage::PassportOffer { passport: fresh, .. }) = f.owner.answer_access_request(&id, &issuer, &pk(&carol), T0 + 14) else { panic!() };
        assert_ne!(fresh.body.serial, passport.body.serial, "público: emite outro, não reenvia o renunciado");

        // Quem tem a Chave do Servidor não renuncia
        assert!(f.owner.leave_renouncing(&id, &issuer, T0 + 19).is_none());
    }

    /// Prova de trabalho do pedido de acesso (#91): exigida só quando a política liga
    #[test]
    fn test_access_proof_follows_server_policy() {
        let mut f = Fixture::new();
        let id = f.id.clone();
        let carol = UserIdentity::generate();
        let carol_pk = pk(&carol);
        assert_eq!(f.owner.access_proof_ok(&id, &carol_pk, None, T0), None, "sem política: prova não é exigida");
        assert!(f.owner.access_policy(&id, T0).is_none());

        let s = f.owner.set_access_pow(&id, &f.owner_id.clone(), 8, T0 + 1).unwrap();
        f.stamp_owner(s, T0 + 1);
        assert_eq!(f.owner.access_proof_ok(&id, &carol_pk, None, T0 + 2), Some(false), "política ligada: sem prova não passa");
        let Some(ServerMessage::AccessPolicy { pow_bits: 8, tsas, .. }) = f.owner.access_policy(&id, T0 + 2) else { panic!() };
        assert_eq!(tsas.len(), 1, "quem pede recebe as autoridades aceitas");

        let make = |stamp_at: u64, authority: &LocalTsa, bits: u8| {
            let seed = "semente";
            let stamp = authority.stamp(&access_proof::seed_imprint(&id, &carol_pk, seed), stamp_at);
            access_proof::AccessProof::sign(&carol, access_proof::compute(&id, &carol_pk, seed, stamp, bits))
        };
        let now = T0 + 100;
        assert_eq!(f.owner.access_proof_ok(&id, &carol_pk, Some(&make(now - 10, &f.tsa, 8)), now), Some(true), "prova válida");
        assert_eq!(f.owner.access_proof_ok(&id, &carol_pk, Some(&make(now - 2000, &f.tsa, 8)), now), Some(false), "carimbo velho");
        assert_eq!(f.owner.access_proof_ok(&id, &carol_pk, Some(&make(now - 10, &LocalTsa::new(), 8)), now), Some(false), "TSA fora da política");
        assert_eq!(f.owner.access_proof_ok(&id, &carol_pk, Some(&make(now - 10, &f.tsa, 2)), now), Some(false), "dificuldade abaixo da política");
        let other = pk(&UserIdentity::generate());
        assert_eq!(f.owner.access_proof_ok(&id, &other, Some(&make(now - 10, &f.tsa, 8)), now), Some(false), "prova de outra pessoa");
    }

    /// Sair e voltar ao próprio servidor: a chave de dono ficou no disco e a posse volta
    #[test]
    fn test_rejoining_own_server_restores_ownership() {
        let dir = temp_dir("rejoin_owner");
        let mut reg = ServerRegistry::load(&dir, T0).unwrap();
        let id = reg.create("Minha", &pk(&UserIdentity::generate()), T0).unwrap();
        assert!(reg.leave(&id));
        assert!(reg.join(&id).unwrap());
        assert!(reg.get(&id).unwrap().is_owner(), "a chave salva devolve a posse");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tampered_file_drops_altered_event() {
        let dir = temp_dir("events_tamper");
        let tsa = LocalTsa::new();
        let policy = TimestampPolicy { tsas: vec![tsa.trusted("local")], max_delay_secs: 600 };
        let owner = UserIdentity::generate();
        let id = {
            let mut reg = ServerRegistry::load(&dir, T0).unwrap();
            let id = reg.create_with_policy("Original", &pk(&owner), policy, T0).unwrap();
            let s = reg.add_channel(&id, &owner, "segredo", ChannelType::Text, T0 + 1).unwrap();
            reg.attach_stamp(&id, &s.imprint, &tsa.stamp(&s.imprint, T0 + 1), T0 + 1);
            id
        };
        let path = dir.join(format!("{}.server.json", id));
        let text = std::fs::read_to_string(&path).unwrap().replace("segredo", "alterado");
        std::fs::write(&path, text).unwrap();
        let reg = ServerRegistry::load(&dir, T0 + 2).unwrap();
        let server = reg.get(&id).unwrap();
        assert_eq!(server.chain().events().count(), 0, "evento adulterado descartado");
        assert!(!server.has_channel("alterado", ChannelType::Text));
        assert_eq!(server.name(), "Original", "a Genesis continua");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Consolidação (#52): vira o novo ponto de partida; quem chega depois recebe só ela e o que
    /// veio depois; evento com carimbo anterior a ela é recusado
    #[test]
    fn test_consolidation_becomes_new_genesis() {
        let mut f = Fixture::new();
        let id = f.id.clone();
        let owner = f.owner_id.clone();
        let mut member = f.member(T0);
        let moderator = UserIdentity::generate();
        f.passport(&mut member, &moderator, vec![PassportPermission::EnterServer, PassportPermission::ManageChannels], T0);
        // Evento antigo guardado sem publicar
        let s = member.add_channel(&id, &moderator, "guardado", ChannelType::Text, T0 + 5).unwrap();
        let held = f.stamp(&mut member, s, T0 + 5);

        let mut published = Vec::new();
        for (i, name) in ["a", "b"].iter().enumerate() {
            let s = f.owner.add_channel(&id, &owner, name, ChannelType::Text, T0 + 10 + i as u64).unwrap();
            published.extend(f.stamp_owner(s, T0 + 10 + i as u64));
        }
        let banned = pk(&UserIdentity::generate());
        let s = f.owner.moderate(&id, &owner, ModKind::Ban { until: None }, &banned, "", T0 + 15).unwrap();
        published.extend(f.stamp_owner(s, T0 + 15));
        let s = f.owner.consolidate(&id, &owner, T0 + 20).unwrap();
        let consolidation = f.stamp_owner(s, T0 + 20);
        assert_eq!(f.owner.get(&id).unwrap().chain().state().generation, 1);
        assert_eq!(f.owner.get(&id).unwrap().chain().events().count(), 0, "histórico anterior esquecido");
        let s = f.owner.add_channel(&id, &owner, "depois", ChannelType::Text, T0 + 30).unwrap();
        f.stamp_owner(s, T0 + 30);

        // Membro que tinha o histórico confere o estado consolidado
        deliver(&mut member, published, None, T0 + 21);
        let events = deliver(&mut member, consolidation, None, T0 + 21);
        assert!(events.iter().any(|e| matches!(e, ServerEvent::EventApplied { .. })), "{:?}", events);
        assert_eq!(member.get(&id).unwrap().chain().state().generation, 1);

        // Quem chega depois recebe a consolidação e o evento seguinte
        let late = f.member(T0 + 40);
        let state = late.get(&id).unwrap().chain().state();
        assert!(state.channels.iter().any(|c| c.name == "a") && state.channels.iter().any(|c| c.name == "depois"));
        assert!(state.is_banned(&banned, T0 + 40), "bans atravessam a consolidação");
        assert_eq!(f.owner.snapshot(&id).iter().map(|m| match m { ServerMessage::Events { events, .. } => events.len(), _ => 0 }).sum::<usize>(), 2);

        // O evento guardado (carimbo anterior à consolidação) é recusado
        let mut late = late;
        deliver(&mut late, held, None, T0 + 41);
        assert!(!late.get(&id).unwrap().has_channel("guardado", ChannelType::Text));
    }

    /// Consolidação adulterada (estado que não confere com o histórico) é recusada por quem o tem
    #[test]
    fn test_consolidation_with_wrong_state_is_refused() {
        let mut f = Fixture::new();
        let id = f.id.clone();
        let owner = f.owner_id.clone();
        let s = f.owner.add_channel(&id, &owner, "a", ChannelType::Text, T0 + 1).unwrap();
        let first = f.stamp_owner(s, T0 + 1);
        let mut member = f.member(T0);
        deliver(&mut member, first, None, T0 + 2);
        let mut fake = f.owner.get(&id).unwrap().chain().consolidation();
        fake.snapshot.config.name = "Tomado".into();
        let s = f.owner.submit(&id, &owner, Entry::Consolidate(Box::new(fake)), T0 + 3).unwrap();
        let stamp = f.tsa.stamp(&s.imprint, T0 + 3);
        let events = f.owner.attach_stamp(&id, &s.imprint, &stamp, T0 + 3);
        assert!(events.iter().any(|e| matches!(e, ServerEvent::EventRejected { .. })), "{:?}", events);
        assert!(replies(&events).is_empty(), "nada publicado");
        assert_eq!(f.owner.get(&id).unwrap().chain().state().generation, 0);
        assert_eq!(member.get(&id).unwrap().chain().state().name, "Rust Guild");
    }

    /// Transferência da Chave do Servidor (#99) pelos três passos (proposta, aceitação na máquina de
    /// quem recebe, elo assinado e carimbado pela TSA). O id não muda; a posse passa; quem entregou
    /// sai da lista de protegidos e quem recebeu entra
    fn transfer_to(f: &mut Fixture, to: &mut ServerRegistry, new_owner: &UserIdentity, at: u64) -> Vec<ServerMessage> {
        let id = f.id.clone();
        let offer = f.owner.offer_transfer(&id, &f.owner_id, &pk(new_owner)).unwrap();
        let ServerMessage::KeyTransferAccept { body, new_key_signature, .. } = to.accept_transfer_offer(&id, new_owner, &offer, at).unwrap() else {
            panic!("aceitação esperada")
        };
        let owner_id = f.owner_id.clone();
        let s = f.owner.complete_transfer(&id, &owner_id, body, new_key_signature).unwrap();
        let messages = f.stamp_owner(s, at);
        deliver(to, messages.clone(), None, at);
        messages
    }

    /// Passaporte emitido pela raiz atual do dono, com carimbo de TSA em `stamp_at` (se houver)
    fn root_passport(f: &Fixture, holder: &UserIdentity, issued_at: u64, stamp_at: Option<u64>) -> ServerPassport {
        let mut p = f.owner.issue_passport(&f.id, &f.owner_id, &pk(holder), PassportPermission::member(), None, issued_at).unwrap();
        if let Some(at) = stamp_at {
            let imprint = p.imprint();
            p.add_stamp_to_link(&imprint, &f.tsa.stamp(&imprint, at));
        }
        p
    }

    #[test]
    fn test_server_key_transfer() {
        let mut f = Fixture::new();
        let id = f.id.clone();
        let b = UserIdentity::generate();
        let mut b_reg = f.member(T0);
        let m = UserIdentity::generate();
        // Emitidos pela chave antiga antes da transferência: um carimbado pela TSA, outro não
        let stamped = root_passport(&f, &m, T0 + 1, Some(T0 + 1));
        let unstamped = root_passport(&f, &m, T0 + 1, None);

        // Aceitação não pode ser forjada nem vir de outra pessoa
        let offer = f.owner.offer_transfer(&id, &f.owner_id, &pk(&b)).unwrap();
        assert!(b_reg.accept_transfer_offer(&id, &UserIdentity::generate(), &offer, T0 + 2).is_err(), "proposta é para B");
        assert!(f.owner.offer_transfer(&id, &UserIdentity::generate(), &pk(&b)).is_ok(), "quem tem a chave propõe");
        assert!(b_reg.offer_transfer(&id, &b, &pk(&f.owner_id)).is_err(), "sem a chave não propõe");

        transfer_to(&mut f, &mut b_reg, &b, T0 + 10);
        let t = T0 + 10;
        assert!(!f.owner.get(&id).unwrap().is_owner(), "a chave antiga deixou de ser a raiz");
        let server = b_reg.get(&id).unwrap();
        assert!(server.is_owner(), "quem recebeu passa a emitir");
        let state = server.chain().state();
        assert_eq!(state.roots.len(), 2);
        assert_eq!(state.roots[0].until, Some(t), "marco T");
        assert!(state.protected.contains(&pk(&b)) && !state.protected.contains(&pk(&f.owner_id)), "proteção passa ao novo dono");
        assert_eq!(server.server_id, id, "o id não muda");

        // Marco: elo da chave antiga só vale com carimbo de TSA anterior a T
        assert!(state.verify_passport(&stamped, t + 5).is_ok(), "comprovado antes de T");
        assert!(state.verify_passport(&unstamped, t + 5).is_err(), "sem prova: sem carência");
        // O antigo dono ainda tem a chave antiga e assina com data retroativa
        let old_key = f.owner.get(&id).unwrap().stored_keys.first().unwrap().clone();
        let mut backdated = ServerPassport::issue_root_for(&id, &old_key, &pk(&m), PassportPermission::all(), T0 + 1, None);
        let imprint = backdated.imprint();
        backdated.add_stamp_to_link(&imprint, &f.tsa.stamp(&imprint, t + 20));
        assert!(f.owner.issue_passport(&id, &f.owner_id, &pk(&m), PassportPermission::member(), None, t + 20).is_err(), "o antigo dono não emite mais");
        assert!(state.verify_passport(&backdated, t + 30).is_err(), "data retroativa carimbada depois de T não vale");
        // ... e nada da chave antiga vale depois do vencimento dela
        let old_expiry = state.roots[0].expires_at;
        assert!(state.verify_passport(&stamped, old_expiry).is_err(), "morre no vencimento da chave antiga");
        let new_passport = b_reg.issue_passport(&id, &b, &pk(&m), PassportPermission::member(), None, t + 40).unwrap();
        assert!(state.verify_passport(&new_passport, t + 50).is_ok());
    }

    /// Nada é vitalício: o passaporte do dono vence com a raiz; a renovação estende
    #[test]
    fn test_root_expiry_and_renewal() {
        let mut f = Fixture::new();
        let id = f.id.clone();
        let m = UserIdentity::generate();
        let p = root_passport(&f, &m, T0 + 1, None);
        let expires = f.owner.get(&id).unwrap().chain().state().root_expires_at();
        assert_eq!(expires, T0 + keychain::DEFAULT_ROOT_VALIDITY_SECS, "90 dias por padrão");
        let state = f.owner.get(&id).unwrap().chain().state();
        assert!(state.verify_passport(&p, expires - 1).is_ok());
        assert!(state.verify_passport(&p, expires).is_err(), "venceu com a raiz");

        let mut member = f.member(T0);
        let s = f.owner.renew_root(&id, T0 + 60 * 86_400).unwrap();
        let messages = f.stamp_owner(s, T0 + 60 * 86_400);
        assert!(!messages.is_empty(), "renovação publicada");
        deliver(&mut member, messages, None, T0 + 60 * 86_400);
        for reg in [&f.owner, &member] {
            let state = reg.get(&id).unwrap().chain().state();
            assert_eq!(state.root_expires_at(), T0 + 150 * 86_400);
            assert!(state.verify_passport(&p, expires + 1).is_ok(), "renovada: volta a valer");
        }
        assert!(f.owner.get(&id).unwrap().outbox().count() == 0);
        assert!(member.renew_root(&id, T0).is_err(), "só quem tem a chave renova");
    }

    /// A consolidação não carrega a posse: quem entra depois resolve as raízes pela corrente de chaves
    #[test]
    fn test_newcomer_after_consolidation_gets_ownership_from_key_chain() {
        let mut f = Fixture::new();
        let id = f.id.clone();
        let b = UserIdentity::generate();
        let mut b_reg = f.member(T0);
        transfer_to(&mut f, &mut b_reg, &b, T0 + 10);
        let s = b_reg.add_channel(&id, &b, "novo", ChannelType::Text, T0 + 20).unwrap();
        let stamp = f.tsa.stamp(&s.imprint, T0 + 20);
        b_reg.attach_stamp(&id, &s.imprint, &stamp, T0 + 20);
        let s = b_reg.consolidate(&id, &b, T0 + 30).unwrap();
        let stamp = f.tsa.stamp(&s.imprint, T0 + 30);
        b_reg.attach_stamp(&id, &s.imprint, &stamp, T0 + 30);
        assert_eq!(b_reg.get(&id).unwrap().chain().state().generation, 1);

        let mut late = ServerRegistry::in_memory();
        late.join(&id).unwrap();
        sync(&b_reg, &mut late, &id, T0 + 40);
        let state = late.get(&id).unwrap().chain().state();
        assert_eq!(state.generation, 1);
        assert_eq!(state.current_root(), b_reg.get(&id).unwrap().owner_key().unwrap().public_key_hex(), "posse pela corrente de chaves");
        assert!(state.channels.iter().any(|c| c.name == "novo"));
        assert!(state.protected.contains(&pk(&b)));
    }
}
