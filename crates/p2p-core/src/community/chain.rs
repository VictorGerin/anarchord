//! Registro de governança do servidor (#93, #94, #52).
//!
//! Não é uma corrente de blocos: com vários escritores (moderadores), uma corrente linear vive de
//! conflitos (dois blocos na mesma altura) e qualquer regra de desempate vira ferramenta de censura
//! ou divide a rede quando ela se parte. Em vez disso, o servidor é:
//!
//! - **Genesis:** a configuração inicial, assinada pela Chave do Servidor (nome, canais, política de
//!   tempo inicial, lista de protegidos...).
//! - **Eventos de governança** ([`GovEvent`]): **uma ação** cada, assinada pelo autor com o
//!   **passaporte completo** (obrigatório também para o dono, que usa o passaporte vitalício emitido
//!   pela Chave do Servidor) e com **carimbo de tempo obrigatório** (TSA ou testemunha). Não há
//!   horário declarado pelo autor: o tempo do evento é o carimbo aceito mais antigo, verificado pela
//!   política de tempo vigente na época.
//! - **Estado:** os eventos aplicados na ordem (tempo atestado, id), cada um validado contra o estado
//!   anterior a ele. Eventos simultâneos valem os dois; redes que se partiram se somam ao voltar.
//!
//! Regras (#84):
//! - **Linhagem**: ninguém age sobre um ancestral da própria cadeia de passaporte.
//! - **Comprovado primeiro vence**: um evento de A é anulado se um ban contra A for anterior a ele;
//!   empate de tempo vale os dois.
//! - **Ban é uma janela sobre a pubkey**: invalida os passaportes do alvo emitidos antes e durante,
//!   exceto os emitidos por uma chave raiz depois do início; depois de `until`, qualquer emissor.
//! - **Protegidos** não podem ser banidos nem revogados por moderador (defesa contra o "evento
//!   guardado": carimbar ações hoje e soltá-las depois).
//! - **Consolidação** (#52): nova Genesis dentro do registro. Vira o ponto de partida; evento com
//!   carimbo anterior a ela é recusado. Consolidações concorrentes da mesma geração se resolvem pela
//!   mais antiga (tempo, id) dentro de uma janela de acomodação.
//! - **Posse da Chave do Servidor**: fica numa corrente própria, nunca consolidada
//!   ([`super::keychain`]); o id do servidor não muda, só a raiz que emite passaportes.

use super::keychain::{AppliedTransfer, KeyChain, KeyLink, Ownership, RootKey, DEFAULT_ROOT_VALIDITY_SECS};
use super::passport::{PassportError, PassportPermission, ServerPassport, UtcSecs};
use super::timestamp::{verify_rfc3161, TimestampAttestation, TimestampPolicy, TrustedTsa};
use crate::identity::{verify_signature_hex, UserIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

/// Tolerância para relógios adiantados
pub const CLOCK_SKEW_SECS: u64 = super::passport::CLOCK_SKEW_SECS;
/// Validade padrão dos passaportes emitidos por moderadores
pub const DEFAULT_PASSPORT_VALIDITY_SECS: u64 = 7 * 86_400;
/// Janela de renovação padrão (antes de expirar)
pub const DEFAULT_RENEWAL_WINDOW_SECS: u64 = 2 * 86_400;
/// Janela em que uma consolidação concorrente da mesma geração ainda pode substituir a aceita
pub const CONSOLIDATION_SETTLE_SECS: u64 = 10 * 60;
/// Até quantos níveis de carimbo-de-testemunha-de-testemunha a verificação desce
const MAX_STAMP_DEPTH: u8 = 3;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelType {
    Text,
    Voice,
    ScreenShare,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Channel {
    pub name: String,
    pub channel_type: ChannelType,
}

/// Configuração do servidor: vive na Genesis e em cada consolidação
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    pub name: String,
    pub channels: Vec<Channel>,
    /// `false` = público (moderadores emitem passaporte automaticamente a quem pedir)
    pub closed: bool,
    pub passport_validity_secs: u64,
    pub renewal_window_secs: u64,
    pub timestamp_policy: TimestampPolicy,
    /// Bits zero exigidos na prova de trabalho dos pedidos de acesso (0 = sem prova)
    pub access_pow_bits: u8,
    /// Quem não pode ser banido nem revogado por moderador
    pub protected: BTreeSet<String>,
    /// Intervalo da consolidação automática (0 = desligada)
    pub consolidation_interval_secs: u64,
    /// Validade da chave raiz a cada renovação ou transferência (#99)
    pub root_validity_secs: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GenesisBody {
    pub server_id: String,
    pub config: ServerConfig,
    /// Informativo (relógio de quem criou); o tempo que vale nos eventos é o dos carimbos
    pub created_at: UtcSecs,
    /// Vencimento da primeira chave raiz (o id do servidor); renovável pela corrente de chaves
    pub root_valid_until: UtcSecs,
}

/// Configuração inicial do servidor, assinada pela Chave do Servidor
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Genesis {
    pub body: GenesisBody,
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

impl Genesis {
    pub fn create(server_key: &UserIdentity, config: ServerConfig, created_at: UtcSecs) -> Self {
        let root_valid_until = created_at + config.root_validity_secs;
        let body = GenesisBody { server_id: server_key.public_key_hex(), config, created_at, root_valid_until };
        let signature = server_key.sign(&crate::wire::signing_bytes("genesis", &body));
        Self { body, signature }
    }

    pub fn verify(&self, server_id: &str) -> bool {
        self.body.server_id == server_id && verify_signature_hex(server_id, &crate::wire::signing_bytes("genesis", &self.body), &self.signature)
    }
}

/// Um ban registrado sobre uma pubkey
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BanState {
    pub until: Option<UtcSecs>,
    pub reason: String,
    /// Pubkey de quem baniu
    pub by: String,
    /// Início do ban: o tempo atestado do evento
    pub starts_at: UtcSecs,
    pub event_id: String,
}

/// Estado consolidado (#52): tudo de que se precisa para seguir sem o histórico
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StateSnapshot {
    pub config: ServerConfig,
    pub revoked: BTreeSet<String>,
    pub bans: BTreeMap<String, Vec<BanState>>,
}

/// Consolidação: nova Genesis dentro do registro
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Consolidation {
    /// Geração crescente (a Genesis original é a 0)
    pub generation: u64,
    /// Eventos aplicados desde o ponto de partida anterior (quem os tem confere o estado)
    pub included: BTreeSet<String>,
    pub snapshot: StateSnapshot,
}

/// Uma ação de governança
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Entry {
    SetName(String),
    AddChannel(Channel),
    RemoveChannel(String),
    SetClosed(bool),
    SetPassportPolicy { validity_secs: u64, renewal_window_secs: u64 },
    /// Dificuldade da prova de trabalho exigida nos pedidos de acesso (0 = desligada)
    SetAccessPow { bits: u8 },
    /// Intervalo da consolidação automática (0 = desligada)
    SetConsolidationInterval { secs: u64 },
    SetTimestampPolicy(TimestampPolicy),
    /// Entra ou sai da lista de protegidos
    SetProtected { pubkey: String, protected: bool },
    /// Ban até `until` (UTC); `None` = permanente
    Ban { target: String, until: Option<UtcSecs>, reason: String },
    /// Desfaz os bans aplicados **pelo próprio autor**
    Unban { target: String },
    /// Revoga um passaporte específico do alvo
    Revoke { target: String, serial: String },
    /// O próprio titular abre mão do passaporte (saiu do servidor)
    Renounce { serial: String },
    /// Validade da chave raiz a cada renovação ou transferência
    SetRootValidity { secs: u64 },
    /// Consolidação (nova Genesis)
    Consolidate(Box<Consolidation>),
}

impl Entry {
    /// Permissão do passaporte exigida para a ação (`None` = qualquer titular, ex.: renúncia)
    pub fn permission(&self) -> Option<PassportPermission> {
        Some(match self {
            Entry::AddChannel(_) | Entry::RemoveChannel(_) => PassportPermission::ManageChannels,
            Entry::SetName(_)
            | Entry::SetClosed(_)
            | Entry::SetPassportPolicy { .. }
            | Entry::SetAccessPow { .. }
            | Entry::SetConsolidationInterval { .. }
            | Entry::SetRootValidity { .. } => PassportPermission::ManageConfig,
            Entry::SetTimestampPolicy(_) => PassportPermission::ManageTimestampPolicy,
            Entry::SetProtected { .. } => PassportPermission::ManageProtected,
            Entry::Ban { .. } | Entry::Unban { .. } | Entry::Revoke { .. } => PassportPermission::Ban,
            Entry::Consolidate(_) => PassportPermission::Consolidate,
            Entry::Renounce { .. } => return None,
        })
    }

    /// Pubkey afetada por ações de moderação (para a regra de linhagem e de protegidos)
    pub fn target(&self) -> Option<&str> {
        match self {
            Entry::Ban { target, .. } | Entry::Unban { target } | Entry::Revoke { target, .. } => Some(target),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GovEventBody {
    pub server_id: String,
    pub entry: Entry,
    /// Pubkey do autor (titular do passaporte anexado)
    pub author: String,
    pub passport_serial: String,
    /// Torna únicos eventos iguais (ex.: o mesmo canal criado de novo depois de removido)
    pub nonce: String,
}

/// Evento de governança: uma ação, o passaporte completo do autor e os carimbos de tempo
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GovEvent {
    pub body: GovEventBody,
    pub passport: ServerPassport,
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
    /// Carimbos sobre [`GovEvent::imprint`] (fora do corpo assinado: chegam depois)
    #[serde(default)]
    pub stamps: Vec<TimestampAttestation>,
}

impl GovEvent {
    pub fn create(author: &UserIdentity, passport: &ServerPassport, entry: Entry) -> Self {
        let body = GovEventBody {
            server_id: passport.body.server_id.clone(),
            entry,
            author: author.public_key_hex(),
            passport_serial: passport.body.serial.clone(),
            nonce: super::timestamp::hex(&rand::random::<[u8; 8]>()),
        };
        let signature = author.sign(&crate::wire::signing_bytes("gov-event", &body));
        Self { body, passport: passport.clone(), signature, stamps: Vec::new() }
    }

    /// Identificador do evento (não muda quando chegam carimbos)
    pub fn id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(crate::wire::to_bytes(&self.body));
        hasher.update(&self.signature);
        hasher.finalize()[..16].iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Hash carimbado do evento (corpo + assinatura)
    pub fn imprint(&self) -> [u8; 32] {
        super::timestamp::imprint("gov-event", &crate::wire::signing_bytes("gov-event", &self.body), &self.signature)
    }

    /// Assinado pelo titular do passaporte anexado, do mesmo servidor
    pub fn verify_signature(&self, server_id: &str) -> bool {
        let body = &self.body;
        body.server_id == server_id
            && self.passport.body.server_id == server_id
            && self.passport.body.holder == body.author
            && self.passport.body.serial == body.passport_serial
            && verify_signature_hex(&body.author, &crate::wire::signing_bytes("gov-event", body), &self.signature)
    }

    pub fn author(&self) -> &str {
        &self.body.author
    }

    pub fn add_stamp(&mut self, stamp: TimestampAttestation) -> bool {
        if self.stamps.contains(&stamp) {
            return false;
        }
        self.stamps.push(stamp);
        true
    }

    /// Menor horário declarado pelos carimbos (sem verificar), para ordenar
    pub fn declared_time(&self) -> Option<UtcSecs> {
        self.stamps.iter().filter_map(TimestampAttestation::declared_time).min()
    }
}

/// Por que um evento foi recusado
#[derive(Debug, Clone, PartialEq)]
pub enum Rejection {
    BadSignature,
    InvalidPassport(String),
    MissingPermission,
    /// Sem carimbo aceito pela política de tempo
    NoTimestamp,
    TargetIsAncestor,
    ProtectedTarget,
    SelfTarget,
    ActorBanned,
    NotBanAuthor,
    NotOwnPassport,
    AlreadyApplied,
    /// Carimbo anterior à última consolidação
    BeforeConsolidation,
    BadConsolidation(String),
}

impl Rejection {
    /// A recusa pode mudar quando chegarem outros eventos
    pub fn depends_on_order(&self) -> bool {
        matches!(self, Rejection::NotBanAuthor | Rejection::ActorBanned)
    }
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejection::BadSignature => f.write_str("assinatura inválida"),
            Rejection::InvalidPassport(why) => write!(f, "passaporte do autor inválido: {}", why),
            Rejection::MissingPermission => f.write_str("o passaporte não dá essa permissão"),
            Rejection::NoTimestamp => f.write_str("sem carimbo de tempo aceito pela política do servidor"),
            Rejection::TargetIsAncestor => f.write_str("o alvo é ancestral de quem age (emitiu o passaporte dele ou de alguém acima)"),
            Rejection::ProtectedTarget => f.write_str("o alvo é protegido (ou é a chave do servidor)"),
            Rejection::SelfTarget => f.write_str("não é possível agir sobre si mesmo"),
            Rejection::ActorBanned => f.write_str("o autor já estava banido quando agiu"),
            Rejection::NotBanAuthor => f.write_str("só quem aplicou o ban pode desfazê-lo antes do prazo"),
            Rejection::NotOwnPassport => f.write_str("só o titular renuncia, e só ao passaporte que apresenta"),
            Rejection::AlreadyApplied => f.write_str("evento já aplicado"),
            Rejection::BeforeConsolidation => f.write_str("evento anterior à última consolidação"),
            Rejection::BadConsolidation(why) => write!(f, "consolidação inválida: {}", why),
        }
    }
}

/// Estado do servidor calculado a partir da Genesis (ou da última consolidação) e dos eventos
#[derive(Clone, Debug, Default)]
pub struct ServerState {
    pub server_id: String,
    pub name: String,
    pub channels: Vec<Channel>,
    /// `false` = público: moderadores emitem passaporte de membro automaticamente
    pub closed: bool,
    pub passport_validity_secs: u64,
    pub renewal_window_secs: u64,
    pub timestamp_policy: TimestampPolicy,
    pub access_pow_bits: u8,
    pub protected: BTreeSet<String>,
    pub consolidation_interval_secs: u64,
    /// Chaves raiz, resolvidas pela corrente de chaves (nunca pela consolidação)
    pub roots: Vec<RootKey>,
    /// Transferências ainda a aplicar na lista de protegidos (posteriores ao ponto de partida)
    pending_transfers: Vec<AppliedTransfer>,
    pub root_validity_secs: u64,
    /// Seriais de passaporte revogados
    pub revoked: BTreeSet<String>,
    pub bans: BTreeMap<String, Vec<BanState>>,
    /// Eventos aplicados e o tempo atestado de cada um
    pub applied_actions: BTreeSet<String>,
    pub event_times: BTreeMap<String, UtcSecs>,
    /// Eventos avaliados e recusados (por id), com o motivo
    pub rejected_actions: BTreeMap<String, Rejection>,
    /// Geração do ponto de partida (0 = Genesis original)
    pub generation: u64,
    /// Tempo do ponto de partida (0 na Genesis; o da consolidação depois)
    pub base_time: UtcSecs,
    /// Último evento aplicado e seu tempo
    pub last_event: Option<(String, UtcSecs)>,
}

impl ServerState {
    fn from_genesis(genesis: &Genesis, ownership: &Ownership) -> Self {
        let mut state = Self { server_id: genesis.body.server_id.clone(), ..Self::default() };
        state.set_config(&genesis.body.config);
        state.set_ownership(ownership);
        state
    }

    fn from_snapshot(server_id: &str, snapshot: &StateSnapshot, generation: u64, base_time: UtcSecs, ownership: &Ownership) -> Self {
        let mut state = Self { server_id: server_id.to_string(), generation, base_time, ..Self::default() };
        state.set_config(&snapshot.config);
        state.set_ownership(ownership);
        state.revoked = snapshot.revoked.clone();
        state.bans = snapshot.bans.clone();
        state
    }

    /// Raízes da corrente de chaves; as transferências anteriores ao ponto de partida já estão na lista de protegidos
    fn set_ownership(&mut self, ownership: &Ownership) {
        self.roots = ownership.roots.clone();
        self.pending_transfers = ownership.transfers.iter().filter(|t| t.at > self.base_time).cloned().collect();
    }

    /// Transferência: quem entregou a chave sai da lista de protegidos, quem recebeu entra
    fn apply_transfers_until(&mut self, at: UtcSecs) {
        while self.pending_transfers.first().is_some_and(|t| t.at <= at) {
            let transfer = self.pending_transfers.remove(0);
            if let Some(previous) = &transfer.previous_owner {
                self.protected.remove(previous);
            }
            if let Some(new) = &transfer.new_owner {
                self.protected.insert(new.clone());
            }
        }
    }

    fn set_config(&mut self, config: &ServerConfig) {
        self.name = config.name.clone();
        self.channels = config.channels.clone();
        self.closed = config.closed;
        self.passport_validity_secs = config.passport_validity_secs;
        self.renewal_window_secs = config.renewal_window_secs;
        self.timestamp_policy = config.timestamp_policy.clone();
        self.access_pow_bits = config.access_pow_bits;
        self.protected = config.protected.clone();
        self.consolidation_interval_secs = config.consolidation_interval_secs;
        self.root_validity_secs = config.root_validity_secs;
    }

    pub fn config(&self) -> ServerConfig {
        ServerConfig {
            name: self.name.clone(),
            channels: self.channels.clone(),
            closed: self.closed,
            passport_validity_secs: self.passport_validity_secs,
            renewal_window_secs: self.renewal_window_secs,
            timestamp_policy: self.timestamp_policy.clone(),
            access_pow_bits: self.access_pow_bits,
            protected: self.protected.clone(),
            consolidation_interval_secs: self.consolidation_interval_secs,
            root_validity_secs: self.root_validity_secs,
        }
    }

    /// Estado consolidado (determinístico: quem confere chega ao mesmo resultado)
    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot { config: self.config(), revoked: self.revoked.clone(), bans: self.bans.clone() }
    }

    /// Vencimento da chave raiz em vigor
    pub fn root_expires_at(&self) -> UtcSecs {
        self.roots.last().map_or(0, |r| r.expires_at)
    }

    /// Chave raiz em vigor (a que emite passaportes agora)
    pub fn current_root(&self) -> &str {
        self.roots.iter().rev().find(|r| r.until.is_none()).map_or(self.server_id.as_str(), |r| r.pubkey.as_str())
    }

    fn root_pubkeys(&self) -> Vec<String> {
        self.roots.iter().map(|r| r.pubkey.clone()).collect()
    }

    /// Chave raiz (atual ou anterior) do servidor
    pub fn is_root(&self, pubkey: &str) -> bool {
        pubkey == self.server_id || self.roots.iter().any(|r| r.pubkey == pubkey)
    }

    /// Aplica eventos na ordem do tempo atestado. A ordem parte do horário declarado pelos
    /// carimbos; ao aplicar, o tempo vira o verificado pela política da época (se for maior,
    /// o evento volta para a fila na posição certa).
    fn apply_all(&mut self, events: &BTreeMap<String, GovEvent>) {
        let mut queue: BinaryHeap<Reverse<(UtcSecs, String)>> = BinaryHeap::new();
        for (id, event) in events {
            match event.declared_time() {
                Some(t) => queue.push(Reverse((t, id.clone()))),
                None => {
                    self.rejected_actions.insert(id.clone(), Rejection::NoTimestamp);
                }
            }
        }
        let mut requeued = BTreeSet::new();
        while let Some(Reverse((t, id))) = queue.pop() {
            let event = &events[&id];
            match self.event_time(event) {
                None => {
                    self.rejected_actions.insert(id, Rejection::NoTimestamp);
                }
                Some(verified) if verified > t && requeued.insert(id.clone()) => queue.push(Reverse((verified, id))),
                Some(verified) => match {
                    self.apply_transfers_until(verified.saturating_sub(1));
                    self.check_event(event, verified)
                } {
                    Ok(()) => self.apply_entry(event, verified),
                    Err(rejection) => {
                        self.rejected_actions.insert(id, rejection);
                    }
                },
            }
        }
        self.apply_transfers_until(UtcSecs::MAX);
    }

    /// Tempo atestado do evento: o carimbo aceito mais antigo pela política vigente
    pub fn event_time(&self, event: &GovEvent) -> Option<UtcSecs> {
        let imprint = event.imprint();
        event.stamps.iter().filter_map(|s| self.stamp_time(s, &imprint, event.author(), MAX_STAMP_DEPTH)).min()
    }

    /// Instante atestado por um carimbo sobre `imprint`, se ele for aceito.
    /// `excluded` é quem gerou o conteúdo: não pode testemunhar nem ser ancestral da testemunha.
    pub fn stamp_time(&self, stamp: &TimestampAttestation, imprint: &[u8; 32], excluded: &str, depth: u8) -> Option<UtcSecs> {
        match stamp {
            TimestampAttestation::Rfc3161 { token_der, .. } => {
                verify_rfc3161(token_der, imprint, &self.timestamp_policy.tsas).ok().map(|(at, _)| at)
            }
            TimestampAttestation::Peer(token) => {
                let at = token.verify_structure(&self.server_id, imprint).ok()?;
                let witness = &token.witness_passport;
                if token.body.witness == excluded || witness.has_ancestor(excluded) {
                    return None; // linhagem: quem descende do autor não atesta por ele
                }
                if depth == 0 || !witness.allows(PassportPermission::EnterServer) {
                    return None;
                }
                self.verify_passport_inner(witness, at, true, depth - 1).ok()?;
                Some(at)
            }
        }
    }

    /// Valida um evento que ainda não está no registro, com o tempo atestado dele
    pub fn check_new_event(&self, event: &GovEvent) -> Result<UtcSecs, Rejection> {
        let at = self.event_time(event).ok_or(Rejection::NoTimestamp)?;
        if at <= self.base_time {
            return Err(Rejection::BeforeConsolidation);
        }
        self.check_event(event, at)?;
        Ok(at)
    }

    /// Valida um evento contra este estado, com o tempo atestado `at`
    pub fn check_event(&self, event: &GovEvent, at: UtcSecs) -> Result<(), Rejection> {
        let id = event.id();
        if self.applied_actions.contains(&id) {
            return Err(Rejection::AlreadyApplied);
        }
        if at <= self.base_time {
            return Err(Rejection::BeforeConsolidation);
        }
        if !event.verify_signature(&self.server_id) {
            return Err(Rejection::BadSignature);
        }
        let passport = &event.passport;
        let actor = event.author();
        // Bans contra o próprio autor seguem a regra de precedência abaixo, não a do titular
        self.verify_passport_inner(passport, at, false, MAX_STAMP_DEPTH)
            .map_err(|e| Rejection::InvalidPassport(e.to_string()))?;
        if let Some(bans) = self.bans.get(actor) {
            if bans.iter().any(|ban| ban.starts_at < at && !self.cleared(passport, ban)) {
                return Err(Rejection::ActorBanned);
            }
        }
        if let Some(permission) = event.body.entry.permission() {
            if !passport.allows(permission) {
                return Err(Rejection::MissingPermission);
            }
        }
        match &event.body.entry {
            Entry::Renounce { serial } if serial != &passport.body.serial => return Err(Rejection::NotOwnPassport),
            Entry::Unban { target } if !self.bans.get(target).is_some_and(|bans| bans.iter().any(|b| b.by == actor)) => {
                return Err(Rejection::NotBanAuthor);
            }
            Entry::Consolidate(consolidation) if consolidation.generation != self.generation + 1 => {
                return Err(Rejection::BadConsolidation(format!("geração {} (esperada {})", consolidation.generation, self.generation + 1)));
            }
            _ => {}
        }
        if let Some(target) = event.body.entry.target() {
            if target == actor {
                return Err(Rejection::SelfTarget);
            }
            if self.is_root(target) || (!matches!(event.body.entry, Entry::Unban { .. }) && self.protected.contains(target)) {
                return Err(Rejection::ProtectedTarget);
            }
            if passport.has_ancestor(target) {
                return Err(Rejection::TargetIsAncestor);
            }
        }
        Ok(())
    }

    fn apply_entry(&mut self, event: &GovEvent, at: UtcSecs) {
        let id = event.id();
        let actor = event.author().to_string();
        match &event.body.entry {
            Entry::SetName(name) => self.name = name.clone(),
            Entry::AddChannel(channel) => {
                if !self.channels.iter().any(|c| c.name == channel.name) {
                    self.channels.push(channel.clone());
                }
            }
            Entry::RemoveChannel(name) => self.channels.retain(|c| &c.name != name),
            Entry::SetClosed(closed) => self.closed = *closed,
            Entry::SetPassportPolicy { validity_secs, renewal_window_secs } => {
                self.passport_validity_secs = *validity_secs;
                self.renewal_window_secs = (*renewal_window_secs).min(*validity_secs);
            }
            Entry::SetAccessPow { bits } => self.access_pow_bits = (*bits).min(super::access_proof::MAX_POW_BITS),
            Entry::SetConsolidationInterval { secs } => self.consolidation_interval_secs = *secs,
            Entry::SetTimestampPolicy(policy) => self.timestamp_policy = policy.clone(),
            Entry::SetProtected { pubkey, protected } => {
                if *protected {
                    self.protected.insert(pubkey.clone());
                } else {
                    self.protected.remove(pubkey);
                }
            }
            Entry::Ban { target, until, reason } => {
                let ban = BanState { until: *until, reason: reason.clone(), by: actor, starts_at: at, event_id: id.clone() };
                self.bans.entry(target.clone()).or_default().push(ban);
            }
            Entry::Unban { target } => {
                if let Some(list) = self.bans.get_mut(target) {
                    list.retain(|b| b.by != actor);
                    if list.is_empty() {
                        self.bans.remove(target);
                    }
                }
            }
            Entry::Revoke { serial, .. } | Entry::Renounce { serial } => {
                self.revoked.insert(serial.clone());
            }
            Entry::SetRootValidity { secs } => self.root_validity_secs = *secs,
            // Consolidações são aplicadas pela `ServerChain` (trocam o ponto de partida)
            Entry::Consolidate(_) => {}
        }
        self.applied_actions.insert(id.clone());
        self.event_times.insert(id.clone(), at);
        if self.last_event.as_ref().is_none_or(|(_, t)| at >= *t) {
            self.last_event = Some((id, at));
        }
    }

    /// Passaporte emitido depois do ban de forma que o libera: por uma chave raiz depois do início
    /// do ban, ou por qualquer emissor depois do fim do prazo
    fn cleared(&self, passport: &ServerPassport, ban: &BanState) -> bool {
        (self.is_root(&passport.body.issuer) && passport.body.issued_at > ban.starts_at)
            || ban.until.is_some_and(|until| passport.body.issued_at >= until)
    }

    /// Bans sobre `pubkey` já iniciados em `at`
    fn bans_started<'a>(&'a self, pubkey: &str, at: UtcSecs) -> impl Iterator<Item = &'a BanState> + 'a {
        self.bans.get(pubkey).into_iter().flatten().filter(move |b| b.starts_at <= at)
    }

    /// Valida um passaporte em `at`: cadeia criptográfica, raiz em vigor, revogação e bans de
    /// titular e emissores
    pub fn verify_passport(&self, passport: &ServerPassport, at: UtcSecs) -> Result<(), PassportError> {
        self.verify_passport_inner(passport, at, true, MAX_STAMP_DEPTH)
    }

    fn verify_passport_inner(&self, passport: &ServerPassport, at: UtcSecs, holder_bans: bool, depth: u8) -> Result<(), PassportError> {
        passport.verify_with_roots(&self.server_id, &self.root_pubkeys(), at)?;
        if self.revoked.contains(&passport.body.serial) {
            return Err(PassportError::RevokedOrBanned(passport.body.serial.clone()));
        }
        let holder = &passport.body.holder;
        if holder_bans && self.bans_started(holder, at).any(|ban| !self.cleared(passport, ban)) {
            return Err(PassportError::RevokedOrBanned(holder.clone()));
        }
        let links = passport.links();
        // Raiz do passaporte (#99): nada vale depois do vencimento dela; transferida em T, o elo emitido
        // por ela só vale com carimbo de TSA anterior a T (a data de emissão é declarada pelo emissor)
        if let Some(root_link) = links.last() {
            let issuer = &root_link.body.issuer;
            let root = self.roots.iter().find(|r| &r.pubkey == issuer).ok_or_else(|| PassportError::RevokedOrBanned(issuer.clone()))?;
            if at >= root.expires_at {
                return Err(PassportError::Expired { expires_at: root.expires_at, at });
            }
            if let Some(transferred_at) = root.until {
                if !self.proven_by_tsa_before(root_link, transferred_at) {
                    return Err(PassportError::RevokedOrBanned(issuer.clone()));
                }
            }
        }
        // Emissores banidos: o elo filho precisa de prova de que existia antes do ban
        for pair in links.windows(2) {
            let (child, parent) = (pair[0], pair[1]);
            let issuer = &child.body.issuer;
            if self.is_root(issuer) {
                continue;
            }
            for ban in self.bans_started(issuer, at) {
                if self.cleared(parent, ban) || (depth > 0 && self.proven_before(child, ban.starts_at, issuer, depth - 1)) {
                    continue;
                }
                return Err(PassportError::RevokedOrBanned(issuer.clone()));
            }
        }
        Ok(())
    }

    /// Algum carimbo de TSA da política prova que o elo existia antes de `t`
    fn proven_by_tsa_before(&self, link: &ServerPassport, t: UtcSecs) -> bool {
        let imprint = link.imprint();
        link.stamps.iter().any(|s| match s {
            TimestampAttestation::Rfc3161 { token_der, .. } => {
                verify_rfc3161(token_der, &imprint, &self.timestamp_policy.tsas).is_ok_and(|(at, _)| at < t)
            }
            TimestampAttestation::Peer(_) => false,
        })
    }

    /// Algum carimbo aceito prova que o elo existia antes de `t`
    fn proven_before(&self, link: &ServerPassport, t: UtcSecs, issuer: &str, depth: u8) -> bool {
        let imprint = link.imprint();
        link.stamps.iter().filter_map(|s| self.stamp_time(s, &imprint, issuer, depth)).any(|at| at < t)
    }

    /// Ban em vigor em `at` (bans com prazo expiram sozinhos)
    pub fn is_banned(&self, pubkey: &str, at: UtcSecs) -> bool {
        self.bans_started(pubkey, at).any(|b| b.until.is_none_or(|until| at < until))
    }

    pub fn active_bans(&self, at: UtcSecs) -> Vec<(&String, &BanState)> {
        self.bans
            .iter()
            .flat_map(|(pk, list)| list.iter().map(move |b| (pk, b)))
            .filter(|(_, b)| b.starts_at <= at && b.until.is_none_or(|until| at < until))
            .collect()
    }

    /// Chaves raiz do servidor sempre participam (quem fala é a identidade pessoal, com passaporte)
    pub fn is_owner_key(&self, pubkey: &str) -> bool {
        self.is_root(pubkey)
    }

    /// Pode participar: chave raiz, ou passaporte válido do próprio `pubkey`
    pub fn is_allowed_with_passport(&self, pubkey: &str, passport: Option<&ServerPassport>, at: UtcSecs) -> bool {
        if self.is_owner_key(pubkey) {
            return true;
        }
        passport.is_some_and(|p| p.body.holder == pubkey && p.allows(PassportPermission::EnterServer) && self.verify_passport(p, at).is_ok())
    }
}

/// Ponto de partida do estado
#[derive(Clone, Debug)]
enum Base {
    Genesis,
    /// Consolidação aceita e seu tempo atestado
    Consolidation(Box<GovEvent>, UtcSecs),
}

/// Resultado de acrescentar um evento recebido
#[derive(Debug, PartialEq)]
pub enum AddResult {
    Added,
    Duplicate,
    /// Consolidação aceita: o histórico anterior foi descartado
    Consolidated,
    Rejected(Rejection),
    /// Sem a Genesis ainda
    NoGenesis,
}

/// Registro de governança de um servidor e o estado calculado a partir dele
#[derive(Clone, Debug)]
pub struct ServerChain {
    server_id: String,
    genesis: Option<Genesis>,
    base: Base,
    events: BTreeMap<String, GovEvent>,
    /// Ponto de partida e eventos anteriores à última consolidação, guardados durante a janela de
    /// acomodação (uma consolidação concorrente mais antiga ainda pode substituí-la)
    previous: Option<(Base, BTreeMap<String, GovEvent>)>,
    /// Corrente de chaves (nunca consolidada) e a posse resolvida a partir dela
    keys: KeyChain,
    ownership: Ownership,
    state: ServerState,
}

impl ServerChain {
    pub fn new(server_id: &str) -> Self {
        Self {
            server_id: server_id.to_string(),
            genesis: None,
            base: Base::Genesis,
            events: BTreeMap::new(),
            previous: None,
            keys: KeyChain::default(),
            ownership: Ownership::default(),
            state: ServerState { server_id: server_id.to_string(), ..ServerState::default() },
        }
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn state(&self) -> &ServerState {
        &self.state
    }

    pub fn is_empty(&self) -> bool {
        self.genesis.is_none()
    }

    pub fn genesis(&self) -> Option<&Genesis> {
        self.genesis.as_ref()
    }

    /// Eventos desde o ponto de partida (sem a consolidação que o define)
    pub fn events(&self) -> impl Iterator<Item = &GovEvent> {
        self.events.values()
    }

    /// Consolidação que é o ponto de partida atual, se houver
    pub fn base_consolidation(&self) -> Option<&GovEvent> {
        match &self.base {
            Base::Consolidation(event, _) => Some(event),
            Base::Genesis => None,
        }
    }

    /// Eventos aplicados, na ordem do tempo atestado (para histórico)
    pub fn ordered_events(&self) -> Vec<(&GovEvent, UtcSecs)> {
        let mut list: Vec<(&GovEvent, UtcSecs)> =
            self.events.values().filter_map(|e| self.state.event_times.get(&e.id()).map(|t| (e, *t))).collect();
        list.sort_by(|a, b| (a.1, a.0.id()).cmp(&(b.1, b.0.id())));
        list
    }

    /// Ids que este nó conhece (para a sincronização por inventário)
    pub fn inventory(&self) -> BTreeSet<String> {
        let mut ids: BTreeSet<String> = self.events.keys().cloned().collect();
        ids.extend(self.keys.links().map(KeyLink::id));
        if let Some(base) = self.base_consolidation() {
            ids.insert(base.id());
        }
        ids
    }

    /// O que falta a quem tem `have`: a consolidação de partida (se ele não a tiver) e os eventos
    pub fn missing_for(&self, have: &BTreeSet<String>) -> Vec<GovEvent> {
        let mut out: Vec<GovEvent> = self.base_consolidation().filter(|b| !have.contains(&b.id())).cloned().into_iter().collect();
        out.extend(self.events.values().filter(|e| !have.contains(&e.id())).cloned());
        out
    }

    /// Define a Genesis (recebida ou criada). Só a assinada pela chave do servidor é aceita.
    pub fn set_genesis(&mut self, genesis: Genesis) -> bool {
        if self.genesis.is_some() || !genesis.verify(&self.server_id) {
            return false;
        }
        self.genesis = Some(genesis);
        self.rebuild();
        true
    }

    /// Acrescenta um evento recebido (ou criado). Valida assinatura e carimbo; a aplicação em si
    /// depende da posição no tempo e do estado de então.
    pub fn add_event(&mut self, event: GovEvent, now: UtcSecs) -> AddResult {
        self.add_events(vec![event], now).pop().map_or(AddResult::Duplicate, |(_, r)| r)
    }

    /// Acrescenta vários eventos de uma vez (recalcula o estado uma vez só para os comuns).
    /// Consolidações são tratadas antes, em ordem de geração.
    pub fn add_events(&mut self, mut events: Vec<GovEvent>, now: UtcSecs) -> Vec<(GovEvent, AddResult)> {
        if self.genesis.is_none() {
            return events.into_iter().map(|e| (e, AddResult::NoGenesis)).collect();
        }
        events.sort_by_key(|e| match &e.body.entry {
            Entry::Consolidate(c) => (0, c.generation),
            _ => (1, 0),
        });
        let mut results = Vec::new();
        let mut inserted = Vec::new();
        let mut stamps_changed = false;
        for event in events {
            let id = event.id();
            if self.base_consolidation().is_some_and(|b| b.id() == id) {
                results.push((event, AddResult::Duplicate));
                continue;
            }
            if let Some(known) = self.events.get_mut(&id) {
                // Mesmo evento com carimbos novos
                for stamp in &event.stamps {
                    stamps_changed |= known.add_stamp(stamp.clone());
                }
                results.push((event, AddResult::Duplicate));
                continue;
            }
            if !event.verify_signature(&self.server_id) {
                results.push((event, AddResult::Rejected(Rejection::BadSignature)));
                continue;
            }
            if let Entry::Consolidate(consolidation) = &event.body.entry {
                if !inserted.is_empty() || stamps_changed {
                    self.rebuild();
                    stamps_changed = false;
                }
                let consolidation = consolidation.as_ref().clone();
                let result = self.add_consolidation(event.clone(), &consolidation, now);
                results.push((event, result));
                continue;
            }
            match self.state.event_time(&event) {
                None => results.push((event, AddResult::Rejected(Rejection::NoTimestamp))),
                Some(at) if at <= self.state.base_time => results.push((event, AddResult::Rejected(Rejection::BeforeConsolidation))),
                Some(_) => {
                    self.events.insert(id.clone(), event);
                    inserted.push(id);
                }
            }
        }
        if inserted.is_empty() {
            if stamps_changed {
                self.rebuild();
            }
            return results;
        }
        self.rebuild();
        let mut dropped = false;
        for id in inserted {
            if self.state.applied_actions.contains(&id) {
                results.push((self.events[&id].clone(), AddResult::Added));
                continue;
            }
            let rejection = self.state.rejected_actions.get(&id).cloned().unwrap_or(Rejection::NoTimestamp);
            // Recusas que dependem da ordem (o ban que o desban desfaz ainda não chegou; o ban contra o
            // autor pode cair) ficam guardadas e são reavaliadas a cada evento novo
            let event = if rejection.depends_on_order() {
                self.events[&id].clone()
            } else {
                dropped = true;
                self.events.remove(&id).expect("inserido acima")
            };
            results.push((event, AddResult::Rejected(rejection)));
        }
        if dropped {
            self.rebuild();
        }
        results
    }

    fn add_consolidation(&mut self, event: GovEvent, consolidation: &Consolidation, now: UtcSecs) -> AddResult {
        let Some(at) = self.state.event_time(&event) else { return AddResult::Rejected(Rejection::NoTimestamp) };
        // Concorrente da mesma geração dentro da janela de acomodação: vence a mais antiga (tempo, id)
        if let (Base::Consolidation(current, current_at), Some((previous_base, previous_events))) = (&self.base, &self.previous) {
            if consolidation.generation == self.state.generation
                && now < current_at + CONSOLIDATION_SETTLE_SECS
                && (at, event.id()) < (*current_at, current.id())
            {
                let (base, events) = (previous_base.clone(), previous_events.clone());
                let mut restored = self.clone();
                restored.base = base;
                restored.events = events;
                restored.previous = None;
                restored.rebuild();
                let result = restored.add_consolidation(event, consolidation, now);
                if result == AddResult::Consolidated {
                    *self = restored;
                }
                return result;
            }
        }
        if let Err(rejection) = self.state.check_event(&event, at) {
            return AddResult::Rejected(rejection);
        }
        // Quem tem os eventos incluídos confere o estado; quem não tem aceita pela assinatura
        let have_all = consolidation.included.iter().all(|id| self.events.contains_key(id));
        if have_all {
            let mut check = self.clone();
            check.events.retain(|id, _| consolidation.included.contains(id));
            check.rebuild();
            if check.state.snapshot() != consolidation.snapshot {
                return AddResult::Rejected(Rejection::BadConsolidation("o estado não confere com o histórico".into()));
            }
        }
        let previous = (self.base.clone(), self.events.clone());
        self.base = Base::Consolidation(Box::new(event), at);
        // Esquece o passado: só ficam os eventos posteriores à consolidação
        let times = self.state.event_times.clone();
        self.events.retain(|id, e| times.get(id).copied().or_else(|| e.declared_time()).is_some_and(|t| t > at));
        self.previous = Some(previous);
        self.rebuild();
        AddResult::Consolidated
    }

    /// Fim da janela de acomodação: a consolidação vira definitiva e o histórico anterior é descartado
    pub fn settle(&mut self, now: UtcSecs) {
        if let Base::Consolidation(_, at) = &self.base {
            if now >= at + CONSOLIDATION_SETTLE_SECS {
                self.previous = None;
            }
        }
    }

    fn rebuild(&mut self) {
        let Some(genesis) = self.genesis.clone() else { return };
        // A posse vem da corrente de chaves. Os carimbos dela valem pelas TSAs da Genesis e pelas da
        // política atual (que pode ter mudado): resolve, calcula o estado e, se a política trouxer
        // TSAs novas, resolve de novo.
        let mut tsas: Vec<TrustedTsa> = genesis.body.config.timestamp_policy.tsas.clone();
        for _ in 0..2 {
            self.ownership = self.keys.resolve(&genesis, &tsas);
            let mut state = match &self.base {
                Base::Genesis => ServerState::from_genesis(&genesis, &self.ownership),
                Base::Consolidation(event, at) => match &event.body.entry {
                    Entry::Consolidate(c) => ServerState::from_snapshot(&self.server_id, &c.snapshot, c.generation, *at, &self.ownership),
                    _ => ServerState::from_genesis(&genesis, &self.ownership),
                },
            };
            state.apply_all(&self.events);
            self.state = state;
            let extra: Vec<TrustedTsa> = self.state.timestamp_policy.tsas.iter().filter(|t| !tsas.contains(t)).cloned().collect();
            if extra.is_empty() {
                break;
            }
            tsas.extend(extra);
        }
    }

    /// Elos conhecidos da corrente de chaves
    pub fn key_links(&self) -> impl Iterator<Item = &KeyLink> {
        self.keys.links()
    }

    /// Posse resolvida (raízes, transferências e o último elo aceito)
    pub fn ownership(&self) -> &Ownership {
        &self.ownership
    }

    /// Acrescenta elos da corrente de chaves (assinaturas conferidas). Devolve `true` se a posse mudou.
    pub fn add_key_links(&mut self, links: Vec<KeyLink>) -> bool {
        let mut changed = false;
        for link in links {
            changed |= self.keys.insert(link, &self.server_id);
        }
        if !changed || self.genesis.is_none() {
            return false;
        }
        let before = self.ownership.clone();
        self.rebuild();
        self.ownership != before
    }

    /// O elo está no caminho aceito da corrente de chaves
    pub fn key_link_accepted(&self, id: &str) -> bool {
        self.ownership.path.iter().any(|(link, _)| link == id)
    }

    /// Consolidação do estado atual (para quem tem `Consolidate` publicar)
    pub fn consolidation(&self) -> Consolidation {
        Consolidation {
            generation: self.state.generation + 1,
            included: self.state.applied_actions.clone(),
            snapshot: self.state.snapshot(),
        }
    }

    /// Tempo do ponto de partida (Genesis = criação; consolidação = seu carimbo)
    pub fn base_time(&self) -> UtcSecs {
        match &self.base {
            Base::Consolidation(_, at) => *at,
            Base::Genesis => self.genesis.as_ref().map_or(0, |g| g.body.created_at),
        }
    }
}

/// Configuração inicial sugerida para um servidor novo (o dono já protegido)
pub fn default_config(name: &str, owner: &str, channels: Vec<Channel>, policy: TimestampPolicy) -> ServerConfig {
    ServerConfig {
        name: name.to_string(),
        channels,
        closed: false,
        passport_validity_secs: DEFAULT_PASSPORT_VALIDITY_SECS,
        renewal_window_secs: DEFAULT_RENEWAL_WINDOW_SECS,
        timestamp_policy: policy,
        access_pow_bits: 0,
        protected: [owner.to_string()].into_iter().collect(),
        consolidation_interval_secs: 0,
        root_validity_secs: DEFAULT_ROOT_VALIDITY_SECS,
    }
}
