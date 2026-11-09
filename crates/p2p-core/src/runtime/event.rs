//! Eventos que o core manda para a interface. Tudo tipado: o texto mostrado ao usuário é
//! escolhido pela interface (cada uma no seu idioma e estilo).

use crate::community::{HistoryEntry, ModKind, UtcSecs};
use crate::config::NodeConfig;
use crate::dm::FirewallBlockEntry;
use crate::files::{FileEvent, FileSummary};
use crate::screen::ScreenInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CoreEvent {
    /// Nó no ar
    Started { nick: String, pubkey: String, peer_id: String, port: u16 },
    Network(NetworkEvent),
    /// Par Anarchord identificado (primeira vez na conexão ou nick novo)
    PeerIdentified { peer_id: String, nick: String, pubkey: String },
    /// Par Anarchord desconectou
    PeerLeft { peer_id: String, nick: String },
    /// Resposta a `ListPeers` (`/peers`)
    Peers {
        anarchord: usize,
        connections: usize,
        #[serde(default)]
        peers: Vec<PeerProtocolInfo>,
    },
    /// Par usa uma versão incompatível do protocolo (emitido uma única vez por par na sessão)
    PeerIncompatible {
        peer_id: String,
        nick: String,
        pubkey: String,
        peer_version: String,
        supported_versions: String,
    },
    AudioDevices { inputs: Vec<String>, outputs: Vec<String> },
    /// Espaço atual (Lobby ou servidor) e os canais dele
    SpaceChanged { space: SpaceInfo, channels: Vec<ChannelInfo> },
    ServersChanged(Vec<ServerSummary>),
    /// Estado da chave do grupo cifrado (MLS) da sala atual; emitido só quando muda
    RoomKey(RoomKeyStatus),
    ChannelEntered { space: SpaceInfo, channel: String },
    /// Pares Anarchord inscritos no canal de texto atual
    ChannelMembers { channel: String, members: Vec<String> },
    ChatMessage { channel: String, author: String, author_pubkey: String, text: String, timestamp: u64 },
    /// Mensagem de canal de texto de servidor que chegou mas este nó não consegue decifrar (sem a
    /// chave do grupo: banido, ainda sem passaporte ou fora de sincronia). Só o que trafega em claro:
    /// canal (do tópico), época MLS, tamanho e o próprio texto cifrado (base64, encurtado).
    EncryptedMessage { server: String, channel: String, epoch: Option<u64>, size: usize, ciphertext_b64: String, timestamp: u64 },
    /// Convite de servidor recebido no chat (`/server accept`)
    InviteReceived { from: String, server_id: String, known: bool },
    Voice(VoiceEvent),
    Screen(ScreenEvent),
    File(FileEvent),
    /// Resposta a `ListFiles`
    Files(Vec<FileSummary>),
    /// Resposta a `ListFriends` e atualizações de presença de amigos
    Friends(Vec<FriendStatus>),
    /// Um amigo ficou online ou offline
    FriendPresence { public_key: String, alias: Option<String>, online: bool },
    /// Amigo adicionado ou removido com sucesso
    FriendUpdated { pubkey: String, alias: Option<String>, removed: bool },
    /// Pedido de amizade recebido de outro par
    FriendRequestReceived {
        pubkey: String,
        sender_nick: String,
        message: Option<String>,
        offline_delivery: bool,
    },
    /// Pedido de amizade enviado foi aceito pelo outro par
    FriendRequestAccepted {
        pubkey: String,
        peer_name: String,
        offline_delivery: bool,
    },
    /// Pedido de amizade enviado foi rejeitado pelo outro par
    FriendRequestRejected {
        pubkey: String,
        peer_name: String,
        offline_delivery: bool,
    },
    /// Canal de DM privado aberto na TUI (`@Amigo`)
    DmOpened { peer_pubkey: String, peer_name: String, channel: String },
    /// Mensagem Direta (DM 1:1 E2EE) enviada ou recebida (online ou entregue via Mailbox offline)
    DirectMessage {
        peer_pubkey: String,
        peer_name: String,
        author: String,
        author_pubkey: String,
        text: String,
        timestamp: u64,
        offline_delivery: bool,
    },
    /// Envelope de DM enfileirado para entrega offline via guardiões amigos
    MailboxQueued {
        recipient_pubkey: String,
        recipient_name: String,
        envelope_id: String,
        suggested_ttl: Option<u64>,
    },
    /// Este nó guardião aceitou armazenar um envelope offline para um amigo
    MailboxStoredForFriend {
        sender_name: String,
        recipient_short: String,
        envelope_id: String,
        effective_ttl_secs: u64,
    },
    /// Status da configuração local e uso de disco da Mailbox
    ConfigStatus {
        config: NodeConfig,
        mailbox_used_bytes: u64,
        mailbox_envelope_count: usize,
    },
    /// Parâmetro de configuração alterado
    ConfigUpdated { key: String, value: String },
    /// Chave de criptografia X25519 rotacionada com sucesso
    EncryptionKeyRotated {
        epoch: u64,
        public_key: String,
    },
    /// Um par foi bloqueado temporariamente pelo Firewall local (aviso único por bloqueio)
    PeerBlocked {
        pubkey: String,
        peer_name: String,
        is_friend: bool,
        reason: String,
        duration_secs: u64,
        blocked_until: u64,
        offense_level: u32,
        courtesy_sent: bool,
    },
    /// Um par foi desbloqueado no Firewall local
    PeerUnblocked {
        pubkey: String,
        peer_name: String,
    },
    /// Lista de bloqueios ativos no Firewall (`/firewall`)
    FirewallStatus(Vec<FirewallBlockEntry>),
    /// Lendo o arquivo para montar o manifesto
    FilePreparing { name: String },
    Server(ServerNotice),
    Error(CoreError),
    /// O nó encerrou (depois de `Shutdown`)
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FriendStatus {
    pub public_key: String,
    pub alias: Option<String>,
    pub added_at: u64,
    pub online: bool,
    pub current_nick: Option<String>,
    pub peer_id: Option<String>,
    #[serde(default)]
    pub state: crate::identity::FriendState,
}

/// Resumo de versão do protocolo e capacidades de um par Anarchord conectado (`/peers`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerProtocolInfo {
    pub peer_id: String,
    pub nick: String,
    pub pubkey: String,
    /// Faixa de versões anunciada pelo par (ex.: `"v1-v2"` ou `"v1"`)
    pub announced_versions: String,
    /// Versão do envelope negociada com este par (`None` se incompatível)
    pub negotiated_version: Option<u8>,
    /// Versão da aplicação anunciada pelo par (ex.: `"0.1.0"`)
    pub app_version: String,
    /// Capacidades em comum negociadas com este par
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SpaceInfo {
    Lobby,
    /// `name` é `None` enquanto a configuração do servidor não chegou
    Server { id: String, name: Option<String> },
}

/// Se a sala atual é cifrada e se a chave do grupo MLS já chegou
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoomKeyStatus {
    /// Lobby: nada é cifrado de ponta a ponta
    Unencrypted,
    /// Sala de servidor ainda sem a chave do grupo (Welcome a caminho, sem passaporte ou fora de sincronia)
    Waiting,
    /// Sala de servidor com a chave do grupo: mensagens cifradas de ponta a ponta
    Ready,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelInfo {
    pub name: String,
    pub voice: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerSummary {
    pub id: String,
    pub name: String,
    pub current: bool,
    pub owner: bool,
    pub moderator: bool,
    /// Configuração ainda não chegou
    pub pending: bool,
    pub closed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkEvent {
    Listening(String),
    ExternalAddress(String),
    DhtBootstrap { nodes: usize },
    Dialing(String),
    TrackerPeer(String),
    BehindNat,
    RelayRequested { relay: String, address: String },
    RelayReserved(String),
    HolePunched(String),
    /// Tentativa de hole punching falhou (a conexão segue pelo relay)
    HolePunchFailed { peer_id: String, error: String },
    /// Primeira conexão com um par Anarchord, ou a primeira direta depois de uma relayada
    Connected { peer_id: String, address: String, relayed: bool },
    ConnectionClosed { peer_id: String, cause: String },
    /// Pares novos recebidos na troca de pares e discados
    PeerExchange { from: String, dialed: usize },
    AudioUnavailable(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VoiceEvent {
    Joined(String),
    Left(String),
    Members(Vec<String>),
    Speaking { nick: String, speaking: bool },
    Muted(bool),
    AudioReady,
    SynthStarted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScreenEvent {
    Monitors(Vec<ScreenInfo>),
    ShareStarted { stream_id: String, quality: u32, synthetic: bool },
    ShareStopped,
    /// A cada 60 quadros enviados
    FrameSent { seq: u64, bytes: usize },
    StreamAvailable { stream_id: String, nick: String },
    /// A cada 60 quadros recebidos de uma stream assistida
    FrameReceived { nick: String, seq: u64, bytes: usize, width: u32, height: u32 },
    Watching { stream_id: String, nick: String },
    /// A janela fechou: o core saiu da transmissão
    WatchEnded,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServerNotice {
    Created { id: String, name: String },
    /// Procurando membros online para receber a configuração
    Searching { id: String },
    /// `/server switch` para um servidor cuja configuração ainda não chegou
    WaitingConfig { id: String },
    Left { name: String, was_owner: bool },
    Synced { id: String, name: String, height: u64 },
    /// Alteração feita por este nó, já carimbada e aplicada
    Changed { server: String, change: ServerChange },
    /// Ação de moderação feita por este nó
    Moderated { server: String, target: String, kind: ModKind, at: UtcSecs },
    /// Ação de moderação de outro moderador
    ModerationReceived { server: String, by: String, target: String, kind: ModKind, at: UtcSecs, reason: String },
    /// Evento deste nó recusado pelas regras do servidor ao ser carimbado
    EventRejected { server: String, description: String, reason: String },
    /// Ban deste usuário começou ou acabou
    BanStatus { server: String, banned: bool },
    /// Este usuário passou a ser (ou deixou de ser) moderador
    Role { server: String, moderator: bool },
    /// Alguém sem passaporte pediu acesso a um servidor privado (só moderador emite manualmente).
    /// Avisado uma vez por pessoa (repete no máximo a cada 30 minutos).
    AccessRequested { server: String, who: String },
    /// Pedidos de acesso pendentes no servidor atual (para quem pode emitir passaporte): enviado
    /// quando a lista muda (`explicit: false`, só para a interface atualizar menus) e em resposta a
    /// `/server requests` (`explicit: true`, para mostrar ao usuário)
    AccessRequests { server_id: String, server: String, requests: Vec<AccessRequestEntry>, explicit: bool },
    /// Calculando a prova de trabalho exigida para pedir acesso (pode levar alguns segundos)
    AccessProofComputing { server: String, bits: u8 },
    /// Não foi possível obter carimbo de TSA para a prova; tentando com uma testemunha da rede
    AccessProofFailed { server: String, reason: String },
    /// Carimbo de tempo obtido (TSA ou testemunha) para uma ação ou passaporte deste nó
    StampObtained { server: String, source: String },
    /// Não foi possível obter carimbo de uma TSA da política
    StampFailed { server: String, tsa: String, reason: String },
    /// (líder) entregou a chave do grupo cifrado a alguém
    KeyGranted { to: String },
    KeyReceived { server: String },
    /// Passaporte do servidor recebido, renovado ou achatado com sucesso
    PassportUpdated { server: String },
    /// O líder do grupo cifrado do servidor mudou (`None` = sem grupo/sem líder no momento)
    LeaderChanged { server: String, leader: Option<String>, you: bool },
    /// Chave do grupo MLS rotacionada para uma nova época
    KeyRotated { server: String, epoch: u64 },
    /// Corrente de chaves: raízes (pubkey, desde, transferida em, vence em) e se este nó tem a chave em vigor
    KeyChain { server: String, roots: Vec<(String, UtcSecs, Option<UtcSecs>, UtcSecs)>, mine: bool },
    /// Renovação ou transferência pedida; vale quando o carimbo da TSA chegar
    KeyLinkRequested { server: String, transfer: bool },
    /// Proposta de transferência enviada a `target`
    TransferOffered { server: String, target: String },
    /// Proposta de transferência recebida (aceitar com `/server key accept`)
    TransferOfferReceived { server: String, from: String },
    /// Aceitação enviada; a chave nova foi gerada e guardada nesta máquina
    TransferAccepted { server: String },
    /// A posse mudou: `owner` = este nó tem agora a Chave do Servidor em vigor
    OwnershipChanged { server: String, owner: bool, expires_at: UtcSecs },
    /// A Chave do Servidor (deste nó) vence em breve
    RootExpiring { server: String, expires_at: UtcSecs },
    RemovedFromGroup { server: String },
    InviteSent { server: String },
    /// Ninguém no Lobby para receber o convite: id para mandar à mão
    InviteManual { id: String },
    /// Servidor privado: quem foi convidado precisa receber passaporte de um moderador
    InviteNeedsPassport,
    List { lobby_current: bool, servers: Vec<ServerListEntry> },
    /// Lista dos membros atualmente banidos
    Bans { server: String, bans: Vec<BanEntry> },
    Info(ServerInfo),
    /// Detalhes do passaporte criptográfico local
    PassportInfo {
        server: String,
        holder: String,
        issuer: String,
        chain_depth: usize,
        stamps: usize,
        expires_at: Option<UtcSecs>,
        permissions: Vec<String>,
    },
    History(Vec<HistoryEntry>),
    Help,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServerChange {
    ChannelAdded { name: String, voice: bool },
    ChannelRemoved(String),
    ModeratorAdded { who: String, validity_secs: u64 },
    ModeratorRemoved { who: String },
    Closed,
    Opened,
    Policy { validity_secs: u64, renewal_window_secs: u64 },
    TsaAdded(String),
    TsaRemoved(String),
    /// Dificuldade da prova de trabalho dos pedidos de acesso (0 = desligada)
    AccessPow(u8),
}

/// Um pedido de acesso pendente
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessRequestEntry {
    pub pubkey: String,
    pub nick: String,
    /// Quando o pedido foi visto pela primeira vez (UTC)
    pub since: UtcSecs,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerListEntry {
    pub id: String,
    pub name: String,
    pub current: bool,
    pub owner: bool,
    pub moderator: bool,
    pub pending: bool,
    pub closed: bool,
    pub banned: bool,
}

/// Detalhes de um ban ativo para a gestão visual de moderação
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BanEntry {
    pub target: String,
    pub target_nick: String,
    pub until: Option<UtcSecs>,
    pub reason: String,
    pub by: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Role {
    Owner,
    Moderator,
    Member,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub id: String,
    pub name: String,
    /// Número de segurança verificável da chave de governança do servidor (e do dono)
    #[serde(default)]
    pub safety_number: String,
    /// Pubkey (hex) ou nick do líder determinístico atual do grupo MLS efêmero (menor pubkey online)
    #[serde(default)]
    pub mls_leader: Option<String>,
    /// Época atual do grupo MLS efêmero
    #[serde(default)]
    pub mls_epoch: Option<u64>,
    pub height: u64,
    pub updated_at: Option<UtcSecs>,
    pub channels: Vec<ChannelInfo>,
    pub role: Role,
    pub closed: bool,
    /// Passaportes conhecidos de participantes
    pub passports_known: usize,
    /// (nick, permissões, validade do passaporte)
    pub moderators: Vec<(String, Vec<String>, Option<UtcSecs>)>,
    /// (nick, até quando, quem baniu)
    pub bans: Vec<(String, Option<UtcSecs>, String)>,
    /// Autoridades de tempo aceitas: (nome, url)
    pub tsas: Vec<(String, String)>,
    pub passport_validity_secs: u64,
    pub renewal_window_secs: u64,
    pub pending_actions: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CoreError {
    PeerNotFound(String),
    NoStream(String),
    AlreadyStreaming,
    NotStreaming,
    NotInVoice,
    NoSuchChannel { name: String, voice: bool },
    /// Servidor e este nó ainda não tem a chave do grupo cifrado
    NoGroupKey,
    BannedHere,
    /// Sem passaporte válido no servidor
    NoPassport,
    /// Comando de servidor usado no Lobby
    InLobby,
    SelfModeration,
    NoInvite,
    ServerNotFound(String),
    /// Erro de regra de servidor (permissão, nível, canal...)
    Server(String),
    File(String),
    Friend(String),
    Config(String),
    Io { context: String, message: String },
    Network(String),
}
