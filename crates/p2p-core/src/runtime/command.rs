//! Comandos que a interface (TUI, GUI, daemon) manda para o core.

use crate::screen::VideoCodec;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Para onde vão os quadros da tela que o usuário está assistindo. Fila curta e limitada:
/// se a janela atrasar, os quadros excedentes são descartados. Quando a janela fecha (o
/// receptor é descartado), o core sai da transmissão sozinho.
pub type FrameSink = std::sync::mpsc::SyncSender<(VideoCodec, Vec<u8>)>;

#[derive(Debug, Serialize, Deserialize)]
pub enum CoreCommand {
    /// Mensagem de texto no canal atual
    SendMessage(String),
    /// Entra num canal de texto do espaço atual
    JoinChannel(String),
    JoinVoice(String),
    LeaveVoice,
    ToggleMute,
    ListPeers,
    ListAudioDevices,
    ListScreens,
    StartScreenShare { monitor: usize, quality: u32 },
    StopScreenShare,
    /// Assiste a transmissão de um par (nick, id da stream ou prefixo da pubkey). Sem `sink`
    /// (ex.: controle remoto), o core só conta os quadros (`ScreenEvent::FrameReceived`).
    WatchScreen {
        query: String,
        #[serde(skip)]
        sink: Option<FrameSink>,
    },
    /// Disca um endereço (ex.: `/ip4/.../p2p/<relay>/p2p-circuit/p2p/<par>`)
    Dial(String),
    /// Compartilha um arquivo na sala atual
    ShareFile(PathBuf),
    /// Oferece um arquivo só a um par
    SendFile { to: String, path: PathBuf },
    GetFile(String),
    RejectFile(String),
    Unshare(String),
    ListFiles,
    /// Gerenciamento de amigos e pedidos de amizade
    AddFriend { pubkey: String, alias: Option<String> },
    /// Aceita um pedido de amizade pendente
    AcceptFriend { target: String },
    /// Rejeita um pedido de amizade pendente
    RejectFriend { target: String },
    /// Reenvia pedido de amizade a um par
    ResendFriendRequest { target: String, message: Option<String> },
    RemoveFriend { pubkey: String },
    ListFriends,
    /// Abre uma conversa privada de DM como canal ativo (`@Nome`)
    OpenDm { target: String },
    /// Envia uma Mensagem Direta (E2EE online ou Store-and-Forward offline com TTL opcional)
    SendDm { target: String, text: String, suggested_ttl: Option<u64> },
    /// Configuração do nó e da Mailbox
    ShowConfig,
    SetConfig { key: String, value: String },
    /// Firewall local de proteção contra spam/abuso
    ListFirewall,
    UnblockPeer { target: String },
    /// Rotaciona a chave de criptografia X25519 (DMs E2EE) e propaga aos amigos
    RotateEncryptionKey,
    Server(ServerCommand),
    /// Encerra o nó (desanuncia nos trackers e emite `CoreEvent::Stopped`)
    Shutdown,
}

/// Comandos de servidor
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum ServerCommand {
    Create(String),
    Join(String),
    /// Entra no servidor do último convite recebido no chat
    Accept,
    Leave,
    List,
    Info,
    /// Troca de espaço: nome ou id de servidor, ou "lobby"
    Switch(String),
    /// Convite para o servidor: no Lobby se `target` for None, ou por DM direta para o par alvo (com passaporte automático se for privado)
    Invite { target: Option<String>, server_id: Option<String> },
    History,
    AddChannel { name: String, voice: bool },
    RemoveChannel(String),
    /// Emite passaporte de moderador (permissões padrão de moderação se `None`, ou personalizadas)
    AddModerator { target: String, permissions: Option<Vec<crate::community::PassportPermission>> },
    /// Revoga os passaportes de moderação conhecidos (dono)
    RemoveModerator(String),
    /// Ban com duração em segundos (`None` = permanente)
    Ban { target: String, duration: Option<u64>, reason: String },
    Unban(String),
    /// Revoga o passaporte conhecido de um participante
    Revoke(String),
    /// Lista os pedidos de acesso pendentes do servidor atual
    Requests,
    /// Tira um pedido de acesso da lista local (não bane; a pessoa pode pedir de novo mais tarde)
    DismissRequest(String),
    /// Dificuldade da prova de trabalho exigida nos pedidos de acesso (dono); 0 desliga
    AccessPow(u8),
    Close,
    Open,
    /// Lista os membros banidos do servidor atual
    Bans,
    /// Validade dos passaportes e janela de renovação, em segundos
    Policy { validity: u64, renewal_window: u64 },
    /// Rotaciona imediatamente a chave de época do grupo MLS atual (executado pelo líder)
    RotateKey,
    /// Emite um passaporte criptográfico do servidor para um par
    IssuePassport { target: String, moderator: bool, duration: Option<u64> },
    /// Acrescenta uma autoridade de tempo RFC 3161 à configuração do servidor (dono)
    AddTsa { name: String, url: String, public_key_b64: String },
    RemoveTsa(String),
    /// Exibe os detalhes criptográficos do passaporte deste nó no servidor atual
    ShowPassport,
    /// Solicita o achatamento de cadeia do passaporte local caso haja autoridade superior online
    FlattenPassport,
    /// Corrente de chaves do servidor: raiz em vigor, validade e transferências (#99)
    KeyShow,
    /// Renova a validade da Chave do Servidor (quem a tem)
    KeyRenew,
    /// Propõe transferir a Chave do Servidor a um par (nick ou pubkey)
    KeyTransfer(String),
    /// Aceita a última proposta de transferência recebida
    KeyAccept,
    Help,
}
