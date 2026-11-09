//! Loop de eventos do nó Anarchord.
//!
//! A interface manda [`CoreCommand`]s e recebe [`CoreEvent`]s; todo o resto (rede, chat, voz,
//! tela, servidores, arquivos, descoberta) roda aqui, numa tarefa tokio. O CLI, uma GUI futura
//! ou um teste usam o mesmo core.
//!
//! O estado fica em [`Runtime`]; cada assunto tem seu arquivo com os métodos dele
//! (`network`, `chat`, `voice`, `screen`, `servers`, `files`).

mod access;
mod chat;
pub mod discovery;
pub mod command;
mod dm;
pub mod event;
mod files;
mod network;
mod screen;
mod servers;
mod voice;

pub use chat::ActiveChannel;
pub use command::{CoreCommand, FrameSink, ServerCommand};
pub use event::*;
pub use servers::{invite_text, parse_invite, parse_invite_details};
// FriendStatus vem de `event::*`

use crate::community::{self, e2ee::ServerGroups, ServerRegistry, Space};
use crate::dm::{dm_topic, DmWireMessage};
use crate::identity::UserIdentity;
use crate::node::P2PNode;
use crate::relay::RelayManager;
use crate::wire;
use libp2p::gossipsub::IdentTopic;
use libp2p::{Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// Como o nó deve rodar
#[derive(Clone)]
pub struct CoreConfig {
    /// Caminho do arquivo de identidade no disco (para persistir amigos e perfil)
    pub identity_path: Option<PathBuf>,
    /// Caminho do arquivo de configuração `config.json` (None = padrão agnóstico ao SO)
    pub config_path: Option<PathBuf>,
    pub identity: UserIdentity,
    /// Porta TCP + QUIC (0 = escolhe uma livre)
    pub port: u16,
    /// Endereço IP de escuta (None = "0.0.0.0" para todas as interfaces; Some("127.0.0.1") para loopback em testes)
    pub listen_ip: Option<String>,
    /// Onde ficam os servidores acompanhados e o estado MLS
    pub servers_dir: PathBuf,
    /// Onde os downloads completos são salvos
    pub download_dir: PathBuf,
    /// Canal de texto inicial no Lobby
    pub channel: String,
    /// Endereço para discar ao iniciar
    pub connect: Option<Multiaddr>,
    /// Sala de voz do Lobby em que entra ao iniciar
    pub auto_voice: Option<String>,
    /// Abre microfone e alto-falante
    pub audio: bool,
    /// Transmite uma melodia sintética na sala de voz (bots e testes)
    pub synth_audio: bool,
    /// Transmite vídeo sintético no Lobby (bots e testes)
    pub synth_video: bool,
    /// Descoberta automática (DHT Amino e trackers BitTorrent)
    pub discovery: bool,
    /// Modo de teste: baixa todo arquivo oferecido e assiste toda tela anunciada
    pub test_mode: bool,
    /// Bootstrap da DHT (com `/p2p/<id>`), além dos públicos se `public_defaults`
    pub bootstrap: Vec<Multiaddr>,
    /// Trackers BitTorrent UDP (`host:porta`), além dos públicos se `public_defaults`
    pub trackers: Vec<String>,
    /// Usa também os nós de bootstrap do IPFS e os trackers públicos embutidos.
    /// Desligado, o nó só conhece o que foi informado (redes isoladas, laboratório).
    pub public_defaults: bool,
    /// Descoberta na rede local (mDNS)
    pub mdns: bool,
    /// Atende como servidor de relay (nós públicos)
    pub relay_server: bool,
    /// Rede de laboratório: IPs privados valem como públicos e as sondagens são rápidas
    pub lab: bool,
    /// Arquivo JSONL opcional para gravar os pacotes brutos de aplicação (sniffer de pacotes)
    pub sniff_file: Option<PathBuf>,
    /// Capacidades de protocolo customizadas anunciadas no Identify (`None` = padrão local `v1..=v2`)
    pub protocol_capabilities: Option<crate::wire::ProtocolCapabilities>,
}

impl CoreConfig {
    /// Configuração padrão para uma identidade (sem áudio nem descoberta, útil em testes)
    pub fn new(identity: UserIdentity, servers_dir: PathBuf, download_dir: PathBuf) -> Self {
        Self {
            identity_path: None,
            config_path: None,
            identity,
            port: 0,
            listen_ip: Some("127.0.0.1".into()),
            servers_dir,
            download_dir,
            channel: "geral".into(),
            connect: None,
            auto_voice: None,
            audio: false,
            synth_audio: false,
            synth_video: false,
            discovery: false,
            test_mode: false,
            bootstrap: Vec::new(),
            trackers: Vec::new(),
            public_defaults: false,
            mdns: false,
            relay_server: false,
            lab: false,
            sniff_file: None,
            protocol_capabilities: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CoreStartError {
    #[error("rede: {0}")]
    Node(#[from] crate::node::NodeError),
    #[error("servidores: {0}")]
    Servers(#[from] crate::community::CommunityError),
    #[error("tópico: {0}")]
    Subscribe(String),
}

/// Ponta da interface: manda comandos e recebe eventos
pub struct CoreHandle {
    commands: UnboundedSender<CoreCommand>,
    events: UnboundedReceiver<CoreEvent>,
}

impl CoreHandle {
    pub fn send(&self, command: CoreCommand) {
        let _ = self.commands.send(command);
    }

    pub async fn next_event(&mut self) -> Option<CoreEvent> {
        self.events.recv().await
    }

    /// Separa as duas pontas (ex.: comandos numa tarefa, eventos em outra)
    pub fn split(self) -> (UnboundedSender<CoreCommand>, UnboundedReceiver<CoreEvent>) {
        (self.commands, self.events)
    }
}

pub struct Core;

impl Core {
    /// Prepara o nó e devolve a ponta da interface e o loop a executar.
    ///
    /// O loop não é `Send` (os fluxos de áudio do sistema ficam presos à thread), então ele roda
    /// com `.await` na tarefa principal (ou numa `LocalSet`), enquanto a interface roda em outra
    /// tarefa conversando pelo `CoreHandle`.
    pub fn start(config: CoreConfig) -> Result<(CoreHandle, CoreTask), CoreStartError> {
        let (tx_events, events) = unbounded_channel();
        let (commands, rx_commands) = unbounded_channel();
        let runtime = Runtime::new(config, tx_events)?;
        Ok((CoreHandle { commands, events }, CoreTask { runtime, commands: rx_commands }))
    }
}

/// O loop do nó, pronto para rodar
pub struct CoreTask {
    runtime: Runtime,
    commands: UnboundedReceiver<CoreCommand>,
}

impl CoreTask {
    /// Roda até `CoreCommand::Shutdown` (ou até a interface descartar o `CoreHandle`)
    pub async fn run(self) {
        self.runtime.run(self.commands).await
    }

    pub fn peer_id(&self) -> PeerId {
        self.runtime.node.peer_id
    }

    pub fn listen_port(&self) -> u16 {
        self.runtime.node.listen_port
    }
}

/// Agora, em segundos Unix (UTC)
pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default()
}

/// Agora, em milissegundos Unix (UTC) — usado para o timestamp cronológico de envio das mensagens
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// Estado do nó. Os campos são usados pelos módulos de cada assunto.
pub(crate) struct Runtime {
    config: CoreConfig,
    identity: UserIdentity,
    nick: String,
    events: UnboundedSender<CoreEvent>,
    node: P2PNode,

    // Rede
    connected_peers: HashSet<PeerId>,
    /// Melhor conexão conhecida com cada par: (endereço, relayed). O `Connected` só é emitido
    /// para pares Anarchord identificados (a maioria das conexões é com nós do IPFS na DHT)
    links: HashMap<PeerId, (String, bool)>,
    /// PeerId -> (nick, pubkey) dos pares Anarchord identificados
    peer_metadata: HashMap<PeerId, (String, String)>,
    /// Tópicos em que cada par remoto se inscreveu: PeerId -> HashSet<TopicHash>
    /// Usado como barreira reativa determinística para garantir que se o Gossipsub negociar antes
    /// ou depois do Identify, a lista de membros do canal seja publicada assim que ambos estiverem prontos.
    peer_topics: HashMap<PeerId, HashSet<libp2p::gossipsub::TopicHash>>,
    /// PeerId -> capacidades e versões de protocolo anunciadas no Identify
    peer_protocols: HashMap<PeerId, crate::wire::ProtocolCapabilities>,
    /// Capacidades locais deste nó (`v1..=v2` por padrão)
    local_capabilities: crate::wire::ProtocolCapabilities,
    /// Pares com versão incompatível sobre os quais a TUI já foi avisada (evita avisos repetidos)
    warned_incompatible: HashSet<PeerId>,
    /// Pares já anunciados na interface desde que conectaram
    identified: HashSet<PeerId>,
    /// Endereços discados com conexão aberta (o tracker repete os mesmos pares)
    dialed_open: HashSet<Multiaddr>,
    /// Histórico de discagens de endereços IP descobertos via tracker: Multiaddr -> Instant
    tracker_dial_attempts: HashMap<Multiaddr, std::time::Instant>,
    /// Pares para os quais hole punching direto já teve sucesso na conexão ativa (evita spam na aba Sistema)
    dcutr_punched: HashSet<PeerId>,
    /// Histórico de falhas de hole punching por par para cooldown: PeerId -> (Instant, String)
    dcutr_last_failure: HashMap<PeerId, (std::time::Instant, String)>,
    has_anarchord_connected: std::sync::Arc<std::sync::atomic::AtomicBool>,
    relay_manager: RelayManager,
    discovery: discovery::DiscoveryState,
    tracker_rx: Option<UnboundedReceiver<String>>,

    // Chat e servidores
    active: ActiveChannel,
    servers: ServerRegistry,
    mls: ServerGroups,
    last_key_package: HashMap<String, std::time::Instant>,
    /// Último estado da chave da sala enviado à interface (`None` = ainda não enviado)
    room_key: Option<RoomKeyStatus>,
    /// Último pedido de carimbo de cada evento da fila (para pedir de novo se nada chegar)
    outbox_retry: HashMap<String, std::time::Instant>,
    /// Alterações deste nó aguardando carimbo: o aviso sai quando forem aplicadas
    pending_changes: HashMap<String, ServerChange>,
    /// Última proposta de transferência da Chave do Servidor recebida (servidor e mensagem)
    pending_transfer_offer: Option<(String, crate::community::ServerMessage)>,
    /// Servidores cujo vencimento próximo da chave já foi avisado nesta execução
    root_expiry_warned: std::collections::HashSet<String>,
    /// Servidor em que entra assim que a configuração chegar
    pending_switch: Option<String>,
    last_invite: Option<String>,
    last_snapshot_reply: HashMap<String, std::time::Instant>,
    /// Carimbos pedidos às TSAs em threads; o resultado volta para o loop
    stamp_tx: UnboundedSender<servers::StampResult>,
    stamp_rx: Option<UnboundedReceiver<servers::StampResult>>,
    /// Provas de trabalho de pedidos de acesso calculadas em threads
    pow_tx: UnboundedSender<access::PowResult>,
    pow_rx: Option<UnboundedReceiver<access::PowResult>>,
    /// Pedidos de acesso: inscrições, pendentes e esperas (#91)
    access: access::AccessState,
    /// Último líder do grupo cifrado avisado à interface, por servidor
    last_leader: HashMap<String, Option<String>>,

    voice: voice::VoiceState,
    screen: screen::ScreenState,
    files: files::FilesState,
    dm: dm::DmState,
}

impl Runtime {
    fn new(config: CoreConfig, events: UnboundedSender<CoreEvent>) -> Result<Self, CoreStartError> {
        let identity = config.identity.clone();
        let nick = identity.profile.display_name.clone();
        let local_capabilities = config
            .protocol_capabilities
            .clone()
            .unwrap_or_else(crate::wire::ProtocolCapabilities::local);
        let now = now_secs();
        let dm = dm::DmState::new(config.config_path.clone(), Some(config.servers_dir.join("mailbox.json")), now);
        let relay_access = dm.firewall.relay_access();
        relay_access.set_friends_only(dm.node_config.firewall.relay_friends_only);
        relay_access.update_friends(identity.get_friends().iter().map(|f| f.public_key.clone()));
        let mut node = P2PNode::with_options(
            identity.clone(),
            crate::node::NodeOptions {
                port: config.port,
                listen_ip: config.listen_ip.clone(),
                relay_server: config.relay_server,
                lab: config.lab,
                mdns: config.mdns,
                capabilities: Some(local_capabilities.clone()),
                validate_messages: true,
                relay_access: Some(relay_access),
            },
        )?;
        let mut relay_manager = RelayManager::new();
        relay_manager.allow_private(config.lab);
        let servers = ServerRegistry::load(config.servers_dir.clone(), now)?;
        let mls = ServerGroups::new(&identity, Some(config.servers_dir.join("mls-state.json")));
        let active = ActiveChannel::new(Space::Lobby, config.channel.clone());
        node.swarm.behaviour_mut().gossipsub.subscribe(&active.topic).map_err(|e| CoreStartError::Subscribe(format!("{:?}", e)))?;
        let screen = screen::ScreenState::new(&mut node);
        let files = files::FilesState::new(&identity, config.download_dir.clone());
        let (stamp_tx, stamp_rx) = unbounded_channel();
        let (pow_tx, pow_rx) = unbounded_channel();
        Ok(Self {
            identity,
            nick,
            events,
            node,
            connected_peers: HashSet::new(),
            links: HashMap::new(),
            peer_metadata: HashMap::new(),
            peer_topics: HashMap::new(),
            peer_protocols: HashMap::new(),
            local_capabilities,
            warned_incompatible: HashSet::new(),
            identified: HashSet::new(),
            dialed_open: HashSet::new(),
            tracker_dial_attempts: HashMap::new(),
            dcutr_punched: HashSet::new(),
            dcutr_last_failure: HashMap::new(),
            has_anarchord_connected: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            relay_manager,
            discovery: discovery::DiscoveryState::new(config.lab),
            tracker_rx: None,
            active,
            servers,
            mls,
            last_key_package: HashMap::new(),
            room_key: None,
            outbox_retry: HashMap::new(),
            pending_changes: HashMap::new(),
            pending_transfer_offer: None,
            root_expiry_warned: std::collections::HashSet::new(),
            pending_switch: None,
            last_invite: None,
            last_snapshot_reply: HashMap::new(),
            stamp_tx,
            stamp_rx: Some(stamp_rx),
            pow_tx,
            pow_rx: Some(pow_rx),
            access: access::AccessState::default(),
            last_leader: HashMap::new(),
            voice: voice::VoiceState::default(),
            screen,
            files,
            dm,
            config,
        })
    }

    fn emit(&self, event: CoreEvent) {
        let _ = self.events.send(event);
    }

    fn error(&self, error: CoreError) {
        self.emit(CoreEvent::Error(error));
    }

    fn my_pubkey(&self) -> String {
        self.identity.public_key_hex()
    }

    async fn run(mut self, mut commands: UnboundedReceiver<CoreCommand>) {
        self.emit(CoreEvent::Started {
            nick: self.nick.clone(),
            pubkey: self.my_pubkey(),
            peer_id: self.node.peer_id.to_string(),
            port: self.node.listen_port,
        });
        for id in self.servers.list().map(|s| s.server_id.clone()).collect::<Vec<_>>() {
            self.follow_server(&id);
        }
        if let Some(address) = self.config.connect.clone() {
            self.emit(CoreEvent::Network(NetworkEvent::Dialing(address.to_string())));
            if let Err(e) = self.node.swarm.dial(address) {
                self.error(CoreError::Network(e.to_string()));
            }
        }
        self.subscribe_peer_exchange();
        self.init_dm_and_mailbox();
        self.start_discovery();
        self.start_voice();
        self.start_synthetic_video();
        self.publish_servers();
        self.resume_files();

        let mut discovery_tick = tokio::time::interval(Duration::from_secs(1));
        let mut server_sync = tokio::time::interval(Duration::from_secs(5));
        let mut mailbox_tick = tokio::time::interval(Duration::from_secs(3));
        let mut screen_announce = tokio::time::interval(Duration::from_secs(2));
        let mut speaker_check = tokio::time::interval(Duration::from_millis(200));
        let mut files_tick = tokio::time::interval(Duration::from_secs(1));
        let mut tracker_rx = self.tracker_rx.take();
        let mut voice_rx = self.voice.outgoing.take();
        let mut screen_rx = self.screen.outgoing.take();
        let mut manifest_rx = self.files.manifests.take();
        let mut fs_events_rx = self.files.fs_events.take();
        let mut stamp_rx = self.stamp_rx.take();
        let mut pow_rx = self.pow_rx.take();

        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(CoreCommand::Shutdown) | None => break,
                    Some(command) => self.handle_command(command),
                },
                event = self.node.swarm.next_event() => self.handle_swarm_event(event),
                _ = discovery_tick.tick() => self.discovery_tick(),
                _ = server_sync.tick() => self.server_sync_tick(),
                _ = mailbox_tick.tick() => self.mailbox_tick(),
                _ = screen_announce.tick() => self.screen_tick(),
                _ = speaker_check.tick() => self.speaker_tick(),
                _ = files_tick.tick() => self.files_tick(),
                Some(address) = recv(&mut tracker_rx) => self.dial_discovered(address),
                Some(packet) = recv(&mut voice_rx) => self.broadcast_voice(packet),
                Some(packet) = recv(&mut screen_rx) => self.broadcast_screen(packet),
                Some(job) = recv(&mut manifest_rx) => self.manifest_ready(job),
                Some(()) = recv(&mut fs_events_rx) => self.on_fs_watch_event(),
                Some(result) = recv(&mut stamp_rx) => self.on_stamp_result(result),
                Some(result) = recv(&mut pow_rx) => self.on_pow_result(result),
            }
            // O grupo da sala nasce, chega ou some em vários caminhos (Welcome, Commit, troca de sala,
            // anúncio de grupo vencedor...): conferir aqui cobre todos
            self.sync_room_key();
        }

        // Avisa o grupo cifrado da sala que saímos e dá um instante para a rede enviar (Ctrl+C não
        // passa por aqui; nesse caso a readmissão acontece pelo KeyPackage quando voltarmos)
        self.leave_room_group();
        let _ = tokio::time::timeout(Duration::from_millis(300), async {
            loop {
                let event = self.node.swarm.next_event().await;
                self.handle_swarm_event(event);
            }
        })
        .await;
        self.stop_discovery();
        self.emit(CoreEvent::Stopped);
    }

    fn handle_command(&mut self, command: CoreCommand) {
        match command {
            CoreCommand::SendMessage(text) => self.send_chat(&text),
            CoreCommand::JoinChannel(channel) => self.join_text_channel(channel),
            CoreCommand::JoinVoice(channel) => self.join_voice(channel),
            CoreCommand::LeaveVoice => self.leave_voice(),
            CoreCommand::ToggleMute => self.toggle_mute(),
            CoreCommand::ListPeers => {
                let mut peers: Vec<PeerProtocolInfo> = self
                    .peer_metadata
                    .iter()
                    .filter(|(p, _)| self.connected_peers.contains(p))
                    .map(|(peer_id, (nick, pubkey))| {
                        let remote_caps = self
                            .peer_protocols
                            .get(peer_id)
                            .cloned()
                            .unwrap_or_else(crate::wire::ProtocolCapabilities::legacy_v1);
                        let negotiated_version = self.local_capabilities.negotiate_version(&remote_caps);
                        let capabilities: Vec<String> = self
                            .local_capabilities
                            .negotiate_capabilities(&remote_caps)
                            .into_iter()
                            .collect();
                        PeerProtocolInfo {
                            peer_id: peer_id.to_string(),
                            nick: nick.clone(),
                            pubkey: pubkey.clone(),
                            announced_versions: remote_caps.version_range_label(),
                            negotiated_version,
                            app_version: remote_caps.app_version,
                            capabilities,
                        }
                    })
                    .collect();
                peers.sort_by(|a, b| a.nick.cmp(&b.nick).then_with(|| a.peer_id.cmp(&b.peer_id)));
                let anarchord = peers.len();
                self.emit(CoreEvent::Peers {
                    anarchord,
                    connections: self.connected_peers.len(),
                    peers,
                });
            }
            CoreCommand::ListAudioDevices => self.emit(CoreEvent::AudioDevices {
                inputs: crate::voice::AudioDeviceManager::list_input_devices(),
                outputs: crate::voice::AudioDeviceManager::list_output_devices(),
            }),
            CoreCommand::ListScreens => {
                self.emit(CoreEvent::Screen(ScreenEvent::Monitors(crate::screen::ScreenCaptureEngine::list_screens())))
            }
            CoreCommand::StartScreenShare { monitor, quality } => self.start_screen_share(monitor, quality),
            CoreCommand::StopScreenShare => self.stop_screen_share(),
            CoreCommand::WatchScreen { query, sink } => self.watch_screen(&query, sink),
            CoreCommand::Dial(address) => match address.parse::<Multiaddr>() {
                Ok(address) => {
                    self.emit(CoreEvent::Network(NetworkEvent::Dialing(address.to_string())));
                    if let Err(e) = self.node.swarm.dial(address) {
                        self.error(CoreError::Network(e.to_string()));
                    }
                }
                Err(e) => self.error(CoreError::Network(e.to_string())),
            },
            CoreCommand::ShareFile(path) => self.share_file(path),
            CoreCommand::SendFile { to, path } => self.send_file(&to, path),
            CoreCommand::GetFile(query) => self.get_file(&query),
            CoreCommand::RejectFile(query) => self.reject_file(&query),
            CoreCommand::Unshare(query) => self.unshare_file(&query),
            CoreCommand::ListFiles => self.list_files(),
            CoreCommand::AddFriend { pubkey, alias } => self.add_friend(&pubkey, alias.as_deref()),
            CoreCommand::AcceptFriend { target } => self.accept_friend(&target),
            CoreCommand::RejectFriend { target } => self.reject_friend(&target),
            CoreCommand::ResendFriendRequest { target, message } => self.resend_friend_request(&target, message.as_deref()),
            CoreCommand::RemoveFriend { pubkey } => self.remove_friend(&pubkey),
            CoreCommand::ListFriends => self.list_friends(),
            CoreCommand::OpenDm { target } => self.open_dm(&target),
            CoreCommand::SendDm { target, text, suggested_ttl } => self.send_dm(&target, &text, suggested_ttl),
            CoreCommand::ShowConfig => self.show_config(),
            CoreCommand::SetConfig { key, value } => self.set_config(&key, &value),
            CoreCommand::ListFirewall => self.list_firewall(),
            CoreCommand::UnblockPeer { target } => self.unblock_peer(&target),
            CoreCommand::Server(command) => self.run_server_command(command),
            CoreCommand::RotateEncryptionKey => self.rotate_encryption_key(),
            CoreCommand::Shutdown => {}
        }
    }

    /// Calcula a versão de envelope `wire` a usar num tópico Gossipsub (menor versão máxima negociada
    /// entre todos os pares compatíveis atualmente inscritos no tópico).
    pub(super) fn topic_wire_version(&self, topic: &IdentTopic) -> u8 {
        let topic_hash = topic.hash();
        let peer_caps = self
            .node
            .swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .filter(|(_, topics)| topics.contains(&&topic_hash))
            .filter_map(|(peer, _)| self.peer_protocols.get(peer));
        self.local_capabilities.room_wire_version(peer_caps)
    }

    /// Ajusta o byte de versão do envelope `wire` para a versão negociada do tópico, se necessário.
    fn adapt_envelope_version(&self, topic: &IdentTopic, mut payload: Vec<u8>) -> Vec<u8> {
        let target_ver = self.topic_wire_version(topic);
        if let Some(first) = payload.first_mut() {
            if crate::wire::is_supported_version(*first) && *first != target_ver {
                *first = target_ver;
            }
        }
        payload
    }

    /// Publica um quadro bruto no Gossipsub (adaptando o cabeçalho para a versão negociada do tópico)
    /// e, se o sniffer estiver ativo, disseca e grava o pacote TX.
    pub(super) fn publish_gossip(&mut self, topic: IdentTopic, payload: Vec<u8>) -> Result<(), PublishError> {
        let payload = self.adapt_envelope_version(&topic, payload);
        let topic_name = topic.hash().into_string();
        self.sniff_packet("TX", &topic_name, None, &payload, None);
        self.node
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, payload)
            .map(|_| ())
            .map_err(|_| PublishError::Network)
    }

    /// Registra um pacote bruto (TX ou RX) no arquivo de sniffer, caso configurado.
    pub(super) fn sniff_packet(
        &self,
        direction: &str,
        topic: &str,
        source_peer_id: Option<String>,
        raw_bytes: &[u8],
        mls_decrypted: Option<&[u8]>,
    ) {
        if let Some(ref path) = self.config.sniff_file {
            let pkt = crate::sniffer::SniffedPacket::dissect(
                now_secs(),
                &self.nick,
                direction,
                topic,
                source_peer_id,
                raw_bytes,
                mls_decrypted,
            );
            pkt.append_to_file(path);
        }
    }

    /// Publica conteúdo (chat, voz, tela, enxame). Em tópicos de servidor, cifra antes com o grupo MLS.
    fn publish_content(&mut self, topic: &IdentTopic, bytes: Vec<u8>) -> Result<(), PublishError> {
        let bytes = self.adapt_envelope_version(topic, bytes);
        let topic_name = topic.hash().into_string();
        match community::parse_server_content_topic(&topic_name) {
            Some(_) => {
                // Cifra com o grupo da sala (cada canal tem o próprio grupo e chave)
                let room = self.room_for_topic(&topic_name).ok_or(PublishError::NoGroupKey)?;
                let encrypted = self.mls.encrypt(&room, &bytes).map_err(|_| PublishError::NoGroupKey)?;
                self.sniff_packet("TX", &topic_name, None, &encrypted, Some(&bytes));
                self.node
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), encrypted)
                    .map(|_| ())
                    .map_err(|_| PublishError::Network)
            }
            None => self.publish_gossip(topic.clone(), bytes),
        }
    }

    /// Nick conhecido de uma pubkey, ou o início dela
    pub(super) fn nick_for(&self, pubkey: &str) -> String {
        if pubkey == self.my_pubkey() {
            return self.nick.clone();
        }
        self.peer_metadata
            .values()
            .find(|(_, pk)| pk == pubkey)
            .map(|(nick, _)| nick.clone())
            .unwrap_or_else(|| community::short_id(pubkey).to_string())
    }

    pub(super) fn nick_or_short(&self, pubkey: &str) -> String {
        self.nick_for(pubkey)
    }

    /// Nome amigável de exibição de um par (alias de amigo > nick conectado > PeerId cru) com prefixo do PeerId
    pub(super) fn peer_display_name(&self, peer_id: &PeerId) -> String {
        if let Some((nick, pubkey)) = self.peer_metadata.get(peer_id) {
            let name = if let Some(friend) = self
                .identity
                .get_friends()
                .iter()
                .find(|f| f.public_key.eq_ignore_ascii_case(pubkey))
            {
                friend.alias.as_ref().unwrap_or(nick)
            } else {
                nick
            };
            format!("{} ({})", name, community::short_id(&peer_id.to_string()))
        } else {
            peer_id.to_string()
        }
    }

    /// PeerId de um par por nick, PeerId ou prefixo da pubkey
    fn find_peer(&self, query: &str) -> Option<PeerId> {
        self.peer_metadata.iter().find_map(|(peer, (nick, pubkey))| {
            (nick.eq_ignore_ascii_case(query) || peer.to_string().starts_with(query) || pubkey.starts_with(query)).then_some(*peer)
        })
    }

    /// Salva a identidade no disco se houver caminho configurado e sincroniza a lista de amigos no `RelayAccessControl`
    fn persist_identity(&self) {
        self.dm
            .firewall
            .relay_access()
            .update_friends(self.identity.get_friends().iter().map(|f| f.public_key.clone()));
        if let Some(path) = &self.config.identity_path {
            let _ = self.identity.save_to(path);
        }
    }

    /// Rotaciona a chave de criptografia X25519 e propaga o anúncio assinado para os amigos conectados
    fn rotate_encryption_key(&mut self) {
        let ad = self.identity.rotate_encryption_key();
        self.persist_identity();
        let epoch = ad.advertisement.epoch;
        let pubkey = ad.advertisement.encryption_public_key.clone();

        for friend in self.identity.get_friends().to_vec() {
            if self.is_pubkey_online(&friend.public_key) {
                let topic_str = dm_topic(&self.my_pubkey(), &friend.public_key);
                self.subscribe_dm_with(&friend.public_key);
                let msg = DmWireMessage::KeyAdvertisement(ad.clone());
                let bytes = wire::encode(&msg);
                let _ = self.publish_gossip(IdentTopic::new(topic_str), bytes);
            }
        }

        self.emit(CoreEvent::EncryptionKeyRotated {
            epoch,
            public_key: pubkey,
        });
    }

    /// Adiciona um amigo e envia pedido mútuo de amizade (online e via Guardiões offline)
    fn add_friend(&mut self, who: &str, alias: Option<&str>) {
        self.send_friend_request(who, alias, None);
    }

    /// Remove um amigo localmente (pubkey ou nick/apelido)
    fn remove_friend(&mut self, who: &str) {
        let who = who.trim();
        let by_alias = self
            .identity
            .get_friends()
            .iter()
            .find(|f| f.alias.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(who)))
            .map(|f| f.public_key.clone());
        // Senão, o nick de um par conectado (menu de contexto) e, por fim, a pubkey digitada
        let by_nick = || self.find_peer(who).and_then(|p| self.peer_metadata.get(&p).map(|(_, pk)| pk.to_lowercase()));
        let pubkey_clean = by_alias.or_else(by_nick).unwrap_or_else(|| who.to_lowercase());
        let alias = self
            .identity
            .get_friends()
            .iter()
            .find(|f| f.public_key.eq_ignore_ascii_case(&pubkey_clean))
            .and_then(|f| f.alias.clone());
        if self.identity.remove_friend(&pubkey_clean) {
            self.persist_identity();
            self.emit(CoreEvent::FriendUpdated {
                pubkey: pubkey_clean,
                alias,
                removed: true,
            });
            self.list_friends();
        } else {
            self.error(CoreError::Friend("Amigo não encontrado na sua lista".into()));
        }
    }

    /// Avisa a interface quando um amigo fica online/offline (ignora quem não é amigo)
    pub(super) fn friend_presence(&self, pubkey: &str, online: bool) {
        if let Some(friend) = self.identity.get_friends().iter().find(|f| f.public_key.eq_ignore_ascii_case(pubkey)) {
            self.emit(CoreEvent::FriendPresence { public_key: friend.public_key.clone(), alias: friend.alias.clone(), online });
            self.list_friends();
        }
    }

    /// Lista os amigos e seu status de presença atual
    pub(super) fn list_friends(&self) {
        let statuses: Vec<FriendStatus> = self
            .identity
            .get_friends()
            .iter()
            .map(|f| {
                // Procura se a pubkey do amigo está ativa em algum par conectado
                let active = self.peer_metadata.iter().find(|(peer, (_, pk))| {
                    pk.eq_ignore_ascii_case(&f.public_key) && self.connected_peers.contains(peer)
                });
                let (online, current_nick, peer_id) = match active {
                    Some((peer, (nick, _))) => (true, Some(nick.clone()), Some(peer.to_string())),
                    None => (false, None, None),
                };
                FriendStatus {
                    public_key: f.public_key.clone(),
                    alias: f.alias.clone(),
                    added_at: f.added_at,
                    online,
                    current_nick,
                    peer_id,
                    state: f.state,
                }
            })
            .collect();
        self.emit(CoreEvent::Friends(statuses));
    }
}

#[derive(Debug)]
pub(super) enum PublishError {
    /// Conteúdo de servidor e este nó ainda não tem a chave do grupo
    NoGroupKey,
    Network,
}

/// `recv` de um receptor opcional (pendente para sempre se não houver ou se o canal fechar)
async fn recv<T>(rx: &mut Option<UnboundedReceiver<T>>) -> Option<T> {
    match rx {
        Some(inner) => match inner.recv().await {
            Some(val) => Some(val),
            None => {
                *rx = None;
                std::future::pending().await
            }
        },
        None => std::future::pending().await,
    }
}

/// Extensão para usar o swarm dentro do `select!`
trait NextEvent {
    async fn next_event(&mut self) -> libp2p::swarm::SwarmEvent<crate::protocol::AppBehaviourEvent>;
}

impl NextEvent for libp2p::Swarm<crate::protocol::AppBehaviour> {
    async fn next_event(&mut self) -> libp2p::swarm::SwarmEvent<crate::protocol::AppBehaviourEvent> {
        use futures::StreamExt;
        self.select_next_some().await
    }
}
