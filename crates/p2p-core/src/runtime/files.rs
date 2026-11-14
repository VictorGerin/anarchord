//! Ponte entre o motor do enxame de arquivos e a rede.

use super::{CoreError, CoreEvent, Runtime};
use crate::api::pubkey_hex_from_peer_id;
use crate::community;
use crate::files::{self as swarm_files, FileAction, FileEngine, FileEvent, FileKey, FileRequest, Manifest, ShareTarget};
use crate::identity::UserIdentity;
use libp2p::request_response::{self, OutboundRequestId};
use libp2p::PeerId;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// Manifesto montado em segundo plano, pronto para compartilhar
pub(super) struct ManifestJob {
    manifest: std::io::Result<Manifest>,
    path: PathBuf,
    key: Option<FileKey>,
    target: ShareTarget,
}

fn clean_watch_path(path: &Path) -> PathBuf {
    let p = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let s = p.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        p
    }
}

const UPLOAD_QUEUE_TIMEOUT: Duration = Duration::from_secs(10);

struct PendingUpload {
    channel: request_response::ResponseChannel<swarm_files::FileResponse>,
    response: swarm_files::FileResponse,
    bytes: u64,
    enqueued_at: Instant,
}

fn response_byte_len(response: &swarm_files::FileResponse) -> u64 {
    match response {
        swarm_files::FileResponse::Piece(b)
        | swarm_files::FileResponse::Manifest(b)
        | swarm_files::FileResponse::Bitfield(b) => b.len() as u64,
        swarm_files::FileResponse::Ok | swarm_files::FileResponse::Busy | swarm_files::FileResponse::NotFound => 0,
    }
}

pub(super) struct FilesState {
    pub(super) engine: FileEngine,
    requests: HashMap<OutboundRequestId, (PeerId, FileRequest)>,
    upload_limiter: crate::config::SharedBandwidthLimiter,
    pending_uploads: VecDeque<PendingUpload>,
    /// Salas em que o nó se inscreveu por causa de downloads
    followed: HashSet<String>,
    tx: UnboundedSender<ManifestJob>,
    pub(super) manifests: Option<UnboundedReceiver<ManifestJob>>,
    /// Watcher nativo do SO (`notify`: ReadDirectoryChangesW / inotify / FSEvents) para detectar
    /// deleção ou movimentação de arquivos sem polling
    watcher: Option<RecommendedWatcher>,
    watched_dirs: HashSet<PathBuf>,
    pub(super) fs_events: Option<UnboundedReceiver<()>>,
}

impl FilesState {
    pub(super) fn new(
        identity: &UserIdentity,
        download_dir: PathBuf,
        download_limiter: crate::config::SharedBandwidthLimiter,
        upload_limiter: crate::config::SharedBandwidthLimiter,
    ) -> Self {
        // Parciais separados por identidade: vários nós na mesma máquina não se misturam
        let partial_dir = download_dir.join(".parcial").join(&identity.public_key_hex()[..8]);
        let _ = std::fs::create_dir_all(&download_dir);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let (fs_tx, fs_rx) = tokio::sync::mpsc::unbounded_channel();

        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                // Dispara apenas quando o SO reporta remoção, renomeação ou alteração em arquivo
                if matches!(
                    event.kind,
                    EventKind::Remove(_) | EventKind::Modify(_) | EventKind::Any
                ) {
                    let _ = fs_tx.send(());
                }
            }
        })
        .ok();

        let mut watched_dirs = HashSet::new();
        let fs_events = if let Some(w) = watcher.as_mut() {
            let canon = clean_watch_path(&download_dir);
            if w.watch(&canon, RecursiveMode::NonRecursive).is_ok() {
                watched_dirs.insert(canon);
            }
            Some(fs_rx)
        } else {
            None
        };

        Self {
            engine: FileEngine::new(partial_dir, download_dir).with_download_limiter(download_limiter),
            requests: HashMap::new(),
            upload_limiter,
            pending_uploads: VecDeque::new(),
            followed: Default::default(),
            tx,
            manifests: Some(rx),
            watcher,
            watched_dirs,
            fs_events,
        }
    }

    /// Garante que o diretório pai de um arquivo compartilhado/baixado esteja registrado no watcher do SO
    pub(super) fn watch_file_parent(&mut self, file_path: &Path) {
        let Some(parent) = file_path.parent() else { return };
        let canon = clean_watch_path(parent);
        if self.watched_dirs.contains(&canon) {
            return;
        }
        if let Some(w) = self.watcher.as_mut() {
            if w.watch(&canon, RecursiveMode::NonRecursive).is_ok() {
                self.watched_dirs.insert(canon);
            }
        }
    }
}

impl Runtime {
    pub(super) fn resume_files(&mut self) {
        let actions = self.files.engine.resume(Instant::now());
        self.sync_swarm_topics();
        self.apply_file_actions(actions);
    }

    /// Sincroniza as inscrições Gossipsub do enxame de arquivos:
    /// - Inscreve nos tópicos dedicados dos arquivos que estamos baixando ou semeando (`anarchord/file/<cid>`)
    /// - Desinscreve dos tópicos de arquivos que deixaram de ser ativos (/unshare, cancelamento, remoção)
    pub(super) fn sync_swarm_topics(&mut self) {
        let active_topics: HashSet<String> = self.files.engine.swarm_topics().into_iter().collect();

        for topic_str in &active_topics {
            let topic = libp2p::gossipsub::IdentTopic::new(topic_str);
            if self.files.followed.insert(topic_str.clone()) {
                let _ = self.node.swarm.behaviour_mut().gossipsub.subscribe(&topic);
            }
        }

        let to_unfollow: Vec<String> = self.files.followed.difference(&active_topics).cloned().collect();
        for topic_str in to_unfollow {
            let topic = libp2p::gossipsub::IdentTopic::new(&topic_str);
            let _ = self.node.swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
            self.files.followed.remove(&topic_str);
        }
    }

    pub(super) fn share_file(&mut self, path: PathBuf) {
        // Em servidor, os pedaços vão cifrados com uma chave que só viaja na oferta (MLS)
        let key = match self.active.server_id() {
            Some(_) if !self.active_room().is_some_and(|(_, _, room)| self.mls.has_group(&room)) => return self.error(CoreError::NoGroupKey),
            Some(_) => Some(FileKey::generate()),
            None => None,
        };
        let target = ShareTarget::Topic(self.active.topic.hash().into_string());
        self.build_manifest(path, key, target);
    }

    pub(super) fn send_file(&mut self, to: &str, path: PathBuf) {
        match self.find_peer(to) {
            Some(peer) => self.build_manifest(path, None, ShareTarget::Peer(peer)),
            None => self.error(CoreError::PeerNotFound(to.to_string())),
        }
    }

    /// Lê o arquivo e monta o manifesto numa thread de bloqueio, sem travar o loop
    fn build_manifest(&mut self, path: PathBuf, key: Option<FileKey>, target: ShareTarget) {
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
        self.emit(CoreEvent::FilePreparing { name });
        let (tx, identity) = (self.files.tx.clone(), self.identity.clone());
        tokio::task::spawn_blocking(move || {
            let manifest = Manifest::from_file(&path, &identity, key.as_ref(), super::now_secs());
            let _ = tx.send(ManifestJob { manifest, path, key, target });
        });
    }

    pub(super) fn manifest_ready(&mut self, job: ManifestJob) {
        match job.manifest {
            Ok(manifest) => {
                let nick = self.nick.clone();
                self.files.watch_file_parent(&job.path);
                let (_, actions) = self.files.engine.share(manifest, job.path, job.key, job.target, &nick);
                self.sync_swarm_topics();
                self.apply_file_actions(actions);
            }
            Err(e) => self.error(CoreError::Io { context: job.path.display().to_string(), message: e.to_string() }),
        }
    }

    /// Chamado imediatamente quando o watcher de arquivos do SO (`notify`) avisa que um arquivo
    /// monitorado foi deletado/movido no disco (sem polling).
    pub(super) fn on_fs_watch_event(&mut self) {
        let actions = self.files.engine.on_fs_change();
        self.sync_swarm_topics();
        if !actions.is_empty() {
            self.apply_file_actions(actions);
        }
    }

    pub(super) fn get_file(&mut self, query: &str) {
        match self.files.engine.get(query, Instant::now()) {
            Ok(actions) => {
                self.sync_swarm_topics();
                self.apply_file_actions(actions);
            }
            Err(e) => self.error(CoreError::File(e)),
        }
    }

    pub(super) fn reject_file(&mut self, query: &str) {
        match self.files.engine.dismiss(query) {
            Ok(name) => self.emit(CoreEvent::File(FileEvent::Dismissed { name })),
            Err(e) => self.error(CoreError::File(e)),
        }
    }

    pub(super) fn unshare_file(&mut self, query: &str) {
        match self.files.engine.unshare(query) {
            Ok(name) => {
                self.sync_swarm_topics();
                self.emit(CoreEvent::File(FileEvent::Unshared { name }));
            }
            Err(e) => self.error(CoreError::File(e)),
        }
    }

    pub(super) fn list_files(&mut self) {
        self.emit(CoreEvent::Files(self.files.engine.list(Instant::now())));
    }

    pub(super) fn files_tick(&mut self) {
        let now = Instant::now();
        self.drain_pending_uploads(now);
        self.sync_swarm_topics();
        let actions = self.files.engine.tick(now);
        self.apply_file_actions(actions);
    }

    fn drain_pending_uploads(&mut self, now: Instant) {
        while let Some(front) = self.files.pending_uploads.front() {
            if now.duration_since(front.enqueued_at) >= UPLOAD_QUEUE_TIMEOUT {
                let item = self.files.pending_uploads.pop_front().unwrap();
                let _ = self
                    .node
                    .swarm
                    .behaviour_mut()
                    .files
                    .send_response(item.channel, swarm_files::FileResponse::Busy);
                continue;
            }
            if self.files.upload_limiter.try_consume(front.bytes) {
                let item = self.files.pending_uploads.pop_front().unwrap();
                let _ = self
                    .node
                    .swarm
                    .behaviour_mut()
                    .files
                    .send_response(item.channel, item.response);
            } else {
                break;
            }
        }
    }

    /// Pedidos de outros pares e respostas aos nossos pelo protocolo de arquivos
    pub(super) fn on_files_event(&mut self, event: request_response::Event<FileRequest, swarm_files::FileResponse>) {
        let now = Instant::now();
        let actions = match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request { request, channel, .. } => {
                    let requester = pubkey_hex_from_peer_id(&peer);
                    let requester_pk = requester
                        .clone()
                        .unwrap_or_else(|| peer.to_string())
                        .to_lowercase();
                    if self.check_node_firewall(
                        Some(peer),
                        &requester_pk,
                        crate::firewall::FirewallCategory::ChunkRequest,
                        super::now_secs(),
                    ) != crate::firewall::FirewallVerdict::Allowed
                    {
                        let _ = self
                            .node
                            .swarm
                            .behaviour_mut()
                            .files
                            .send_response(channel, swarm_files::FileResponse::NotFound);
                        return;
                    }
                    // Arquivo de servidor: só responde a membros do grupo cifrado da sala do arquivo
                    let mls = &self.mls;
                    let active_room = self.active_room();
                    let allow = |topic: &str| {
                        if community::parse_server_content_topic(topic).is_none() {
                            return true;
                        }
                        let room = match community::parse_room_topic(topic) {
                            Some((server_id, channel)) => Some(community::room_id(server_id, channel)),
                            None => active_room.as_ref().map(|(_, _, room)| room.clone()),
                        };
                        room.is_some_and(|room| requester.as_ref().is_some_and(|pk| mls.members(&room).contains(pk)))
                    };
                    let (response, actions) = self.files.engine.handle_request(peer, request, &allow, now);
                    let cost = response_byte_len(&response);
                    if cost == 0
                        || self.files.upload_limiter.is_unlimited()
                        || (self.files.pending_uploads.is_empty() && self.files.upload_limiter.try_consume(cost))
                    {
                        let _ = self.node.swarm.behaviour_mut().files.send_response(channel, response);
                    } else {
                        self.files.pending_uploads.push_back(PendingUpload {
                            channel,
                            response,
                            bytes: cost,
                            enqueued_at: now,
                        });
                    }
                    actions
                }
                request_response::Message::Response { request_id, response } => match self.files.requests.remove(&request_id) {
                    Some((peer, request)) => self.files.engine.on_response(peer, request, response, now),
                    None => Vec::new(),
                },
            },
            request_response::Event::OutboundFailure { request_id, error, .. } => match self.files.requests.remove(&request_id) {
                Some((peer, request)) => {
                    tracing::debug!("Pedido de arquivo para {} falhou: {}", peer, error);
                    self.files.engine.on_failure(peer, request, now)
                }
                None => Vec::new(),
            },
            _ => Vec::new(),
        };
        self.apply_file_actions(actions);
    }

    /// Executa o que o motor do enxame pediu
    pub(super) fn apply_file_actions(&mut self, actions: Vec<FileAction>) {
        let mut queue: std::collections::VecDeque<FileAction> = actions.into();
        while let Some(action) = queue.pop_front() {
            match action {
                FileAction::Request { peer, request } => {
                    let id = self.node.swarm.behaviour_mut().files.send_request(&peer, request.clone());
                    self.files.requests.insert(id, (peer, request));
                }
                FileAction::Publish { topic, message } => {
                    if topic.starts_with("anarchord/file/") {
                        self.sync_swarm_topics();
                    }
                    if self.publish_content(&libp2p::gossipsub::IdentTopic::new(topic), crate::wire::encode(&message)).is_err() {
                        tracing::debug!("Mensagem do enxame não publicada (sem pares no tópico ou sem chave do grupo)");
                    }
                }
                FileAction::Provide(cid) => self.node.dht_provide(swarm_files::dht_key(&cid)),
                FileAction::FindProviders(cid) => self.node.dht_find(swarm_files::dht_key(&cid)),
                FileAction::Event(event) => {
                    if let FileEvent::Completed { path, .. } = &event {
                        self.files.watch_file_parent(path);
                    }
                    // Modo de teste: baixa tudo o que for oferecido
                    if let (true, FileEvent::Offered { cid, .. }) = (self.config.test_mode, &event) {
                        if let Ok(more) = self.files.engine.get(&cid.short(), Instant::now()) {
                            queue.extend(more);
                        }
                    }
                    self.emit(CoreEvent::File(event));
                }
            }
        }
    }
}
