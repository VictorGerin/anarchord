//! Motor do enxame: decide o que pedir a quem, atende os pedidos dos outros e avisa a interface.
//!
//! Não faz IO de rede: recebe o que chegou (mensagens da sala, pedidos e respostas do protocolo
//! `/anarchord/files/1`, provedores achados na DHT, ticks) e devolve [`FileAction`]s para o loop
//! de rede executar. Assim a mesma lógica serve à TUI, à GUI futura e aos testes, que ligam
//! vários motores entre si em memória.

use super::cid::Cid;
use super::crypto::FileKey;
use super::manifest::Manifest;
use super::protocol::{FileRequest, FileResponse};
use super::store::{Origin, PieceStore};
use super::{file_swarm_topic, OfferInfo, SwarmMessage};
use libp2p::PeerId;
use rand::Rng;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Pedidos de pedaço em andamento por par e no total
const MAX_INFLIGHT_PER_PEER: u32 = 4;
const MAX_INFLIGHT: usize = 16;
const PIECE_TIMEOUT: Duration = Duration::from_secs(15);
const MANIFEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Pedaços errados ou falhas antes de ignorar o par neste arquivo
const MAX_STRIKES: u32 = 3;
const BUSY_PAUSE: Duration = Duration::from_secs(2);
/// Timeout de busca quando não há nenhum par disponível para o manifesto ou pedaços restantes (Issue #67)
const MANIFEST_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(15);
const PIECE_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);
/// De quanto em quanto tempo quem está baixando anuncia os pedaços novos no enxame
const HAVE_INTERVAL: Duration = Duration::from_secs(5);
/// Sem ninguém para pedir: pergunta de novo no enxame e na DHT
const WANT_INTERVAL: Duration = Duration::from_secs(15);
const WANT_RETRY_INTERVAL: Duration = Duration::from_secs(2);
const FIND_INTERVAL: Duration = Duration::from_secs(30);
const HAVE_REPLY_INTERVAL: Duration = Duration::from_secs(3);
const PROGRESS_INTERVAL: Duration = Duration::from_millis(500);

/// Para onde vai a oferta de um arquivo compartilhado
#[derive(Clone, Debug, PartialEq)]
pub enum ShareTarget {
    /// Sala (tópico do canal no Lobby ou num servidor)
    Topic(String),
    /// Um par só (`/send`)
    Peer(PeerId),
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum FileEvent {
    Offered { cid: Cid, name: String, size: u64, from: String, direct: bool },
    Shared { cid: Cid, name: String },
    Started { cid: Cid, name: String },
    Progress { cid: Cid, name: String, progress: f32, peers: usize },
    Completed { cid: Cid, name: String, path: PathBuf },
    Failed { cid: Cid, name: String, reason: String },
    /// Oferta recusada
    Dismissed { name: String },
    /// Parou de compartilhar ou cancelou o download
    Unshared { name: String },
    /// O arquivo local foi removido do disco: deixou de semear e voltou a ficar disponível para download (`Offered`)
    LocalFileRemoved { cid: Cid, name: String, from: String },
}

#[derive(Clone, Debug, PartialEq)]
pub enum FileAction {
    /// Enviar um pedido pelo protocolo de arquivos
    Request { peer: PeerId, request: FileRequest },
    /// Publicar na sala
    Publish { topic: String, message: SwarmMessage },
    /// Anunciar na DHT que temos o arquivo (só arquivos públicos)
    Provide(Cid),
    /// Procurar na DHT quem tem o arquivo
    FindProviders(Cid),
    Event(FileEvent),
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum FileState {
    Offered,
    Downloading { progress: f32, peers: usize },
    Seeding,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FileSummary {
    pub cid: Cid,
    pub name: String,
    pub size: u64,
    pub from: String,
    pub state: FileState,
}

/// Quem pode pedir o arquivo a este nó
#[derive(Clone, Debug, PartialEq)]
enum Audience {
    /// Quem pode ler a sala (no servidor, os membros)
    Topic(String),
    /// Só um par (envio direto)
    Peer(PeerId),
    /// Download retomado de arquivo público: qualquer um
    Anyone,
    /// Download retomado de arquivo de servidor: ninguém, até sabermos de que sala ele é
    Nobody,
}

#[derive(Default)]
struct PeerInfo {
    /// Bitfield cru recebido (conferido contra o manifesto quando ele chega)
    have: Option<Vec<u8>>,
    /// Quem publicou tem tudo
    full: bool,
    inflight: u32,
    strikes: u32,
    paused_until: Option<Instant>,
    asked_bitfield: bool,
}

impl PeerInfo {
    fn has(&self, index: u32) -> bool {
        self.full || self.have.as_ref().is_some_and(|bits| bits.get(index as usize / 8).is_some_and(|b| b & (1 << (index % 8)) != 0))
    }

    fn has_any(&self) -> bool {
        self.full || self.have.as_ref().is_some_and(|bits| bits.iter().any(|b| *b != 0))
    }

    fn usable(&self, now: Instant) -> bool {
        self.strikes < MAX_STRIKES && self.paused_until.map_or(true, |t| now >= t)
    }
}

#[derive(Default)]
struct Download {
    manifest_request: Option<(PeerId, Instant)>,
    inflight: HashMap<u32, (PeerId, Instant)>,
    last_progress: Option<Instant>,
    last_have: Option<Instant>,
    have_dirty: bool,
    last_want: Option<Instant>,
    last_find: Option<Instant>,
    no_source_since: Option<Instant>,
}

struct Entry {
    offer: OfferInfo,
    audience: Audience,
    store: Option<PieceStore>,
    download: Option<Download>,
    peers: HashMap<PeerId, PeerInfo>,
    last_have_reply: Option<Instant>,
    is_own_share: bool,
}

impl Entry {
    fn topic(&self) -> Option<&str> {
        match &self.audience {
            Audience::Topic(topic) => Some(topic),
            _ => None,
        }
    }

    fn public(&self) -> bool {
        self.offer.key.is_none() && !matches!(self.audience, Audience::Peer(_))
    }

    fn permits(&self, peer: &PeerId, allow: &dyn Fn(&str) -> bool) -> bool {
        match &self.audience {
            Audience::Topic(topic) => allow(topic),
            Audience::Peer(p) => p == peer,
            Audience::Anyone => true,
            Audience::Nobody => false,
        }
    }

    /// Mensagem vinda de uma sala: um download retomado passa a pertencer a ela
    fn adopt_topic(&mut self, topic: &str) {
        if !topic.starts_with("anarchord/file/") && matches!(self.audience, Audience::Anyone | Audience::Nobody) {
            self.audience = Audience::Topic(topic.to_string());
        }
    }

    fn known_peers(&self, now: Instant) -> usize {
        self.peers.values().filter(|p| p.usable(now) && p.has_any()).count()
    }
}

pub struct FileEngine {
    partial_dir: PathBuf,
    download_dir: PathBuf,
    files: HashMap<Cid, Entry>,
}

impl FileEngine {
    /// `partial_dir` guarda downloads em andamento; `download_dir` recebe os arquivos completos
    pub fn new(partial_dir: PathBuf, download_dir: PathBuf) -> Self {
        Self { partial_dir, download_dir, files: HashMap::new() }
    }

    /// Diretório onde os downloads completos são salvos (`download_dir`)
    pub fn download_dir(&self) -> &std::path::Path {
        &self.download_dir
    }

    /// Retoma os downloads que ficaram pela metade na última execução
    pub fn resume(&mut self, now: Instant) -> Vec<FileAction> {
        let mut actions = Vec::new();
        for cid in PieceStore::pending(&self.partial_dir) {
            if self.files.contains_key(&cid) {
                continue;
            }
            let Ok(store) = PieceStore::open(&self.partial_dir, &cid) else { continue };
            let body = &store.manifest().body;
            let offer = OfferInfo {
                manifest: cid,
                name: body.name.clone(),
                size: body.size,
                publisher: body.publisher.clone(),
                publisher_name: body.publisher.chars().take(8).collect(),
                key: store.key().cloned(),
            };
            let peers = HashMap::new();
            let audience = match store.origin() {
                Some(Origin::Topic(topic)) => Audience::Topic(topic.clone()),
                Some(Origin::Peer(peer)) => match peer.parse::<PeerId>() {
                    Ok(peer) => Audience::Peer(peer),
                    Err(_) => Audience::Nobody,
                },
                None if offer.key.is_some() => Audience::Nobody,
                None => Audience::Anyone,
            };
            actions.push(FileAction::Event(FileEvent::Started { cid, name: offer.name.clone() }));
            // Issue #68: Emite progresso herdado do download parcial e publica Want imediatamente no enxame
            let progress = store.progress();
            let known_p = peers.len();
            actions.push(FileAction::Event(FileEvent::Progress {
                cid,
                name: offer.name.clone(),
                progress,
                peers: known_p,
            }));
            actions.push(FileAction::Publish {
                topic: file_swarm_topic(&cid),
                message: SwarmMessage::Want { manifest: cid },
            });
            self.files.insert(
                cid,
                Entry {
                    offer,
                    audience,
                    store: Some(store),
                    download: Some(Download { last_want: None, ..Default::default() }),
                    peers,
                    last_have_reply: None,
                    is_own_share: false,
                },
            );
        }
        actions.extend(self.tick(now));
        actions
    }

    /// Passa a semear um arquivo local e oferece na sala ou a um par.
    /// O manifesto é montado antes, fora do loop (`Manifest::from_file` lê o arquivo inteiro).
    pub fn share(
        &mut self,
        manifest: Manifest,
        path: PathBuf,
        key: Option<FileKey>,
        target: ShareTarget,
        publisher_name: &str,
    ) -> (Cid, Vec<FileAction>) {
        let cid = manifest.cid();
        let offer = OfferInfo {
            manifest: cid,
            name: manifest.body.name.clone(),
            size: manifest.body.size,
            publisher: manifest.body.publisher.clone(),
            publisher_name: publisher_name.to_string(),
            key: key.clone(),
        };
        let audience = match &target {
            ShareTarget::Topic(topic) => Audience::Topic(topic.clone()),
            ShareTarget::Peer(peer) => Audience::Peer(*peer),
        };
        let mut actions = vec![FileAction::Event(FileEvent::Shared { cid, name: offer.name.clone() })];
        match target {
            ShareTarget::Topic(topic) => {
                if key.is_none() {
                    actions.push(FileAction::Provide(cid));
                }
                actions.push(FileAction::Publish { topic, message: SwarmMessage::Offer(offer.clone()) });
            }
            ShareTarget::Peer(peer) => actions.push(FileAction::Request { peer, request: FileRequest::Offer(offer.clone()) }),
        }
        let store = PieceStore::seed(manifest, path, key);
        self.files.insert(cid, Entry { offer, audience, store: Some(store), download: None, peers: HashMap::new(), last_have_reply: None, is_own_share: true });
        (cid, actions)
    }

    /// Mensagem do enxame recebida numa sala. Quem chama já conferiu que uma oferta foi publicada
    /// pela pubkey em `publisher`.
    pub fn on_gossip(&mut self, source: PeerId, topic: &str, message: SwarmMessage, now: Instant) -> Vec<FileAction> {
        match message {
            SwarmMessage::Offer(offer) => {
                let cid = offer.manifest;
                if let Some(entry) = self.files.get_mut(&cid) {
                    entry.peers.entry(source).or_default().full = true;
                    entry.adopt_topic(topic);
                    if entry.offer.key.is_none() {
                        entry.offer.key = offer.key;
                    }
                    return self.schedule(&cid, now);
                }
                let event = FileEvent::Offered {
                    cid,
                    name: offer.name.clone(),
                    size: offer.size,
                    from: offer.publisher_name.clone(),
                    direct: false,
                };
                let mut peers = HashMap::new();
                peers.insert(source, PeerInfo { full: true, ..Default::default() });
                self.files.insert(
                    cid,
                    Entry { offer, audience: Audience::Topic(topic.to_string()), store: None, download: None, peers, last_have_reply: None, is_own_share: false },
                );
                vec![FileAction::Event(event)]
            }
            SwarmMessage::Have { manifest, have } => {
                let Some(entry) = self.files.get_mut(&manifest) else { return Vec::new() };
                let is_swarm = topic == file_swarm_topic(&manifest);
                let is_room = entry.topic() == Some(topic);
                if !is_swarm && !is_room {
                    return Vec::new();
                }
                if entry.store.as_ref().is_some_and(|s| s.manifest().piece_count() != have.len()) {
                    return Vec::new();
                }
                entry.adopt_topic(topic);
                let info = entry.peers.entry(source).or_default();
                info.have = Some(have.as_bytes().to_vec());
                info.full = have.len() > 0 && have.is_complete();
                self.schedule(&manifest, now)
            }
            SwarmMessage::Want { manifest } => {
                let Some(entry) = self.files.get_mut(&manifest) else { return Vec::new() };
                let is_swarm = topic == file_swarm_topic(&manifest);
                let is_room = entry.topic() == Some(topic);
                if !is_swarm && !is_room {
                    return Vec::new();
                }
                entry.adopt_topic(topic);
                let Some(store) = &entry.store else { return Vec::new() };
                let recent = entry.last_have_reply.is_some_and(|t| now.duration_since(t) < HAVE_REPLY_INTERVAL);
                if store.have().count() == 0 || recent {
                    return Vec::new();
                }
                entry.last_have_reply = Some(now);
                vec![FileAction::Publish {
                    topic: file_swarm_topic(&manifest),
                    message: SwarmMessage::Have { manifest, have: store.have().clone() },
                }]
            }
        }
    }

    /// Pedido de outro par. `allow(topic)` diz se o par pode ler a sala do arquivo
    /// (no servidor, se é membro). Retorna a resposta e o que mais fazer.
    pub fn handle_request(
        &mut self,
        peer: PeerId,
        request: FileRequest,
        allow: &dyn Fn(&str) -> bool,
        now: Instant,
    ) -> (FileResponse, Vec<FileAction>) {
        let cid = match &request {
            FileRequest::Offer(offer) => return (FileResponse::Ok, self.on_direct_offer(peer, offer.clone(), now)),
            FileRequest::GetManifest { cid } | FileRequest::GetBitfield { cid } | FileRequest::GetPiece { cid, .. } => *cid,
        };
        let Some(entry) = self.files.get(&cid) else { return (FileResponse::NotFound, Vec::new()) };
        let Some(store) = entry.store.as_ref().filter(|_| entry.permits(&peer, allow)) else {
            return (FileResponse::NotFound, Vec::new());
        };
        let response = match request {
            FileRequest::GetManifest { .. } => FileResponse::Manifest(store.manifest().to_bytes()),
            FileRequest::GetBitfield { .. } => FileResponse::Bitfield(store.have().as_bytes().to_vec()),
            FileRequest::GetPiece { index, .. } => store.serve_piece(index).map(FileResponse::Piece).unwrap_or(FileResponse::NotFound),
            FileRequest::Offer(_) => unreachable!(),
        };
        (response, Vec::new())
    }

    fn on_direct_offer(&mut self, source: PeerId, offer: OfferInfo, _now: Instant) -> Vec<FileAction> {
        let cid = offer.manifest;
        if self.files.contains_key(&cid) {
            if let Some(entry) = self.files.get_mut(&cid) {
                entry.peers.entry(source).or_default().full = true;
            }
            return Vec::new();
        }
        let event = FileEvent::Offered { cid, name: offer.name.clone(), size: offer.size, from: offer.publisher_name.clone(), direct: true };
        let mut peers = HashMap::new();
        peers.insert(source, PeerInfo { full: true, ..Default::default() });
        self.files.insert(cid, Entry { offer, audience: Audience::Peer(source), store: None, download: None, peers, last_have_reply: None, is_own_share: false });
        vec![FileAction::Event(event)]
    }

    /// Começa (ou retoma) o download de um arquivo oferecido. `query` é o prefixo do id ou o nome.
    pub fn get(&mut self, query: &str, now: Instant) -> Result<Vec<FileAction>, String> {
        let cid = self.find(query)?;
        let partial_dir = self.partial_dir.clone();
        let entry = self.files.get_mut(&cid).expect("achado acima");
        if entry.download.is_some() {
            return Err(format!("'{}' já está sendo baixado", entry.offer.name));
        }
        // Se tínhamos um store completo mas o arquivo foi deletado do disco antes do evento do watcher chegar,
        // limpamos o store obsoleto para permitir baixar novamente na hora!
        if entry.store.as_ref().is_some_and(|s| s.is_complete() && !s.path().exists()) {
            entry.store = None;
        }
        if entry.store.as_ref().is_some_and(|s| s.is_complete()) {
            return Err(format!("você já tem '{}'", entry.offer.name));
        }
        if entry.store.is_none() {
            entry.store = PieceStore::open(&partial_dir, &cid).ok();
        }
        for p in entry.peers.values_mut() {
            p.asked_bitfield = false;
            p.strikes = 0;
            p.paused_until = None;
        }
        entry.download = Some(Download { last_want: Some(now), ..Default::default() });
        let mut actions = vec![FileAction::Event(FileEvent::Started { cid, name: entry.offer.name.clone() })];
        // Issue #66: Publica Want no tópico dedicado do arquivo (anarchord/file/<cid>)
        actions.push(FileAction::Publish {
            topic: file_swarm_topic(&cid),
            message: SwarmMessage::Want { manifest: cid },
        });
        actions.extend(self.schedule(&cid, now));
        Ok(actions)
    }

    /// Recusa uma oferta (some da lista). Retorna o nome.
    pub fn dismiss(&mut self, query: &str) -> Result<String, String> {
        let cid = self.find(query)?;
        let entry = &self.files[&cid];
        if entry.store.is_some() || entry.download.is_some() {
            return Err(format!("'{}' já está baixando ou semeando: use /unshare", entry.offer.name));
        }
        Ok(self.files.remove(&cid).map(|e| e.offer.name).unwrap_or_default())
    }

    /// Para de semear ou cancela o download (apagando o parcial).
    /// - Se o arquivo foi publicado originalmente por nós mesmos (`is_own_share`), remove da lista completamente.
    /// - Se o arquivo foi oferecido por outro par (ex.: Alice mandou para Bob e Bob baixou ou estava baixando),
    ///   descarta apenas o `store`/`download` local de Bob e mantém a oferta (`Offered`) para que Bob possa
    ///   baixar novamente da Alice quando quiser com `/get <id>`!
    pub fn unshare(&mut self, query: &str) -> Result<String, String> {
        let cid = self.find(query)?;
        let entry = self.files.get(&cid).expect("achado acima");
        if entry.is_own_share {
            let entry = self.files.remove(&cid).expect("achado acima");
            if let Some(store) = entry.store.filter(|s| !s.is_complete()) {
                store.discard();
            }
            Ok(entry.offer.name)
        } else {
            let entry = self.files.get_mut(&cid).expect("achado acima");
            entry.download = None;
            if let Some(store) = entry.store.take() {
                if !store.is_complete() {
                    store.discard();
                }
            }
            Ok(entry.offer.name.clone())
        }
    }

    /// Orientado a eventos do SO (`notify`): chamado imediatamente quando o sistema operacional
    /// notifica que arquivos foram removidos ou movidos no diretório de downloads/compartilhamento.
    /// Sem precisar de polling, verifica quais arquivos semeados (`store.is_some()`) não existem mais
    /// no disco, atualiza o estado interno, avisa a sala (bitfield vazio) e emite evento para a UI!
    pub fn on_fs_change(&mut self) -> Vec<FileAction> {
        let mut actions = Vec::new();
        let mut remove_cids = Vec::new();
        for (&cid, entry) in self.files.iter_mut() {
            let Some(store) = &entry.store else { continue };
            if store.is_complete() && !store.path().exists() {
                let piece_count = store.manifest().piece_count();
                let name = entry.offer.name.clone();
                let from = entry.offer.publisher_name.clone();
                let is_own_share = entry.is_own_share;
                entry.store = None;
                entry.download = None;
                actions.push(FileAction::Publish {
                    topic: file_swarm_topic(&cid),
                    message: SwarmMessage::Have {
                        manifest: cid,
                        have: super::store::Bitfield::new(piece_count),
                    },
                });
                if is_own_share {
                    remove_cids.push(cid);
                    actions.push(FileAction::Event(FileEvent::Unshared { name }));
                } else {
                    actions.push(FileAction::Event(FileEvent::LocalFileRemoved { cid, name, from }));
                }
            }
        }
        for cid in remove_cids {
            self.files.remove(&cid);
        }
        actions
    }

    pub fn list(&self, now: Instant) -> Vec<FileSummary> {
        let mut list: Vec<FileSummary> = self
            .files
            .values()
            .map(|entry| FileSummary {
                cid: entry.offer.manifest,
                name: entry.offer.name.clone(),
                size: entry.offer.size,
                from: entry.offer.publisher_name.clone(),
                state: match (&entry.download, &entry.store) {
                    (Some(_), store) => FileState::Downloading {
                        progress: store.as_ref().map_or(0.0, |s| s.progress()),
                        peers: entry.known_peers(now),
                    },
                    (None, Some(store)) => {
                        if store.is_complete() && store.path().exists() {
                            FileState::Seeding
                        } else {
                            FileState::Offered
                        }
                    }
                    (None, None) => FileState::Offered,
                },
            })
            .collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        list
    }

    /// Resposta a um pedido nosso
    pub fn on_response(&mut self, peer: PeerId, request: FileRequest, response: FileResponse, now: Instant) -> Vec<FileAction> {
        let cid = match &request {
            FileRequest::Offer(_) => return Vec::new(),
            FileRequest::GetManifest { cid } | FileRequest::GetBitfield { cid } | FileRequest::GetPiece { cid, .. } => *cid,
        };
        let partial_dir = self.partial_dir.clone();
        let Some(entry) = self.files.get_mut(&cid) else { return Vec::new() };
        let mut actions = Vec::new();
        release(entry, &peer, &request);
        match (request, response) {
            (FileRequest::GetManifest { .. }, FileResponse::Manifest(bytes)) => {
                if entry.store.is_none() && entry.download.is_some() {
                    match Manifest::from_bytes(&bytes, &cid) {
                        Ok(manifest) if manifest.body.publisher == entry.offer.publisher => {
                            let origin = match &entry.audience {
                                Audience::Topic(topic) => Some(Origin::Topic(topic.clone())),
                                Audience::Peer(peer) => Some(Origin::Peer(peer.to_string())),
                                _ => None,
                            };
                            match PieceStore::create(&partial_dir, manifest, entry.offer.key.clone(), origin) {
                                Ok(store) => entry.store = Some(store),
                                Err(e) => {
                                    entry.download = None;
                                    actions.push(failed(&entry.offer, format!("não deu para criar o arquivo parcial: {}", e)));
                                }
                            }
                        }
                        _ => strike(entry, &peer),
                    }
                }
            }
            (FileRequest::GetBitfield { .. }, FileResponse::Bitfield(bytes)) => {
                let expected = entry.store.as_ref().map(|s| (s.manifest().piece_count() as usize).div_ceil(8));
                if expected.is_none_or(|len| len == bytes.len()) {
                    entry.peers.entry(peer).or_default().have = Some(bytes);
                }
            }
            (FileRequest::GetPiece { index, .. }, FileResponse::Piece(bytes)) => {
                if let (Some(store), Some(download)) = (entry.store.as_mut(), entry.download.as_mut()) {
                    match store.accept_piece(index, &bytes) {
                        Ok(()) => download.have_dirty = true,
                        Err(super::store::PieceError::Io(e)) => {
                            entry.download = None;
                            actions.push(failed(&entry.offer, format!("erro de disco: {}", e)));
                        }
                        Err(_) => strike(entry, &peer),
                    }
                }
            }
            (_, FileResponse::Busy) => {
                entry.peers.entry(peer).or_default().paused_until = Some(now + BUSY_PAUSE);
            }
            (_, FileResponse::NotFound) => {
                entry.peers.remove(&peer);
                if matches!(entry.audience, Audience::Peer(p) if p == peer) {
                    entry.download = None;
                    actions.push(failed(&entry.offer, "o par não possui mais este arquivo (pode ter parado de compartilhar)".into()));
                    return actions;
                }
                if let Some(download) = entry.download.as_mut() {
                    let has_source = match &entry.store {
                        None => entry.peers.values().any(|p| p.usable(now) && (p.full || p.has_any() || p.have.is_none())),
                        Some(store) => {
                            !download.inflight.is_empty()
                                || entry.peers.values().any(|p| p.usable(now) && store.have().missing().any(|idx| p.has(idx)))
                        }
                    };
                    if !has_source {
                        download.no_source_since.get_or_insert(now);
                    }
                }
            }
            _ => strike(entry, &peer),
        }
        actions.extend(self.after_change(&cid, now));
        actions
    }

    /// Pedido nosso que falhou (par desconectou, timeout do protocolo...)
    pub fn on_failure(&mut self, peer: PeerId, request: FileRequest, now: Instant) -> Vec<FileAction> {
        let cid = match &request {
            FileRequest::Offer(offer) => {
                let name = offer.name.clone();
                return vec![FileAction::Event(FileEvent::Failed { cid: offer.manifest, name, reason: "o par não recebeu a oferta".into() })];
            }
            FileRequest::GetManifest { cid } | FileRequest::GetBitfield { cid } | FileRequest::GetPiece { cid, .. } => *cid,
        };
        let Some(entry) = self.files.get_mut(&cid) else { return Vec::new() };
        release(entry, &peer, &request);
        strike(entry, &peer);
        entry.peers.entry(peer).or_default().paused_until = Some(now + BUSY_PAUSE);
        if matches!(entry.audience, Audience::Peer(p) if p == peer) {
            let strikes = entry.peers.get(&peer).map_or(0, |p| p.strikes);
            if strikes >= MAX_STRIKES {
                entry.download = None;
                return vec![failed(&entry.offer, "o par de envio direto está inacessível ou desconectou".into())];
            }
        }
        self.schedule(&cid, now)
    }

    /// Pares achados na DHT para um arquivo
    pub fn add_providers(&mut self, cid: &Cid, providers: impl IntoIterator<Item = PeerId>, now: Instant) -> Vec<FileAction> {
        let Some(entry) = self.files.get_mut(cid) else { return Vec::new() };
        if entry.download.is_none() {
            return Vec::new();
        }
        for peer in providers {
            entry.peers.entry(peer).or_default();
        }
        self.schedule(cid, now)
    }

    /// CIDs dos arquivos que estamos baixando (para reconhecer respostas da DHT)
    pub fn downloading(&self) -> impl Iterator<Item = &Cid> {
        self.files.iter().filter(|(_, e)| e.download.is_some()).map(|(cid, _)| cid)
    }

    /// Tópicos de enxame ativos (arquivos que estamos baixando ou semeando)
    pub fn swarm_topics(&self) -> Vec<String> {
        let mut topics: Vec<String> = self
            .files
            .iter()
            .filter(|(_, e)| e.download.is_some() || e.store.as_ref().is_some_and(|s| s.have().count() > 0))
            .map(|(cid, _)| file_swarm_topic(cid))
            .collect();
        topics.sort();
        topics.dedup();
        topics
    }

    /// Salas e tópicos de arquivos ativos (mantido para compatibilidade)
    pub fn download_topics(&self) -> Vec<String> {
        self.swarm_topics()
    }

    /// Arquivos públicos que temos (para reanunciar na DHT)
    pub fn providing(&self) -> Vec<Cid> {
        self.files.iter().filter(|(_, e)| e.public() && e.store.as_ref().is_some_and(|s| s.have().count() > 0)).map(|(c, _)| *c).collect()
    }

    /// Chamado periodicamente (~1 s): timeouts, novos pedidos e anúncios
    pub fn tick(&mut self, now: Instant) -> Vec<FileAction> {
        let cids: Vec<Cid> = self.downloading().copied().collect();
        let mut actions = Vec::new();
        for cid in cids {
            let Some(entry) = self.files.get_mut(&cid) else { continue };
            let known = entry.known_peers(now);
            let public = entry.public();
            let have = entry.store.as_ref().map(|s| s.have().clone());
            let Some(download) = entry.download.as_mut() else { continue };
            let due = |last: Option<Instant>, every: Duration| last.is_none_or(|t| now.duration_since(t) >= every);
            if let Some(have) = &have {
                if download.have_dirty && due(download.last_have, HAVE_INTERVAL) {
                    download.have_dirty = false;
                    download.last_have = Some(now);
                    actions.push(FileAction::Publish {
                        topic: file_swarm_topic(&cid),
                        message: SwarmMessage::Have { manifest: cid, have: have.clone() },
                    });
                }
            }
            let has_source = match &entry.store {
                None => entry.peers.values().any(|p| p.usable(now) && (p.full || p.has_any() || p.have.is_none())),
                Some(store) => {
                    store.is_complete()
                        || !download.inflight.is_empty()
                        || entry.peers.values().any(|p| p.usable(now) && store.have().missing().any(|idx| p.has(idx)))
                }
            };

            if known == 0 || !has_source {
                let wait = if known == 0 || !has_source { WANT_RETRY_INTERVAL } else { WANT_INTERVAL };
                if due(download.last_want, wait) {
                    download.last_want = Some(now);
                    actions.push(FileAction::Publish {
                        topic: file_swarm_topic(&cid),
                        message: SwarmMessage::Want { manifest: cid },
                    });
                    if !has_source && entry.store.is_some() {
                        for info in entry.peers.values_mut() {
                            if !info.full && info.usable(now) {
                                info.have = None;
                                info.asked_bitfield = false;
                            }
                        }
                    }
                }
                if public && due(download.last_find, FIND_INTERVAL) {
                    download.last_find = Some(now);
                    actions.push(FileAction::FindProviders(cid));
                }
            }

            // Timeout de descoberta quando não há fontes disponíveis (Issue #67)

            if !has_source {
                let since = download.no_source_since.get_or_insert(now);
                let timeout = if entry.store.is_none() { MANIFEST_DISCOVERY_TIMEOUT } else { PIECE_DISCOVERY_TIMEOUT };
                if now.duration_since(*since) >= timeout {
                    let reason = if entry.store.is_none() {
                        "nenhum par disponível com o arquivo (o compartilhamento pode ter sido encerrado)".to_string()
                    } else {
                        "todos os pares com os pedaços restantes estão indisponíveis".to_string()
                    };
                    entry.download = None;
                    actions.push(failed(&entry.offer, reason));
                    continue;
                }
            } else {
                download.no_source_since = None;
            }

            actions.extend(self.after_change(&cid, now));
        }
        actions
    }

    fn find(&self, query: &str) -> Result<Cid, String> {
        let query = query.trim();
        let matches: Vec<Cid> = self
            .files
            .iter()
            .filter(|(cid, entry)| {
                cid.short().starts_with(query) || cid.to_string() == query || entry.offer.name.eq_ignore_ascii_case(query)
            })
            .map(|(cid, _)| *cid)
            .collect();
        match matches.as_slice() {
            [cid] => Ok(*cid),
            [] => Err(format!("nenhum arquivo com id ou nome '{}' (veja /files)", query)),
            _ => Err(format!("'{}' corresponde a mais de um arquivo; use mais letras do id", query)),
        }
    }

    /// Depois de uma resposta ou tick: conclui o download, informa progresso e pede mais
    fn after_change(&mut self, cid: &Cid, now: Instant) -> Vec<FileAction> {
        let download_dir = self.download_dir.clone();
        let Some(entry) = self.files.get_mut(cid) else { return Vec::new() };
        let Some(download) = entry.download.as_mut() else { return Vec::new() };
        let Some(store) = entry.store.as_mut() else { return self.schedule(cid, now) };
        if store.is_complete() {
            entry.download = None;
            let name = entry.offer.name.clone();
            return match store.finish(&download_dir) {
                Ok(path) => {
                    let mut actions = vec![FileAction::Event(FileEvent::Completed { cid: *cid, name, path })];
                    let have = store.have().clone();
                    actions.push(FileAction::Publish {
                        topic: file_swarm_topic(cid),
                        message: SwarmMessage::Have { manifest: *cid, have },
                    });
                    if entry.public() {
                        actions.push(FileAction::Provide(*cid));
                    }
                    actions
                }
                Err(e) => vec![failed(&entry.offer, format!("não deu para salvar: {}", e))],
            };
        }
        let mut actions = Vec::new();
        if download.last_progress.is_none_or(|t| now.duration_since(t) >= PROGRESS_INTERVAL) {
            download.last_progress = Some(now);
            let peers = entry.peers.values().filter(|p| p.usable(now) && p.has_any()).count();
            actions.push(FileAction::Event(FileEvent::Progress { cid: *cid, name: entry.offer.name.clone(), progress: store.progress(), peers }));
        }
        actions.extend(self.schedule(cid, now));
        actions
    }

    /// Escolhe os próximos pedidos: manifesto, mapas de pedaços e pedaços (os mais raros primeiro)
    fn schedule(&mut self, cid: &Cid, now: Instant) -> Vec<FileAction> {
        let Some(entry) = self.files.get_mut(cid) else { return Vec::new() };
        let Entry { store, download, peers, .. } = entry;
        let Some(download) = download.as_mut() else { return Vec::new() };
        let mut actions = Vec::new();

        let Some(store) = store.as_ref() else {
            let previous = download.manifest_request.map(|(p, _)| p);
            if let Some((prev_peer, t)) = download.manifest_request {
                if now.duration_since(t) >= MANIFEST_TIMEOUT {
                    if let Some(info) = peers.get_mut(&prev_peer) {
                        info.strikes += 1;
                    }
                    download.manifest_request = None;
                }
            }
            if download.manifest_request.is_none() {
                let candidate = peers
                    .iter()
                    .filter(|(_, p)| p.usable(now) && (p.full || p.has_any() || p.have.is_none()))
                    .min_by_key(|(id, p)| (Some(**id) == previous, !p.full, !p.has_any()))
                    .map(|(id, _)| *id);
                download.manifest_request = candidate.map(|p| (p, now));
                if let Some(peer) = candidate {
                    actions.push(FileAction::Request { peer, request: FileRequest::GetManifest { cid: *cid } });
                }
            }
            return actions;
        };

        // Pares que ainda não disseram o que têm
        for (id, info) in peers.iter_mut() {
            if !info.full && info.have.is_none() && !info.asked_bitfield && info.usable(now) {
                info.asked_bitfield = true;
                actions.push(FileAction::Request { peer: *id, request: FileRequest::GetBitfield { cid: *cid } });
            }
        }

        // Pedidos sem resposta há tempo demais voltam para a fila
        let expired: Vec<u32> =
            download.inflight.iter().filter(|(_, (_, t))| now.duration_since(*t) >= PIECE_TIMEOUT).map(|(i, _)| *i).collect();
        for index in expired {
            if let Some((peer, _)) = download.inflight.remove(&index) {
                if let Some(info) = peers.get_mut(&peer) {
                    info.inflight = info.inflight.saturating_sub(1);
                    info.strikes += 1;
                }
            }
        }

        // Pedaços que faltam, dos mais raros para os mais comuns (empate sorteado, para que
        // downloads simultâneos peçam pedaços diferentes e troquem entre si)
        let mut rng = rand::thread_rng();
        let mut wanted: Vec<(usize, u32, u32)> = store
            .have()
            .missing()
            .filter(|i| !download.inflight.contains_key(i))
            .filter_map(|i| {
                let availability = peers.values().filter(|p| p.usable(now) && p.has(i)).count();
                (availability > 0).then(|| (availability, rng.gen::<u32>(), i))
            })
            .collect();
        wanted.sort_unstable();
        for (_, _, index) in wanted {
            if download.inflight.len() >= MAX_INFLIGHT {
                break;
            }
            let peer = peers
                .iter()
                .filter(|(_, p)| p.usable(now) && p.inflight < MAX_INFLIGHT_PER_PEER && p.has(index))
                .min_by_key(|(_, p)| p.inflight)
                .map(|(id, _)| *id);
            if let Some(peer) = peer {
                peers.get_mut(&peer).expect("escolhido acima").inflight += 1;
                download.inflight.insert(index, (peer, now));
                actions.push(FileAction::Request { peer, request: FileRequest::GetPiece { cid: *cid, index } });
            }
        }
        actions
    }
}

/// Tira o pedido da lista de pendentes
fn release(entry: &mut Entry, peer: &PeerId, request: &FileRequest) {
    let Some(download) = entry.download.as_mut() else { return };
    match request {
        FileRequest::GetPiece { index, .. } => {
            if download.inflight.get(index).is_some_and(|(p, _)| p == peer) {
                download.inflight.remove(index);
                if let Some(info) = entry.peers.get_mut(peer) {
                    info.inflight = info.inflight.saturating_sub(1);
                }
            }
        }
        FileRequest::GetManifest { .. } => {
            if download.manifest_request.is_some_and(|(p, _)| p == *peer) {
                download.manifest_request = None;
            }
        }
        _ => {}
    }
}

fn strike(entry: &mut Entry, peer: &PeerId) {
    entry.peers.entry(*peer).or_default().strikes += 1;
}

fn failed(offer: &OfferInfo, reason: String) -> FileAction {
    FileAction::Event(FileEvent::Failed { cid: offer.manifest, name: offer.name.clone(), reason })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::PIECE_SIZE;
    use crate::identity::UserIdentity;
    use std::collections::{HashSet, VecDeque};

    const TOPIC: &str = "p2p-anarchord/channel/geral";

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("anarchord_engine_{}_{}_{}", tag, std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct Node {
        identity: UserIdentity,
        peer: PeerId,
        engine: FileEngine,
        events: Vec<FileEvent>,
        /// Pares que este nó recusa (não membros)
        deny: HashSet<PeerId>,
        /// Pedaços que ainda aceita servir (None = sem limite)
        budget: Option<u32>,
        /// Serve pedaços adulterados
        corrupt: bool,
        offline: bool,
    }

    /// Vários motores ligados em memória: publicações vão para todos, pedidos para o par certo
    struct Net {
        nodes: Vec<Node>,
        now: Instant,
        /// (quem serviu, quem recebeu) -> pedaços
        served: HashMap<(usize, usize), u32>,
    }

    impl Net {
        fn new(count: usize) -> Self {
            let nodes = (0..count)
                .map(|i| {
                    let identity = UserIdentity::generate();
                    let peer = crate::api::peer_id_from_pubkey_hex(&identity.public_key_hex()).unwrap();
                    Node {
                        identity,
                        peer,
                        engine: FileEngine::new(temp_dir(&format!("p{}", i)), temp_dir(&format!("d{}", i))),
                        events: Vec::new(),
                        deny: HashSet::new(),
                        budget: None,
                        corrupt: false,
                        offline: false,
                    }
                })
                .collect();
            Self { nodes, now: Instant::now(), served: HashMap::new() }
        }

        fn run(&mut self, origin: usize, actions: Vec<FileAction>) {
            let mut queue: VecDeque<(usize, FileAction)> = actions.into_iter().map(|a| (origin, a)).collect();
            let now = self.now;
            while let Some((from, action)) = queue.pop_front() {
                let from_peer = self.nodes[from].peer;
                match action {
                    FileAction::Event(event) => self.nodes[from].events.push(event),
                    FileAction::Publish { topic, message } => {
                        for to in 0..self.nodes.len() {
                            if to != from && !self.nodes[to].offline {
                                let out = self.nodes[to].engine.on_gossip(from_peer, &topic, message.clone(), now);
                                queue.extend(out.into_iter().map(|a| (to, a)));
                            }
                        }
                    }
                    FileAction::Request { peer, request } => {
                        let Some(to) = self.nodes.iter().position(|n| n.peer == peer) else {
                            let out = self.nodes[from].engine.on_failure(peer, request, now);
                            queue.extend(out.into_iter().map(|a| (from, a)));
                            continue;
                        };
                        if self.nodes[to].offline {
                            let out = self.nodes[from].engine.on_failure(peer, request, now);
                            queue.extend(out.into_iter().map(|a| (from, a)));
                            continue;
                        }
                        let target = &mut self.nodes[to];
                        let deny = target.deny.clone();
                        let (mut response, out) = target.engine.handle_request(from_peer, request.clone(), &|_| !deny.contains(&from_peer), now);
                        if let FileResponse::Piece(bytes) = &mut response {
                            if target.corrupt {
                                bytes[0] ^= 0xff;
                            }
                            match target.budget.as_mut() {
                                Some(0) => response = FileResponse::Busy,
                                Some(left) => *left -= 1,
                                None => {}
                            }
                            if matches!(response, FileResponse::Piece(_)) {
                                *self.served.entry((to, from)).or_default() += 1;
                            }
                        }
                        queue.extend(out.into_iter().map(|a| (to, a)));
                        let out = self.nodes[from].engine.on_response(peer, request, response, now);
                        queue.extend(out.into_iter().map(|a| (from, a)));
                    }
                    FileAction::Provide(_) | FileAction::FindProviders(_) => {}
                }
            }
        }

        /// Avança o relógio e dá tick em todos até `done` ou desistir
        fn settle(&mut self, done: impl Fn(&Net) -> bool) {
            for _ in 0..40 {
                if done(self) {
                    return;
                }
                self.now += Duration::from_secs(6);
                for i in 0..self.nodes.len() {
                    if !self.nodes[i].offline {
                        let now = self.now;
                        let actions = self.nodes[i].engine.tick(now);
                        self.run(i, actions);
                    }
                }
            }
            assert!(done(self), "não terminou");
        }

        fn share(&mut self, from: usize, pieces: u32, key: Option<FileKey>, target: ShareTarget) -> (Cid, Vec<u8>) {
            let dir = temp_dir("src");
            let path = dir.join("filme.mkv");
            let data: Vec<u8> = (0..(pieces as usize * PIECE_SIZE as usize - 100)).map(|i| (i * 31 % 256) as u8).collect();
            std::fs::write(&path, &data).unwrap();
            let manifest = Manifest::from_file(&path, &self.nodes[from].identity, key.as_ref(), 0).unwrap();
            let (cid, actions) = self.nodes[from].engine.share(manifest, path, key, target, "Alice");
            self.run(from, actions);
            (cid, data)
        }

        fn get(&mut self, who: usize, cid: &Cid) {
            let now = self.now;
            let actions = self.nodes[who].engine.get(&cid.short(), now).unwrap();
            self.run(who, actions);
        }

        fn completed(&self, who: usize) -> Option<PathBuf> {
            self.nodes[who].events.iter().find_map(|e| match e {
                FileEvent::Completed { path, .. } => Some(path.clone()),
                _ => None,
            })
        }
    }

    #[test]
    fn test_offer_reaches_room_and_download_completes() {
        let mut net = Net::new(2);
        let (cid, data) = net.share(0, 5, None, ShareTarget::Topic(TOPIC.into()));
        assert!(matches!(&net.nodes[1].events[0], FileEvent::Offered { name, direct: false, .. } if name == "filme.mkv"));
        assert_eq!(net.nodes[1].engine.list(net.now)[0].state, FileState::Offered);

        net.get(1, &cid);
        net.settle(|n| n.completed(1).is_some());
        assert_eq!(std::fs::read(net.completed(1).unwrap()).unwrap(), data);
        assert_eq!(net.nodes[1].engine.list(net.now)[0].state, FileState::Seeding);
    }

    /// Quem baixou passa a servir: com quem publicou fora do ar, o próximo baixa do anterior
    #[test]
    fn test_downloader_seeds_after_publisher_leaves() {
        let mut net = Net::new(3);
        let (cid, data) = net.share(0, 6, None, ShareTarget::Topic(TOPIC.into()));
        net.get(1, &cid);
        net.settle(|n| n.completed(1).is_some());
        net.nodes[0].offline = true;

        net.get(2, &cid);
        net.settle(|n| n.completed(2).is_some());
        assert_eq!(std::fs::read(net.completed(2).unwrap()).unwrap(), data);
        assert_eq!(net.served.get(&(1, 2)), Some(&6), "todos os pedaços vieram de quem baixou antes");
    }

    /// Efeito torrent: quem publicou só envia uma cópia; os dois que baixam juntos trocam o resto
    #[test]
    fn test_simultaneous_downloaders_exchange_pieces() {
        let mut net = Net::new(3);
        let pieces = 12;
        net.nodes[0].budget = Some(pieces);
        let (cid, data) = net.share(0, pieces, None, ShareTarget::Topic(TOPIC.into()));
        net.get(1, &cid);
        net.get(2, &cid);
        net.settle(|n| n.completed(1).is_some() && n.completed(2).is_some());
        assert_eq!(std::fs::read(net.completed(1).unwrap()).unwrap(), data);
        assert_eq!(std::fs::read(net.completed(2).unwrap()).unwrap(), data);
        let from_publisher = net.served.get(&(0, 1)).unwrap_or(&0) + net.served.get(&(0, 2)).unwrap_or(&0);
        let exchanged = net.served.get(&(1, 2)).unwrap_or(&0) + net.served.get(&(2, 1)).unwrap_or(&0);
        assert!(from_publisher <= pieces, "quem publicou mandou {} pedaços", from_publisher);
        assert!(exchanged >= pieces, "trocados entre os dois: {}", exchanged);
    }

    /// Par que manda pedaço adulterado é descartado; o download termina com quem é honesto
    #[test]
    fn test_corrupt_peer_is_ignored() {
        let mut net = Net::new(3);
        net.nodes[2].corrupt = true;
        let (cid, data) = net.share(0, 4, None, ShareTarget::Topic(TOPIC.into()));
        // O corrupto finge ter tudo
        let fake_offer = SwarmMessage::Offer(OfferInfo {
            manifest: cid,
            name: "filme.mkv".into(),
            size: data.len() as u64,
            publisher: String::new(),
            publisher_name: "Mallory".into(),
            key: None,
        });
        net.run(2, vec![FileAction::Publish { topic: TOPIC.into(), message: fake_offer }]);
        // E tem o arquivo de verdade, para responder pedidos (adulterando os pedaços)
        net.get(2, &cid);
        net.settle(|n| n.completed(2).is_some());

        net.get(1, &cid);
        net.settle(|n| n.completed(1).is_some());
        assert_eq!(std::fs::read(net.completed(1).unwrap()).unwrap(), data);
        assert!(!net.nodes[1].events.iter().any(|e| matches!(e, FileEvent::Failed { .. })));
    }

    /// Arquivo de servidor: quem não é membro não recebe nem o manifesto
    #[test]
    fn test_server_file_only_for_members() {
        let mut net = Net::new(3);
        let outsider = net.nodes[2].peer;
        net.nodes[0].deny.insert(outsider);
        let (cid, data) = net.share(0, 3, Some(FileKey::generate()), ShareTarget::Topic("p2p-anarchord/server/x/channel/geral".into()));
        net.get(1, &cid);
        net.settle(|n| n.completed(1).is_some());
        assert_eq!(std::fs::read(net.completed(1).unwrap()).unwrap(), data);

        net.nodes[1].deny.insert(outsider);
        net.get(2, &cid);
        for _ in 0..5 {
            net.now += Duration::from_secs(6);
            let actions = net.nodes[2].engine.tick(net.now);
            net.run(2, actions);
        }
        assert!(net.completed(2).is_none());
        assert_eq!(net.served.get(&(0, 2)).or(net.served.get(&(1, 2))), None);
    }

    #[test]
    fn test_direct_offer_only_reaches_target() {
        let mut net = Net::new(3);
        let bob = net.nodes[1].peer;
        let (cid, data) = net.share(0, 2, None, ShareTarget::Peer(bob));
        assert!(matches!(&net.nodes[1].events[0], FileEvent::Offered { direct: true, .. }));
        assert!(net.nodes[2].events.is_empty(), "ninguém mais vê a oferta");
        net.get(1, &cid);
        net.settle(|n| n.completed(1).is_some());
        assert_eq!(std::fs::read(net.completed(1).unwrap()).unwrap(), data);

        // Mesmo sabendo o CID, outro par não consegue pedir
        let (carol, now) = (net.nodes[2].peer, net.now);
        let (response, _) = net.nodes[0].engine.handle_request(carol, FileRequest::GetManifest { cid }, &|_| true, now);
        assert_eq!(response, FileResponse::NotFound);
    }

    #[test]
    fn test_resume_unfinished_download() {
        use sha2::{Digest, Sha512};

        let mut net = Net::new(2);
        // Alice tem orçamento para servir apenas 2 pedaços de um total de 4 (exatamente 50%)
        net.nodes[0].budget = Some(2);
        let (cid, data) = net.share(0, 4, None, ShareTarget::Topic(TOPIC.into()));
        let expected_sha512 = Sha512::digest(&data);

        // Bob inicia o download e atinge os 50%
        net.get(1, &cid);
        net.settle(|n| n.nodes[1].engine.list(n.now)[0].state != FileState::Offered);
        assert!(net.completed(1).is_none());
        assert!(matches!(net.nodes[1].engine.list(net.now)[0].state, FileState::Downloading { progress, .. } if (progress - 0.5).abs() < 0.01), "deve ter baixado exatamente 50% antes da interrupção");

        // Bob encerra o processo e reinicia o motor com as mesmas pastas de dados
        let partial = net.nodes[1].engine.partial_dir.clone();
        let downloads = net.nodes[1].engine.download_dir.clone();
        net.nodes[1].engine = FileEngine::new(partial, downloads);
        let now = net.now;
        let actions = net.nodes[1].engine.resume(now);

        // Issue #68: resume deve emitir Started, Progress inicial herdado (exatamente 50% = 0.5) e Want no tópico dedicado
        assert!(actions.iter().any(|a| matches!(a, FileAction::Event(FileEvent::Started { .. }))));
        assert!(actions.iter().any(|a| matches!(a, FileAction::Event(FileEvent::Progress { progress, .. }) if (*progress - 0.5).abs() < 0.01)));
        assert!(actions.iter().any(|a| matches!(a, FileAction::Publish { topic, message: SwarmMessage::Want { manifest } } if *topic == file_swarm_topic(&cid) && *manifest == cid)));

        // Alice volta a servir sem restrição de orçamento para Bob concluir o download
        net.nodes[0].budget = None;
        net.run(1, actions);
        net.settle(|n| n.completed(1).is_some());

        // Validação estrita do arquivo usando SHA-512 antes e depois da transferência
        let completed_path = net.completed(1).unwrap();
        let actual_data = std::fs::read(&completed_path).unwrap();
        let actual_sha512 = Sha512::digest(&actual_data);
        assert_eq!(expected_sha512, actual_sha512, "SHA-512 do arquivo retomado e concluído deve ser idêntico ao original");
    }

    /// Issue #66: O tráfego do enxame (Have/Want) circula exclusivamente no tópico dedicado
    /// `anarchord/file/<cid>`, mantendo o tópico da sala restrito apenas ao anúncio inicial (Offer).
    #[test]
    fn test_swarm_traffic_is_isolated_to_dedicated_file_topic() {
        let mut net = Net::new(2);
        let (cid, _data) = net.share(0, 3, None, ShareTarget::Topic(TOPIC.into()));

        // Na oferta inicial, o anúncio vai para a sala
        assert_eq!(net.nodes[1].events[0], FileEvent::Offered {
            cid,
            name: "filme.mkv".into(),
            size: 3 * PIECE_SIZE as u64 - 100,
            from: "Alice".into(),
            direct: false,
        });

        // Quando o nó 1 pede o arquivo, a ação Publish gerada DEVE ser para anarchord/file/<cid>, NÃO para TOPIC
        let now = net.now;
        let actions = net.nodes[1].engine.get(&cid.short(), now).unwrap();
        let want_action = actions.iter().find(|a| matches!(a, FileAction::Publish { message: SwarmMessage::Want { .. }, .. })).unwrap();
        if let FileAction::Publish { topic, .. } = want_action {
            assert_eq!(topic, &file_swarm_topic(&cid));
            assert_ne!(topic, TOPIC);
        }

        // Tópicos ativos no motor do nó 1 devem conter o tópico dedicado
        assert!(net.nodes[1].engine.swarm_topics().contains(&file_swarm_topic(&cid)));
    }

    #[test]
    fn test_find_dismiss_and_unshare() {
        let mut net = Net::new(2);
        let (cid, _) = net.share(0, 1, None, ShareTarget::Topic(TOPIC.into()));
        let engine = &mut net.nodes[1].engine;
        assert!(engine.get("zzzz", Instant::now()).is_err());
        assert_eq!(engine.dismiss("FILME.MKV").unwrap(), "filme.mkv");
        assert!(engine.list(Instant::now()).is_empty());
        assert_eq!(net.nodes[0].engine.unshare(&cid.short()).unwrap(), "filme.mkv");
        assert!(net.nodes[0].engine.list(Instant::now()).is_empty());
    }

    /// Issue #64: Quando Bob baixa um arquivo da Alice (e passa a semear), se Bob deletar o arquivo
    /// do disco (notificado por `on_fs_change`) ou executar `/unshare <id>`, a oferta original da Alice
    /// continua preservada como `Offered` e Bob pode baixar novamente da Alice com `/get <id>`.
    #[test]
    fn test_redownload_after_deleting_file_on_disk_or_unsharing() {
        let mut net = Net::new(2);
        let (cid, data) = net.share(0, 3, None, ShareTarget::Topic(TOPIC.into()));

        // 1) Bob baixa o arquivo da Alice pela 1ª vez -> vira Seeding
        net.get(1, &cid);
        net.settle(|n| n.completed(1).is_some());
        let first_path = net.completed(1).unwrap();
        assert_eq!(std::fs::read(&first_path).unwrap(), data);
        assert_eq!(net.nodes[1].engine.list(net.now)[0].state, FileState::Seeding);

        // 2) Bob deleta o arquivo no disco e o watcher do SO dispara `on_fs_change`:
        // o estado em Bob muda imediatamente para `Offered` (emite `LocalFileRemoved` + `Have` zerado)
        std::fs::remove_file(&first_path).unwrap();
        let fs_actions = net.nodes[1].engine.on_fs_change();
        assert!(
            fs_actions.iter().any(|a| matches!(a, FileAction::Event(FileEvent::LocalFileRemoved { name, .. }) if name == "filme.mkv")),
            "deveria emitir LocalFileRemoved ao detectar remoção no disco"
        );
        net.run(1, fs_actions);
        assert_eq!(net.nodes[1].engine.list(net.now)[0].state, FileState::Offered);

        // 3) Como Alice continua compartilhando, Bob pode fazer `/get` de novo e baixar o arquivo completo!
        net.nodes[1].events.clear();
        net.get(1, &cid);
        net.settle(|n| n.completed(1).is_some());
        let second_path = net.completed(1).unwrap();
        assert_eq!(std::fs::read(&second_path).unwrap(), data);
        assert_eq!(net.nodes[1].engine.list(net.now)[0].state, FileState::Seeding);

        // 4) E se Bob rodar `/unshare <id>`, ele para de semear mas preserva a oferta da Alice (`Offered`),
        // podendo baixar uma 3ª vez quando quiser!
        assert_eq!(net.nodes[1].engine.unshare(&cid.short()).unwrap(), "filme.mkv");
        assert_eq!(net.nodes[1].engine.list(net.now)[0].state, FileState::Offered);
        net.nodes[1].events.clear();
        net.get(1, &cid);
        net.settle(|n| n.completed(1).is_some());
        assert_eq!(std::fs::read(net.completed(1).unwrap()).unwrap(), data);
    }

    /// Issue #67: Quando o publicador descompartilha antes de Bob baixar, Bob não deve travar em 0%;
    /// deve receber FileEvent::Failed após o timeout e o estado deve retornar para Offered.
    #[test]
    fn test_download_fails_when_publisher_unshares_before_get() {
        let mut net = Net::new(2);
        let (cid, _) = net.share(0, 3, None, ShareTarget::Topic(TOPIC.into()));

        // Alice descompartilha antes de Bob iniciar o download
        assert_eq!(net.nodes[0].engine.unshare(&cid.short()).unwrap(), "filme.mkv");

        // Bob tenta baixar o arquivo oferecido
        net.get(1, &cid);

        // Bob avança o tempo; Alice responde NotFound e o timeout de busca de manifesto é atingido
        net.settle(|n| n.nodes[1].events.iter().any(|e| matches!(e, FileEvent::Failed { .. })));

        let failed_event = net.nodes[1].events.iter().find(|e| matches!(e, FileEvent::Failed { .. })).unwrap();
        if let FileEvent::Failed { cid: failed_cid, name, reason } = failed_event {
            assert_eq!(*failed_cid, cid);
            assert_eq!(name, "filme.mkv");
            assert!(reason.contains("nenhum par disponível"), "motivo esperado: {}", reason);
        }

        // Estado do arquivo deve retornar para Offered e não mais Downloading
        assert_eq!(net.nodes[1].engine.list(net.now)[0].state, FileState::Offered);
    }

    /// Issue #67: No envio direto (Audience::Peer), se o par responde NotFound, a falha deve ser
    /// imediata sem esperar timeout longo.
    #[test]
    fn test_direct_send_fails_immediately_on_not_found() {
        let mut net = Net::new(2);
        let bob = net.nodes[1].peer;
        let (cid, _) = net.share(0, 2, None, ShareTarget::Peer(bob));

        // Alice descompartilha o envio direto
        assert_eq!(net.nodes[0].engine.unshare(&cid.short()).unwrap(), "filme.mkv");

        // Bob tenta baixar
        net.get(1, &cid);

        // A resposta NotFound no envio direto gera FileEvent::Failed imediatamente na mesma rodada
        assert!(net.nodes[1].events.iter().any(|e| matches!(e, FileEvent::Failed { .. })));
        assert_eq!(net.nodes[1].engine.list(net.now)[0].state, FileState::Offered);
    }

    /// Issue #67: Se todos os pares com os pedaços restantes saírem no meio do download,
    /// o download deve falhar com FileEvent::Failed por timeout de pedaços e resetar para Offered.
    #[test]
    fn test_download_fails_when_all_seeders_disconnect_mid_download() {
        let mut net = Net::new(2);
        // Alice tem orçamento para enviar apenas o manifesto e 1 pedaço de 4
        net.nodes[0].budget = Some(1);
        let (cid, _) = net.share(0, 4, None, ShareTarget::Topic(TOPIC.into()));

        net.get(1, &cid);
        // Bob obtém o primeiro pedaço
        net.settle(|n| n.nodes[1].engine.list(n.now)[0].state != FileState::Offered);

        // Alice desconecta
        net.nodes[0].offline = true;

        // Bob aguarda o timeout de pedaços indisponíveis (PIECE_DISCOVERY_TIMEOUT = 30s)
        net.settle(|n| n.nodes[1].events.iter().any(|e| matches!(e, FileEvent::Failed { .. })));

        let failed_event = net.nodes[1].events.iter().find(|e| matches!(e, FileEvent::Failed { .. })).unwrap();
        if let FileEvent::Failed { cid: failed_cid, name, reason } = failed_event {
            assert_eq!(*failed_cid, cid);
            assert_eq!(name, "filme.mkv");
            assert!(reason.contains("pedaços restantes estão indisponíveis"), "motivo esperado: {}", reason);
        }

        assert_eq!(net.nodes[1].engine.list(net.now)[0].state, FileState::Offered);
    }
}
