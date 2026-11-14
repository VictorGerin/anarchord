//! Rede: conexões, identificação, descoberta (mDNS, DHT, trackers), NAT e despacho das
//! mensagens recebidas nos tópicos.

use super::{CoreEvent, NetworkEvent, Runtime};
use crate::api::pubkey_hex_from_peer_id;
use crate::bootstrap::OPENTRACKER_SERVERS;
use crate::community::{self, server_dht_key};
use crate::files as swarm_files;
use crate::node::{parse_agent_info, DHT_DISCOVERY_NAMESPACE};
use crate::protocol::AppBehaviourEvent;
use crate::tracker::{make_info_hash, TorrentTrackerClient};
use crate::wire::{self, Incoming};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, Multiaddr, PeerId};
use std::collections::HashMap;

/// Intervalo mínimo entre mensagens de erro de hole punching repetidas para o mesmo par (Issue #40)
const DCUTR_FAILURE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(600);

impl Runtime {
    /// Trackers em uso: os informados e, com `public_defaults`, os públicos embutidos
    fn trackers(&self) -> Vec<String> {
        let mut trackers = self.config.trackers.clone();
        if self.config.public_defaults {
            trackers.extend(OPENTRACKER_SERVERS.iter().map(|t| t.to_string()));
        }
        trackers
    }

    /// Bootstrap da DHT e trackers BitTorrent (se a descoberta estiver ligada)
    pub(super) fn start_discovery(&mut self) {
        if !self.config.discovery {
            return;
        }
        let mut nodes = 0;
        if self.config.public_defaults {
            nodes += self.node.bootstrap_dht();
        }
        if !self.config.bootstrap.is_empty() {
            let bootstrap = self.config.bootstrap.clone();
            nodes += self.node.bootstrap_with(&bootstrap);
        }
        self.emit(CoreEvent::Network(NetworkEvent::DhtBootstrap { nodes }));

        let trackers = self.trackers();
        if trackers.is_empty() {
            return;
        }
        // Trackers em segundo plano: TCP e QUIC usam a mesma porta, então a porta anunciada vale para os dois
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        self.tracker_rx = Some(rx);
        let port = self.node.listen_port;
        let bt_peer_id = self.bt_peer_id();
        let events = self.events.clone();
        let has_peers = self.has_anarchord_connected.clone();
        let is_lab = self.config.lab;
        let base_interval = std::time::Duration::from_secs(if is_lab { 3 } else { 15 });
        let max_interval = std::time::Duration::from_secs(if is_lab { 30 } else { 600 });
        // Thread comum, não `spawn_blocking`: o laço não termina, e o runtime do tokio espera
        // as tarefas bloqueantes ao ser descartado (o app travava ao sair)
        std::thread::spawn(move || {
            let info_hash = make_info_hash(DHT_DISCOVERY_NAMESPACE);
            let mut seen_peers = std::collections::HashSet::<std::net::SocketAddr>::new();
            let mut announced_trackers = std::collections::HashSet::<String>::new();

            loop {
                let mut reported_interval: Option<u32> = None;
                for tracker in &trackers {
                    let first = !announced_trackers.contains(tracker);
                    let event = if first { 2 } else { 0 }; // 2 = started, 0 = none
                    if let Ok(resp) = TorrentTrackerClient::discover(tracker, &info_hash, &bt_peer_id, port, event) {
                        announced_trackers.insert(tracker.clone());
                        if resp.interval > 0 {
                            reported_interval = Some(reported_interval.map_or(resp.interval, |cur| cur.max(resp.interval)));
                        }
                        for peer in resp.peers {
                            // Não processa a si mesmo caso o tracker devolva
                            if peer.port() == port && (peer.ip().is_loopback() || peer.ip().is_unspecified()) {
                                continue;
                            }
                            if seen_peers.insert(peer) {
                                let _ = events.send(CoreEvent::Network(NetworkEvent::TrackerPeer(peer.to_string())));
                            }
                            let _ = tx.send(format!("/ip4/{}/tcp/{}", peer.ip(), peer.port()));
                            if tx.send(format!("/ip4/{}/udp/{}/quic-v1", peer.ip(), peer.port())).is_err() {
                                return;
                            }
                        }
                        break;
                    }
                }

                // Cálculo do próximo intervalo de consulta
                let mut sleep_dur = if has_peers.load(std::sync::atomic::Ordering::Relaxed) {
                    max_interval
                } else {
                    base_interval
                };
                if let Some(tracker_interval_secs) = reported_interval {
                    sleep_dur = sleep_dur.max(std::time::Duration::from_secs(tracker_interval_secs as u64));
                }

                std::thread::sleep(sleep_dur);
            }
        });
    }

    /// Desanuncia o nó dos trackers (event = stopped) em paralelo
    pub(super) fn stop_discovery(&mut self) {
        if !self.config.discovery {
            return;
        }
        let trackers = self.trackers();
        if trackers.is_empty() {
            return;
        }
        let info_hash = make_info_hash(DHT_DISCOVERY_NAMESPACE);
        let bt_peer_id = self.bt_peer_id();
        let port = self.node.listen_port;

        // Dispara o desanúncio em paralelo em threads para não travar sequencialmente
        let mut handles = Vec::new();
        for tracker in trackers {
            let h = std::thread::spawn(move || {
                let _ = TorrentTrackerClient::announce_stopped(&tracker, &info_hash, &bt_peer_id, port);
            });
            handles.push(h);
        }
        for h in handles {
            let _ = h.join();
        }
    }

    fn bt_peer_id(&self) -> [u8; 20] {
        let bytes = self.node.peer_id.to_bytes();
        let mut id = [0u8; 20];
        let len = bytes.len().min(20);
        id[..len].copy_from_slice(&bytes[..len]);
        id
    }


    pub(super) fn dial_discovered(&mut self, address: String) {
        if let Ok(multiaddr) = address.parse::<Multiaddr>() {
            let now = std::time::Instant::now();
            let redial_after = self.discovery.redial_after;
            self.tracker_dial_attempts.retain(|_, at| now.duration_since(*at) < redial_after);

            // Não redisca quem já está com conexão aberta nem quem tentou recentemente
            if !self.dialed_open.contains(&multiaddr) && !self.tracker_dial_attempts.contains_key(&multiaddr) {
                if self.node.swarm.dial(multiaddr.clone()).is_ok() {
                    self.tracker_dial_attempts.insert(multiaddr, now);
                }
            }
        }
    }

    pub(super) fn handle_swarm_event(&mut self, event: SwarmEvent<AppBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => self.emit(CoreEvent::Network(NetworkEvent::Listening(address.to_string()))),
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                let address = endpoint.get_remote_address().clone();
                let peer_pk = pubkey_hex_from_peer_id(&peer_id);
                let is_friend = peer_pk.as_deref().is_some_and(|pk| {
                    self.identity
                        .get_friends()
                        .iter()
                        .any(|f| f.public_key.eq_ignore_ascii_case(pk))
                });
                let verdict = self.dm.firewall.check_incoming_connection(
                    &peer_id,
                    peer_pk.as_deref(),
                    &address,
                    is_friend,
                    &self.dm.node_config.firewall,
                    super::now_secs(),
                );
                if verdict != crate::firewall::FirewallVerdict::Allowed {
                    tracing::debug!("Conexão recusada pelo NodeFirewall para {} ({}): {:?}", peer_id, address, verdict);
                    self.node.swarm.behaviour_mut().gossipsub.blacklist_peer(&peer_id);
                    let _ = self.node.swarm.disconnect_peer_id(peer_id);
                    return;
                }
                // Do lado de quem recebe, o endereço de uma conexão relayada é só /p2p/<id>
                let relayed = endpoint.is_relayed();
                // Guarda a primeira conexão e a primeira direta (ex.: depois do hole punching). Só
                // avisa a interface se o par já foi identificado como Anarchord; senão o aviso sai
                // no Identify. Conexões com nós do IPFS (DHT) nunca viram evento
                let first = self.connected_peers.insert(peer_id);
                let upgrade = !relayed && self.links.get(&peer_id).is_some_and(|(_, r)| *r);
                if first || upgrade {
                    self.links.insert(peer_id, (address.to_string(), relayed));
                    if self.identified.contains(&peer_id) {
                        self.emit(CoreEvent::Network(NetworkEvent::Connected { peer_id: peer_id.to_string(), address: address.to_string(), relayed }));
                    }
                }
                if let libp2p::core::ConnectedPoint::Dialer { address, .. } = &endpoint {
                    self.dialed_open.insert(address.clone());
                }
                // A maioria das conexões é com nós do IPFS; os pares Anarchord aparecem quando o Identify confirma
                tracing::debug!("Conexão P2P com {} via {:?}", peer_id, endpoint.get_remote_address());
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, num_established, endpoint, .. } => {
                if let libp2p::core::ConnectedPoint::Dialer { address, .. } = &endpoint {
                    self.dialed_open.remove(address);
                }
                if num_established == 0 {
                    self.dm.firewall.on_connection_closed(&peer_id);
                    self.connected_peers.remove(&peer_id);
                    self.links.remove(&peer_id);
                    self.discovery.addresses.remove(&peer_id);
                    self.identified.remove(&peer_id);
                    self.peer_topics.remove(&peer_id);
                    self.relay_manager.remove_peer(&peer_id);
                    let has_peers = self.anarchord_peers().next().is_some();
                    self.has_anarchord_connected.store(has_peers, std::sync::atomic::Ordering::Relaxed);
                    if let Some((nick, pubkey)) = self.peer_metadata.get(&peer_id).cloned() {
                        self.emit(CoreEvent::PeerLeft { peer_id: peer_id.to_string(), nick });
                        let cause = cause.map(|c| c.to_string()).unwrap_or_default();
                        self.emit(CoreEvent::Network(NetworkEvent::ConnectionClosed { peer_id: peer_id.to_string(), cause }));
                        self.publish_channel_members();
                        self.friend_presence(&pubkey, false);
                        self.on_peer_disconnected_mls(&pubkey);
                    }
                }
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Identify(libp2p::identify::Event::Received { peer_id, info, .. })) => {
                // Registra os endereços de escuta no Swarm para permitir `dial(peer_id)` mesmo sem DHT (--no-discovery)
                for addr in &info.listen_addrs {
                    self.node.swarm.add_peer_address(peer_id, addr.clone());
                }
                // Alimenta a tabela de roteamento da DHT com os endereços de quem fala Kademlia
                if info.protocols.contains(&libp2p::kad::PROTOCOL_NAME) {
                    for addr in &info.listen_addrs {
                        self.node.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                    }
                }
                // Pares que oferecem Circuit Relay v2 (HOP) viram candidatos a reserva
                if info.protocols.contains(&libp2p::relay::HOP_PROTOCOL_NAME) {
                    self.relay_manager.add_candidate(peer_id, &info.listen_addrs);
                    self.request_relay_reservations();
                }
                if let Some(agent_info) = parse_agent_info(&info.agent_version) {
                    let (nick, pubkey, peer_caps) = (agent_info.nick, agent_info.pubkey, agent_info.capabilities);
                    self.peer_protocols.insert(peer_id, peer_caps.clone());

                    // Verifica compatibilidade de versão (política N e N-1 + proteção contra downgrade)
                    if self.local_capabilities.negotiate_version(&peer_caps).is_none() {
                        if self.warned_incompatible.insert(peer_id) {
                            self.emit(CoreEvent::PeerIncompatible {
                                peer_id: peer_id.to_string(),
                                nick: nick.clone(),
                                pubkey: pubkey.clone(),
                                peer_version: peer_caps.version_range_label(),
                                supported_versions: self.local_capabilities.version_range_label(),
                            });
                        }
                    }

                    // O Identify se repete a cada conexão: só avisa na primeira identificação ou se o nick mudou
                    let changed = self.peer_metadata.insert(peer_id, (nick.clone(), pubkey.clone())) != Some((nick.clone(), pubkey.clone()));
                    let first = self.identified.insert(peer_id);
                    // Endereços para a troca de pares; par novo ou com endereços novos (ex.: circuito
                    // no relay) é contado aos outros
                    let previous = self.discovery.addresses.insert(peer_id, info.listen_addrs.clone());
                    if first || previous.as_ref() != Some(&info.listen_addrs) {
                        self.discovery.peers_changed = true;
                    }
                    if first {
                        if let Some((address, relayed)) = self.links.get(&peer_id).cloned() {
                            self.emit(CoreEvent::Network(NetworkEvent::Connected { peer_id: peer_id.to_string(), address, relayed }));
                        }
                    }
                    if first || changed {
                        let friend_pubkey = pubkey.clone();
                        self.emit(CoreEvent::PeerIdentified { peer_id: peer_id.to_string(), nick, pubkey });
                        let has_peers = self.anarchord_peers().next().is_some();
                        self.has_anarchord_connected.store(has_peers, std::sync::atomic::Ordering::Relaxed);
                        self.publish_channel_members();
                        if first {
                            self.friend_presence(&friend_pubkey, true);
                            self.on_peer_identified_dm_and_mailbox(&friend_pubkey);
                        }
                    }
                }
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic })) => {
                self.peer_topics.entry(peer_id).or_default().insert(topic.clone());
                self.on_subscribed(peer_id, topic);
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic })) => {
                if let Some(set) = self.peer_topics.get_mut(&peer_id) {
                    set.remove(&topic);
                }
                if let Some(server_id) = community::parse_server_access_topic(topic.as_str()).map(str::to_string) {
                    self.on_access_topic_unsubscribed(&server_id, pubkey_hex_from_peer_id(&peer_id));
                }
                if topic == self.active.topic.hash() {
                    self.publish_channel_members();
                }
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            })) => self.on_gossip_message(propagation_source, message_id, message),
            SwarmEvent::Behaviour(AppBehaviourEvent::Mdns(libp2p::mdns::Event::Discovered(list))) => {
                // Um par anuncia vários endereços: disca uma vez por par, com todos eles,
                // e só se não houver conexão nem discagem em andamento
                let mut by_peer: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
                for (peer_id, multiaddr) in list {
                    if peer_id != self.node.peer_id && !self.connected_peers.contains(&peer_id) {
                        by_peer.entry(peer_id).or_default().push(multiaddr);
                    }
                }
                for (peer_id, addresses) in by_peer {
                    tracing::debug!("Par local descoberto via mDNS: {} ({} endereços)", peer_id, addresses.len());
                    let opts = DialOpts::peer_id(peer_id).addresses(addresses).condition(PeerCondition::DisconnectedAndNotDialing).build();
                    let _ = self.node.swarm.dial(opts);
                }
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Files(event)) => self.on_files_event(event),
            // Provedores achados na DHT: outros nós Anarchord, membros de servidor ou quem tem um arquivo
            SwarmEvent::Behaviour(AppBehaviourEvent::Kademlia(libp2p::kad::Event::OutboundQueryProgressed {
                result: libp2p::kad::QueryResult::GetProviders(Ok(libp2p::kad::GetProvidersOk::FoundProviders { key, providers })),
                ..
            })) => {
                let file = self.files.engine.downloading().find(|cid| swarm_files::dht_key(cid) == key).copied();
                if let Some(cid) = file {
                    let found: Vec<PeerId> = providers.iter().filter(|p| **p != self.node.peer_id).copied().collect();
                    let actions = self.files.engine.add_providers(&cid, found, std::time::Instant::now());
                    self.apply_file_actions(actions);
                }
                for provider in providers {
                    if provider != self.node.peer_id && !self.connected_peers.contains(&provider) {
                        let opts = DialOpts::peer_id(provider).condition(PeerCondition::DisconnectedAndNotDialing).build();
                        let _ = self.node.swarm.dial(opts);
                    }
                }
            }
            // Endereço externo confirmado: (re)anuncia na DHT para o registro carregar esse endereço
            SwarmEvent::ExternalAddrConfirmed { address } => {
                self.emit(CoreEvent::Network(NetworkEvent::ExternalAddress(address.to_string())));
                self.reannounce_dht();
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Autonat(libp2p::autonat::Event::StatusChanged { new, .. })) => match new {
                libp2p::autonat::NatStatus::Private => {
                    self.emit(CoreEvent::Network(NetworkEvent::BehindNat));
                    self.relay_manager.set_behind_nat(true);
                    self.on_autonat_unreachable();
                    self.request_relay_reservations();
                }
                libp2p::autonat::NatStatus::Public(addr) => {
                    tracing::info!("AutoNAT: nó publicamente acessível em {}", addr);
                    self.relay_manager.set_behind_nat(false);
                }
                libp2p::autonat::NatStatus::Unknown => {}
            },
            // Sondagem em que o servidor não conseguiu discar de volta. Já atrás de NAT, o status não
            // muda (não há `StatusChanged`), então é por aqui que se descobre que o UPnP não valeu
            SwarmEvent::Behaviour(AppBehaviourEvent::Autonat(libp2p::autonat::Event::OutboundProbe(
                libp2p::autonat::OutboundProbeEvent::Error {
                    error: libp2p::autonat::OutboundProbeError::Response(libp2p::autonat::ResponseError::DialError),
                    ..
                },
            ))) => self.on_autonat_unreachable(),
            SwarmEvent::Behaviour(AppBehaviourEvent::RelayClient(libp2p::relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                renewal,
                ..
            })) => {
                if !renewal {
                    self.emit(CoreEvent::Network(NetworkEvent::RelayReserved(relay_peer_id.to_string())));
                }
            }
            SwarmEvent::ListenerClosed { listener_id, reason, .. } => {
                if let Some(relay) = self.relay_manager.listener_closed(listener_id) {
                    tracing::info!("Reserva no relay {} encerrada: {:?}", relay, reason);
                    self.request_relay_reservations();
                }
            }
            SwarmEvent::Behaviour(AppBehaviourEvent::Dcutr(libp2p::dcutr::Event { remote_peer_id, result })) => match result {
                Ok(_) => self.on_dcutr_success(remote_peer_id),
                Err(e) => self.on_dcutr_failure(remote_peer_id, &e.to_string()),
            },
            _ => {}
        }
    }

    /// Avalia um pacote/evento no `NodeFirewall` unificado e, se resultar em novo bloqueio,
    /// emite `CoreEvent::PeerBlocked` e adiciona o par à blacklist do Gossipsub.
    pub(super) fn check_node_firewall(
        &mut self,
        peer_id_opt: Option<PeerId>,
        pubkey: &str,
        category: crate::firewall::FirewallCategory,
        now: u64,
    ) -> crate::firewall::FirewallVerdict {
        let clean_pk = pubkey.trim().to_lowercase();
        let is_friend = self
            .identity
            .get_friends()
            .iter()
            .any(|f| f.public_key.eq_ignore_ascii_case(&clean_pk))
            || self.servers.list().any(|srv| srv.chain().state().protected.contains(&clean_pk))
            || self.active_room().is_some_and(|(_, _, room)| self.mls.members(&room).contains(&clean_pk));
        let verdict = self.dm.firewall.check_packet(
            &clean_pk,
            is_friend,
            category,
            &self.dm.node_config.firewall,
            now,
        );
        if let crate::firewall::FirewallVerdict::NewlyBlocked {
            ref reason,
            duration_secs,
            blocked_until,
            offense_level,
            send_courtesy,
        } = verdict
        {
            if let Some(pid) = peer_id_opt.or_else(|| crate::api::peer_id_from_pubkey_hex(&clean_pk)) {
                self.node.swarm.behaviour_mut().gossipsub.blacklist_peer(&pid);
            }
            let peer_name = self.friendly_name(&clean_pk);
            self.emit(CoreEvent::PeerBlocked {
                pubkey: clean_pk,
                peer_name,
                is_friend,
                reason: reason.clone(),
                duration_secs,
                blocked_until,
                offense_level,
                courtesy_sent: send_courtesy,
            });
        }
        verdict
    }

    fn report_gossip_validation(
        &mut self,
        message_id: &gossipsub::MessageId,
        propagation_source: &PeerId,
        acceptance: gossipsub::MessageAcceptance,
    ) {
        let _ = self
            .node
            .swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(message_id, propagation_source, acceptance);
    }

    /// Alguém entrou num tópico: presença, keyframe para quem começou a assistir, cadeia de servidor e mailbox offline
    fn on_subscribed(&mut self, peer_id: PeerId, topic: gossipsub::TopicHash) {
        if topic == self.active.topic.hash() {
            self.publish_channel_members();
        }
        let peer_pk = pubkey_hex_from_peer_id(&peer_id).unwrap_or_else(|| peer_id.to_string());
        if self.dm.firewall.is_blocked(&peer_pk, super::now_secs()) {
            return;
        }
        if topic.as_str() == crate::dm::MAILBOX_TOPIC {
            self.on_peer_subscribed_mailbox(peer_id);
        }
        if self.screen.my_stream.is_some() && topic == self.screen.publish_topic.hash() {
            self.screen.engine.request_keyframe();
        }
        // Entrou no tópico de pedidos de acesso: a inscrição já é o pedido (e pode ser um moderador
        // chegando, para quem está esperando)
        if let Some(server_id) = community::parse_server_access_topic(topic.as_str()).map(str::to_string) {
            self.on_access_topic_subscribed(&server_id, pubkey_hex_from_peer_id(&peer_id));
        }
        // Entrou no tópico de controle de um servidor que conhecemos: entrega a cadeia
        // (servidor privado: só para quem tem passaporte)
        if let Some(server_id) = community::parse_server_control_topic(topic.as_str()).map(str::to_string) {
            let recently = self.last_snapshot_reply.get(&server_id).is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(2));
            let peer_pubkey = pubkey_hex_from_peer_id(&peer_id);
            let allowed = self
                .servers
                .get(&server_id)
                .is_some_and(|s| !s.chain().state().closed || peer_pubkey.as_deref().is_some_and(|pk| s.is_allowed(pk, super::now_secs())));
            if !recently && allowed {
                let snapshot = self.servers.snapshot(&server_id);
                if !snapshot.is_empty() {
                    for message in &snapshot {
                        self.publish_server_message(&server_id, message);
                    }
                    self.last_snapshot_reply.insert(server_id.clone(), std::time::Instant::now());
                }
                if self.active.server_id() == Some(server_id.as_str()) {
                    self.announce_mls_group();
                }
            }
        }
    }

    /// Mensagem num tópico. O tipo vem no envelope; conteúdo de servidor chega cifrado com MLS
    /// (que também autentica quem enviou: quem não está no grupo não produz nada que decifre).
    fn on_gossip_message(
        &mut self,
        propagation_source: PeerId,
        message_id: gossipsub::MessageId,
        message: gossipsub::Message,
    ) {
        let topic = message.topic.as_str().to_string();
        let sender_peer_id = message.source.unwrap_or(propagation_source);
        let sender_pubkey = pubkey_hex_from_peer_id(&sender_peer_id)
            .unwrap_or_else(|| sender_peer_id.to_string())
            .to_lowercase();
        let now = super::now_secs();

        // Portão Estágio 1 (Pré-decodificação O(1)):
        // 1.1: Par já bloqueado no NodeFirewall -> descarta e não repassa na malha
        if self.dm.firewall.is_blocked(&sender_pubkey, now) {
            self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Reject);
            return;
        }
        // 1.2: Filtro estrito de tamanho máximo por tópico e discriminador Wire
        let max_bytes = crate::firewall::NodeFirewall::max_packet_bytes_for_topic(&topic, &message.data);
        if message.data.len() > max_bytes {
            tracing::debug!(
                "Pacote excedeu tamanho máximo do tópico {} ({} > {}B) de {}",
                topic,
                message.data.len(),
                max_bytes,
                sender_peer_id
            );
            self.check_node_firewall(
                Some(sender_peer_id),
                &sender_pubkey,
                crate::firewall::FirewallCategory::InvalidPacket,
                now,
            );
            self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Reject);
            return;
        }

        let src_str = message.source.as_ref().map(|p| p.to_string());
        // Tópico de controle ou de pedidos de acesso do servidor: as mesmas mensagens de servidor
        if let Some(server_id) = community::parse_server_control_topic(&topic).or_else(|| community::parse_server_access_topic(&topic)).map(str::to_string) {
            self.sniff_packet("RX", &topic, src_str, &message.data, None);
            let from = message.source.as_ref().and_then(pubkey_hex_from_peer_id);
            return match wire::decode_as(&message.data) {
                Ok(server_message) => {
                    if self.check_node_firewall(
                        Some(sender_peer_id),
                        &sender_pubkey,
                        crate::firewall::FirewallCategory::Control,
                        now,
                    ) == crate::firewall::FirewallVerdict::Allowed
                    {
                        self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Accept);
                        self.handle_server_network_message(&server_id, server_message, from.as_deref());
                        self.check_leader_changes();
                    } else {
                        self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Ignore);
                    }
                }
                Err(wire::WireError::Version(ver)) => {
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Ignore);
                    if let Some(peer_id) = message.source {
                        if self.warned_incompatible.insert(peer_id) {
                            let (nick, pubkey) = self
                                .peer_metadata
                                .get(&peer_id)
                                .cloned()
                                .unwrap_or_else(|| (peer_id.to_string(), from.unwrap_or_default()));
                            self.emit(CoreEvent::PeerIncompatible {
                                peer_id: peer_id.to_string(),
                                nick,
                                pubkey,
                                peer_version: format!("v{}", ver),
                                supported_versions: self.local_capabilities.version_range_label(),
                            });
                        }
                    }
                    tracing::debug!("Mensagem de servidor em versão incompatível (v{}) descartada", ver);
                }
                Err(e) => {
                    self.check_node_firewall(
                        Some(sender_peer_id),
                        &sender_pubkey,
                        crate::firewall::FirewallCategory::InvalidPacket,
                        now,
                    );
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Reject);
                    tracing::debug!("Mensagem de servidor ilegível: {}", e);
                }
            };
        }
        let raw_data = message.data.clone();
        let mut data = message.data;
        let mut mls_sender: Option<String> = None;
        if community::parse_server_content_topic(&topic).is_some() {
            let decrypted = match self.room_for_topic(&topic) {
                Some(room) => self.mls.decrypt(&room, &data),
                None => Err(community::e2ee::E2eeError::NotInGroup),
            };
            match decrypted {
                Ok(decrypted) => {
                    self.sniff_packet("RX", &topic, src_str, &raw_data, Some(&decrypted.plaintext));
                    data = decrypted.plaintext;
                    mls_sender = Some(decrypted.sender);
                }
                Err(e) => {
                    self.sniff_packet("RX", &topic, src_str, &raw_data, None);
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Ignore);
                    // Texto de canal que chegou sem que possamos ler: mostrado como está (cifrado)
                    if let Some((server, channel)) = community::parse_server_channel_topic(&topic) {
                        use base64::Engine as _;
                        const PREVIEW_BYTES: usize = 48;
                        let mut ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&raw_data[..raw_data.len().min(PREVIEW_BYTES)]);
                        if raw_data.len() > PREVIEW_BYTES {
                            ciphertext_b64.push('…');
                        }
                        self.emit(CoreEvent::EncryptedMessage {
                            server: server.to_string(),
                            channel: channel.to_string(),
                            epoch: community::e2ee::ServerGroups::peek_epoch(&raw_data),
                            size: raw_data.len(),
                            ciphertext_b64,
                            timestamp: super::now_millis(),
                        });
                    }
                    return tracing::debug!("Conteúdo de servidor não decifrado: {}", e);
                }
            }
        } else {
            self.sniff_packet("RX", &topic, src_str, &raw_data, None);
        }
        // Autor declarado no pacote precisa ser quem o MLS diz que enviou
        let sender_matches = |author: &str| mls_sender.as_deref().is_none_or(|s| s == author);
        let incoming = match wire::decode(&data) {
            Ok(incoming) => incoming,
            Err(wire::WireError::Version(ver)) => {
                self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Ignore);
                if let Some(peer_id) = message.source {
                    if self.warned_incompatible.insert(peer_id) {
                        let (nick, pubkey) = self
                            .peer_metadata
                            .get(&peer_id)
                            .cloned()
                            .unwrap_or_else(|| {
                                let pk = pubkey_hex_from_peer_id(&peer_id).unwrap_or_default();
                                let n = if pk.is_empty() {
                                    peer_id.to_string()
                                } else {
                                    community::short_id(&pk).to_string()
                                };
                                (n, pk)
                            });
                        self.emit(CoreEvent::PeerIncompatible {
                            peer_id: peer_id.to_string(),
                            nick,
                            pubkey,
                            peer_version: format!("v{}", ver),
                            supported_versions: self.local_capabilities.version_range_label(),
                        });
                    }
                }
                return tracing::debug!("Mensagem descartada em {} (versão v{} incompatível)", topic, ver);
            }
            Err(e) => {
                self.check_node_firewall(
                    Some(sender_peer_id),
                    &sender_pubkey,
                    crate::firewall::FirewallCategory::InvalidPacket,
                    now,
                );
                self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Reject);
                return tracing::debug!("Mensagem descartada em {}: {}", topic, e);
            }
        };
        let source = message.source;
        match incoming {
            Incoming::Chat(chat) => {
                let matches = sender_matches(&chat.author_pubkey);
                if !matches || !chat.verify(source.as_ref()) {
                    // Anti-Incriminação: pune exclusivamente o `sender_pubkey` autenticado pelo transporte (`message.source`)
                    self.check_node_firewall(
                        Some(sender_peer_id),
                        &sender_pubkey,
                        crate::firewall::FirewallCategory::InvalidPacket,
                        now,
                    );
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Reject);
                    return;
                }
                if self.check_node_firewall(
                    Some(sender_peer_id),
                    &sender_pubkey,
                    crate::firewall::FirewallCategory::Chat,
                    now,
                ) == crate::firewall::FirewallVerdict::Allowed
                {
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Accept);
                    self.on_chat_message(chat, source.as_ref(), matches);
                } else {
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Ignore);
                }
            }
            Incoming::Voice(packet) => {
                if sender_matches(&packet.sender_pubkey) {
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Accept);
                    self.on_voice_packet(packet);
                } else {
                    self.check_node_firewall(
                        Some(sender_peer_id),
                        &sender_pubkey,
                        crate::firewall::FirewallCategory::InvalidPacket,
                        now,
                    );
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Reject);
                }
            }
            Incoming::Swarm(swarm) => {
                // Oferta: quem publicou precisa ser o dono da pubkey anunciada
                let authentic = match &swarm {
                    swarm_files::SwarmMessage::Offer(offer) => {
                        offer.publisher != self.my_pubkey()
                            && sender_matches(&offer.publisher)
                            && source.as_ref().and_then(pubkey_hex_from_peer_id).as_deref() == Some(offer.publisher.as_str())
                    }
                    _ => true,
                };
                if !authentic {
                    self.check_node_firewall(
                        Some(sender_peer_id),
                        &sender_pubkey,
                        crate::firewall::FirewallCategory::InvalidPacket,
                        now,
                    );
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Reject);
                    return;
                }
                if self.check_node_firewall(
                    Some(sender_peer_id),
                    &sender_pubkey,
                    crate::firewall::FirewallCategory::Control,
                    now,
                ) == crate::firewall::FirewallVerdict::Allowed
                {
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Accept);
                    if let Some(source) = source {
                        let actions = self.files.engine.on_gossip(source, &topic, swarm, std::time::Instant::now());
                        self.apply_file_actions(actions);
                    }
                } else {
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Ignore);
                }
            }
            Incoming::ScreenFrame(packet) => {
                if sender_matches(&packet.sender_pubkey) {
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Accept);
                    self.on_screen_frame(packet);
                } else {
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Reject);
                }
            }
            Incoming::ScreenAnnounce(announce) => {
                if sender_matches(&announce.sender_pubkey)
                    && self.check_node_firewall(
                        Some(sender_peer_id),
                        &sender_pubkey,
                        crate::firewall::FirewallCategory::Control,
                        now,
                    ) == crate::firewall::FirewallVerdict::Allowed
                {
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Accept);
                    self.on_screen_announce(announce, &topic);
                } else {
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Ignore);
                }
            }
            Incoming::Peers(list) => {
                if self.check_node_firewall(
                    Some(sender_peer_id),
                    &sender_pubkey,
                    crate::firewall::FirewallCategory::Control,
                    now,
                ) == crate::firewall::FirewallVerdict::Allowed
                {
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Accept);
                    self.on_peer_list(source, list);
                } else {
                    self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Ignore);
                }
            }
            Incoming::Server(_) => {
                self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Reject);
                tracing::debug!("Mensagem de servidor fora do tópico de controle descartada");
            }
            Incoming::DirectMessage(dm_msg) => {
                self.on_dm_wire_message(dm_msg);
                let acceptance = if self.dm.firewall.is_blocked(&sender_pubkey, now) {
                    gossipsub::MessageAcceptance::Ignore
                } else {
                    gossipsub::MessageAcceptance::Accept
                };
                self.report_gossip_validation(&message_id, &propagation_source, acceptance);
            }
            Incoming::Mailbox(mb_msg) => {
                self.on_mailbox_message(mb_msg);
                let acceptance = if self.dm.firewall.is_blocked(&sender_pubkey, now) {
                    gossipsub::MessageAcceptance::Ignore
                } else {
                    gossipsub::MessageAcceptance::Accept
                };
                self.report_gossip_validation(&message_id, &propagation_source, acceptance);
            }
            Incoming::Unknown { version, kind, len } => {
                self.report_gossip_validation(&message_id, &propagation_source, gossipsub::MessageAcceptance::Ignore);
                tracing::debug!(
                    "Tipo de mensagem desconhecido ignorado com segurança em {} (v{}, kind={}, {}B)",
                    topic,
                    version,
                    kind,
                    len
                );
            }
        }
    }

    fn on_dcutr_success(&mut self, remote_peer_id: PeerId) {
        if !self.peer_metadata.contains_key(&remote_peer_id) {
            return;
        }
        // Quando o hole punching tem sucesso, limpa qualquer falha antiga registrada para este par
        self.dcutr_last_failure.remove(&remote_peer_id);
        if self.dcutr_punched.insert(remote_peer_id) {
            let peer_label = self.peer_display_name(&remote_peer_id);
            self.emit(CoreEvent::Network(NetworkEvent::HolePunched(peer_label)));
        }
    }

    fn on_dcutr_failure(&mut self, remote_peer_id: PeerId, error: &str) {
        // Ignora nós da DHT do IPFS que não são pares Anarchord identificados
        // e também ignora falhas se já temos um hole punch bem-sucedido para este par.
        if !self.peer_metadata.contains_key(&remote_peer_id) || self.dcutr_punched.contains(&remote_peer_id) {
            return;
        }
        let now = std::time::Instant::now();
        let should_emit = match self.dcutr_last_failure.get(&remote_peer_id) {
            Some((last_time, _)) => now.duration_since(*last_time) >= DCUTR_FAILURE_COOLDOWN,
            None => true,
        };
        if should_emit {
            self.dcutr_last_failure.insert(remote_peer_id, (now, error.to_string()));
            let peer_label = self.peer_display_name(&remote_peer_id);
            self.emit(CoreEvent::Network(NetworkEvent::HolePunchFailed {
                peer_id: peer_label,
                error: error.to_string(),
            }));
        }
    }

    /// (Re)anuncia na DHT os registros que carregam os endereços externos: descoberta, servidores
    /// acompanhados e arquivos compartilhados
    pub(super) fn reannounce_dht(&mut self) {
        if !self.config.discovery {
            return;
        }
        self.node.dht_start_providing();
        for id in self.servers.list().filter(|s| s.has_chain()).map(|s| s.server_id.clone()).collect::<Vec<_>>() {
            self.node.dht_provide(server_dht_key(&id));
        }
        for cid in self.files.engine.providing() {
            self.node.dht_provide(swarm_files::dht_key(&cid));
        }
    }

    /// Pede reserva nos relays candidatos que faltam (só age quando o AutoNAT indicou NAT
    /// e não há porta encaminhada por UPnP)
    pub(super) fn request_relay_reservations(&mut self) {
        for (relay, circuit_addr) in self.relay_manager.next_reservations() {
            match self.node.swarm.listen_on(circuit_addr.clone()) {
                Ok(listener_id) => {
                    self.relay_manager.track_reservation(listener_id, relay);
                    self.emit(CoreEvent::Network(NetworkEvent::RelayRequested { relay: relay.to_string(), address: circuit_addr.to_string() }));
                }
                Err(e) => tracing::warn!("Falha ao pedir reserva em {}: {:?}", circuit_addr, e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::CoreConfig;
    use crate::UserIdentity;
    use tokio::sync::mpsc::unbounded_channel;

    #[tokio::test]
    async fn test_peer_display_name_formatting() {
        let (tx, _rx) = unbounded_channel();
        let temp = std::env::temp_dir().join(format!("test_dcutr_fmt_{}", rand::random::<u32>()));
        let config = CoreConfig::new(UserIdentity::generate_with_nick("Alice"), temp.join("servers"), temp.join("downloads"));
        let mut runtime = Runtime::new(config, tx).unwrap();

        let peer1 = PeerId::random();
        assert_eq!(runtime.peer_display_name(&peer1), peer1.to_string());

        // Identificado com nick
        let bob_identity = UserIdentity::generate();
        let bob_pubkey = bob_identity.public_key_hex();
        runtime.peer_metadata.insert(peer1, ("Bob".to_string(), bob_pubkey.clone()));
        let label = runtime.peer_display_name(&peer1);
        assert!(label.starts_with("Bob ("), "{}", label);
        assert!(label.contains(&community::short_id(&peer1.to_string())));

        // Com apelido de amigo
        runtime.identity.add_friend(&bob_pubkey, Some("Bobby")).unwrap();
        let label_friend = runtime.peer_display_name(&peer1);
        assert!(label_friend.starts_with("Bobby ("), "{}", label_friend);
    }

    #[tokio::test]
    async fn test_dcutr_deduplication_and_cooldown() {
        let (tx, mut rx) = unbounded_channel();
        let temp = std::env::temp_dir().join(format!("test_dcutr_dedup_{}", rand::random::<u32>()));
        let config = CoreConfig::new(UserIdentity::generate_with_nick("Alice"), temp.join("servers"), temp.join("downloads"));
        let mut runtime = Runtime::new(config, tx).unwrap();

        let peer1 = PeerId::random();
        runtime.peer_metadata.insert(peer1, ("Bob".to_string(), "pubkey123".to_string()));

        // 1) Primeiro sucesso de hole punching: emite HolePunched
        runtime.handle_swarm_event(SwarmEvent::Behaviour(AppBehaviourEvent::Dcutr(libp2p::dcutr::Event {
            remote_peer_id: peer1,
            result: Ok(libp2p::swarm::ConnectionId::new_unchecked(1)),
        })));

        let mut events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], CoreEvent::Network(NetworkEvent::HolePunched(label)) if label.contains("Bob")));

        // 2) Segundo sucesso de hole punching para o mesmo peer conectado: DEDUPLICADO (não emite nada)
        runtime.handle_swarm_event(SwarmEvent::Behaviour(AppBehaviourEvent::Dcutr(libp2p::dcutr::Event {
            remote_peer_id: peer1,
            result: Ok(libp2p::swarm::ConnectionId::new_unchecked(2)),
        })));
        assert!(rx.try_recv().is_err(), "sucesso repetido não deve emitir evento");

        // 3) Falha de hole punching para um segundo par Anarchord (Carol): emite HolePunchFailed
        let peer2 = PeerId::random();
        runtime.peer_metadata.insert(peer2, ("Carol".to_string(), "pubkey456".to_string()));
        runtime.on_dcutr_failure(peer2, "dial timeout");
        let ev = rx.try_recv().expect("falha deve emitir evento");
        assert!(matches!(ev, CoreEvent::Network(NetworkEvent::HolePunchFailed { peer_id, error }) if peer_id.contains("Carol") && error == "dial timeout"));

        // 4) Falha consecutiva para o mesmo par (mesmo com texto de porta/endereço diferente!): SUPRIMIDA por cooldown
        runtime.on_dcutr_failure(peer2, "dial timeout");
        assert!(rx.try_recv().is_err(), "falha consecutiva idêntica em cooldown deve ser suprimida");
        runtime.on_dcutr_failure(peer2, "connection refused on ephemeral port 54321");
        assert!(rx.try_recv().is_err(), "falha com string de porta efêmera diferente no mesmo par também deve respeitar o cooldown");

        // 5) Nós desconhecidos da DHT do IPFS (sem peer_metadata) NUNCA geram eventos de HolePunched / HolePunchFailed
        let ipfs_node = PeerId::random();
        runtime.on_dcutr_failure(ipfs_node, "dial timeout");
        runtime.on_dcutr_success(ipfs_node);
        assert!(rx.try_recv().is_err(), "nós não-Anarchord da DHT não devem poluir a TUI com DCUtR");

        // 6) Mesmo que uma conexão feche temporariamente (idle timeout), reconectar ao mesmo par não repete o spam
        runtime.handle_swarm_event(SwarmEvent::ConnectionClosed {
            peer_id: peer1,
            connection_id: libp2p::swarm::ConnectionId::new_unchecked(1),
            endpoint: libp2p::core::ConnectedPoint::Listener {
                local_addr: "/ip4/127.0.0.1/tcp/8000".parse().unwrap(),
                send_back_addr: "/ip4/127.0.0.1/tcp/8001".parse().unwrap(),
            },
            num_established: 0,
            cause: None,
        });
        runtime.handle_swarm_event(SwarmEvent::Behaviour(AppBehaviourEvent::Dcutr(libp2p::dcutr::Event {
            remote_peer_id: peer1,
            result: Ok(libp2p::swarm::ConnectionId::new_unchecked(3)),
        })));
        let mut new_events = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, CoreEvent::Network(NetworkEvent::HolePunched(_))) {
                new_events.push(ev);
            }
        }
        assert_eq!(new_events.len(), 0, "reconexão por idle timeout ao mesmo par não deve repetir HolePunched");
    }
}
