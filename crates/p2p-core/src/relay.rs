use libp2p::{core::transport::ListenerId, multiaddr::Protocol, Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Quantidade de reservas simultâneas em relays públicos mantidas quando o nó está atrás de NAT
pub const MAX_RELAY_RESERVATIONS: usize = 2;

/// Seleciona relays públicos (Circuit Relay v2) e controla as reservas feitas neles.
///
/// Quando o AutoNAT conclui que o nó está atrás de NAT, o nó reserva um endereço
/// `/p2p/<relay>/p2p-circuit` em alguns pares que oferecem o protocolo HOP. Esse endereço
/// é anunciado (Identify e registros de provedor da DHT), outros nós conectam por ele
/// e o DCUtR tenta em seguida promover a conexão relayada para uma conexão direta (hole punching).
///
/// Com a porta encaminhada por UPnP (#101) o nó é alcançável direto: não reserva circuito, a menos
/// que o AutoNAT mostre que ninguém de fora consegue discar de volta (firewall do sistema, provedor).
#[derive(Debug, Default)]
pub struct RelayManager {
    behind_nat: bool,
    upnp: UpnpReach,
    /// Pares que oferecem o protocolo HOP -> endereço público direto escolhido para alcançá-los
    candidates: HashMap<PeerId, Multiaddr>,
    /// Reservas pendentes ou aceitas: listener do circuito -> relay
    reservations: HashMap<ListenerId, PeerId>,
    /// Relays que recusaram ou derrubaram a reserva (não são tentados de novo)
    failed: HashSet<PeerId>,
    /// Aceita relays em endereços privados (rede de laboratório)
    allow_private: bool,
}

impl RelayManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rede de laboratório: relays em IPs privados também servem
    pub fn allow_private(&mut self, allow: bool) {
        self.allow_private = allow;
    }

    /// Atualiza o estado de NAT informado pelo AutoNAT
    pub fn set_behind_nat(&mut self, behind_nat: bool) {
        self.behind_nat = behind_nat;
    }

    pub fn is_behind_nat(&self) -> bool {
        self.behind_nat
    }

    /// Liga ou desliga o mapeamento UPnP. Ao ligar, devolve os listeners das reservas atuais para
    /// o chamador fechar (`remove_listener`); esses relays não contam como falha e voltam a ser
    /// candidatos se o mapeamento cair.
    pub fn set_upnp_mapped(&mut self, mapped: bool) -> Vec<ListenerId> {
        match (mapped, self.upnp) {
            (true, UpnpReach::Off) => {
                self.upnp = UpnpReach::Mapped;
                self.reservations.drain().map(|(listener, _)| listener).collect()
            }
            (true, _) => Vec::new(),
            (false, _) => {
                self.upnp = UpnpReach::Off;
                Vec::new()
            }
        }
    }

    /// O AutoNAT não conseguiu discar de volta apesar do mapeamento: volta a reservar relay.
    /// Retorna `true` só na primeira vez (para avisar a interface uma vez).
    pub fn upnp_refuted(&mut self) -> bool {
        if self.upnp == UpnpReach::Mapped {
            self.upnp = UpnpReach::Refuted;
            true
        } else {
            false
        }
    }

    /// Mapeamento UPnP ativo e não desmentido pelo AutoNAT
    pub fn upnp_reachable(&self) -> bool {
        self.upnp == UpnpReach::Mapped
    }

    /// Registra um par que anunciou suporte ao protocolo HOP, guardando um endereço
    /// público direto (TCP ou QUIC) que este nó consegue discar
    pub fn add_candidate(&mut self, peer: PeerId, listen_addrs: &[Multiaddr]) {
        if self.failed.contains(&peer) {
            return;
        }
        if let Some(addr) = listen_addrs.iter().find(|a| is_dialable_addr(a, self.allow_private)) {
            self.candidates.insert(peer, strip_peer_id(addr));
        }
    }

    /// Esquece um par que desconectou (a reserva nele, se houver, cai junto com a conexão)
    pub fn remove_peer(&mut self, peer: &PeerId) {
        self.candidates.remove(peer);
    }

    /// Relays que ainda devem receber pedido de reserva, como endereços de circuito prontos para `listen_on`.
    /// O chamador deve registrar o `ListenerId` retornado por `listen_on` com [`Self::track_reservation`].
    pub fn next_reservations(&self) -> Vec<(PeerId, Multiaddr)> {
        if !self.behind_nat || self.upnp_reachable() {
            return Vec::new();
        }
        let reserved: HashSet<&PeerId> = self.reservations.values().collect();
        let missing = MAX_RELAY_RESERVATIONS.saturating_sub(self.reservations.len());
        self.candidates
            .iter()
            .filter(|(peer, _)| !reserved.contains(peer) && !self.failed.contains(peer))
            .take(missing)
            .map(|(peer, addr)| {
                let circuit = addr
                    .clone()
                    .with(Protocol::P2p(*peer))
                    .with(Protocol::P2pCircuit);
                (*peer, circuit)
            })
            .collect()
    }

    pub fn track_reservation(&mut self, listener: ListenerId, relay: PeerId) {
        self.reservations.insert(listener, relay);
    }

    /// Trata o fechamento do listener de um circuito (reserva recusada, expirada ou relay desconectado).
    /// Retorna o relay correspondente, se o listener era de uma reserva.
    pub fn listener_closed(&mut self, listener: ListenerId) -> Option<PeerId> {
        let relay = self.reservations.remove(&listener)?;
        self.failed.insert(relay);
        self.candidates.remove(&relay);
        Some(relay)
    }

    pub fn active_reservations(&self) -> usize {
        self.reservations.len()
    }
}

/// Alcance pelo mapeamento UPnP, do ponto de vista da política de relay
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum UpnpReach {
    /// Sem mapeamento
    #[default]
    Off,
    /// Porta encaminhada no roteador: dispensa relay
    Mapped,
    /// Porta encaminhada, mas o AutoNAT não conseguiu discar de volta: relay de novo
    Refuted,
}

/// Endereço direto (não relayado), com IP público ou DNS, sobre TCP ou QUIC puros
pub(crate) fn is_dialable_addr(addr: &Multiaddr, allow_private: bool) -> bool {
    let mut has_public_host = false;
    let mut has_supported_transport = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => has_public_host = is_public_ipv4(&ip),
            Protocol::Ip6(ip) => has_public_host = is_public_ipv6(&ip),
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => has_public_host = true,
            Protocol::Tcp(_) | Protocol::QuicV1 => has_supported_transport = true,
            Protocol::P2pCircuit
            | Protocol::Ws(_)
            | Protocol::Wss(_)
            | Protocol::WebTransport
            | Protocol::WebRTCDirect
            | Protocol::Tls => return false,
            _ => {}
        }
    }
    (has_public_host || (allow_private && addr.iter().any(|p| matches!(p, Protocol::Ip4(ip) if !ip.is_loopback() && !ip.is_unspecified()))))
        && has_supported_transport
}

pub(crate) fn is_public_ipv4(ip: &Ipv4Addr) -> bool {
    let shared_cgnat = ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64;
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || shared_cgnat)
}

fn is_public_ipv6(ip: &Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    let unique_local = (first & 0xfe00) == 0xfc00;
    let link_local = (first & 0xffc0) == 0xfe80;
    !(ip.is_loopback() || ip.is_unspecified() || unique_local || link_local)
}

/// Remove um `/p2p/<id>` final, já que o endereço de circuito adiciona o seu próprio
fn strip_peer_id(addr: &Multiaddr) -> Multiaddr {
    addr.iter()
        .filter(|p| !matches!(p, Protocol::P2p(_)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_only_public_direct_addrs_are_candidates() {
        assert!(is_dialable_addr(&addr("/ip4/8.8.8.8/tcp/4001"), false));
        assert!(is_dialable_addr(&addr("/ip4/8.8.8.8/udp/4001/quic-v1"), false));
        assert!(is_dialable_addr(&addr("/dns4/relay.example.com/tcp/4001"), false));
        assert!(!is_dialable_addr(&addr("/ip4/192.168.0.10/tcp/4001"), false));
        assert!(!is_dialable_addr(&addr("/ip4/127.0.0.1/tcp/4001"), false));
        assert!(!is_dialable_addr(&addr("/ip4/100.64.1.1/tcp/4001"), false));
        assert!(!is_dialable_addr(&addr("/ip4/8.8.8.8/tcp/443/wss"), false));
        assert!(!is_dialable_addr(&addr("/ip4/8.8.8.8/udp/4001/quic-v1/webtransport"), false));
        // Rede de laboratório: IP privado vale, loopback e circuito continuam fora
        assert!(is_dialable_addr(&addr("/ip4/192.168.0.10/tcp/4001"), true));
        assert!(!is_dialable_addr(&addr("/ip4/127.0.0.1/tcp/4001"), true));
        assert!(!is_dialable_addr(&addr("/ip4/10.0.0.1/tcp/4001/p2p-circuit"), true));
    }

    #[test]
    fn test_reservations_only_when_behind_nat_and_capped() {
        let mut mgr = RelayManager::new();
        for i in 1..=4u8 {
            mgr.add_candidate(PeerId::random(), &[addr(&format!("/ip4/8.8.8.{}/tcp/4001", i))]);
        }
        assert!(mgr.next_reservations().is_empty());

        mgr.set_behind_nat(true);
        let next = mgr.next_reservations();
        assert_eq!(next.len(), MAX_RELAY_RESERVATIONS);
        for (peer, circuit) in &next {
            let protos: Vec<Protocol> = circuit.iter().collect();
            assert_eq!(protos[protos.len() - 2], Protocol::P2p(*peer));
            assert_eq!(protos[protos.len() - 1], Protocol::P2pCircuit);
        }
    }

    #[test]
    fn test_closed_reservation_is_not_retried() {
        let mut mgr = RelayManager::new();
        mgr.set_behind_nat(true);
        let relay = PeerId::random();
        mgr.add_candidate(relay, &[addr("/ip4/8.8.8.8/tcp/4001")]);

        let listener = ListenerId::next();
        mgr.track_reservation(listener, relay);
        assert!(mgr.next_reservations().is_empty());

        assert_eq!(mgr.listener_closed(listener), Some(relay));
        assert_eq!(mgr.active_reservations(), 0);
        mgr.add_candidate(relay, &[addr("/ip4/8.8.8.8/tcp/4001")]);
        assert!(mgr.next_reservations().is_empty());
    }

    #[test]
    fn test_upnp_mapping_releases_reservations_without_blaming_the_relay() {
        let mut mgr = RelayManager::new();
        mgr.set_behind_nat(true);
        let relay = PeerId::random();
        mgr.add_candidate(relay, &[addr("/ip4/8.8.8.8/tcp/4001")]);
        let listener = ListenerId::next();
        mgr.track_reservation(listener, relay);

        // Porta aberta no roteador: solta a reserva e não pede outra, mesmo atrás de NAT
        assert_eq!(mgr.set_upnp_mapped(true), vec![listener]);
        assert_eq!(mgr.active_reservations(), 0);
        assert!(mgr.next_reservations().is_empty());
        assert!(mgr.set_upnp_mapped(true).is_empty(), "segundo aviso de mapeamento não solta nada");
        // O listener solto fecha depois: não marca o relay como falho
        assert_eq!(mgr.listener_closed(listener), None);

        // Mapeamento perdido: o mesmo relay volta a ser candidato
        mgr.set_upnp_mapped(false);
        let next = mgr.next_reservations();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].0, relay);
    }

    #[test]
    fn test_autonat_refutes_upnp_once_and_relays_come_back() {
        let mut mgr = RelayManager::new();
        mgr.set_behind_nat(true);
        mgr.add_candidate(PeerId::random(), &[addr("/ip4/8.8.8.8/tcp/4001")]);
        assert!(!mgr.upnp_refuted(), "sem mapeamento não há o que desmentir");

        mgr.set_upnp_mapped(true);
        assert!(mgr.upnp_reachable());
        assert!(mgr.upnp_refuted());
        assert!(!mgr.upnp_refuted(), "desmentido avisa uma vez só");
        assert!(!mgr.upnp_reachable());
        assert_eq!(mgr.next_reservations().len(), 1);

        // Mapeamento renovado não apaga o desmentido; perder e remapear dá nova chance
        mgr.set_upnp_mapped(true);
        assert!(!mgr.upnp_reachable());
        mgr.set_upnp_mapped(false);
        mgr.set_upnp_mapped(true);
        assert!(mgr.upnp_reachable());
    }
}
