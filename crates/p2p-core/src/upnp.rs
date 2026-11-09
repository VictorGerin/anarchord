//! UPnP IGD (#101): pede ao roteador que encaminhe a porta de escuta do nó (TCP e UDP/QUIC).
//!
//! Basta um dos lados de uma conexão estar alcançável para dispensar hole punching e relay.
//! Com a porta encaminhada, o endereço externo vira endereço confirmado do swarm (Identify, DHT)
//! e o nó deixa de reservar circuito em relay enquanto o AutoNAT não desmentir (ver `RelayManager`).
//!
//! Não usa o `libp2p-upnp` 0.3 (o da linha libp2p 0.54): ele deduplica mapeamentos só pela porta
//! (aqui TCP e QUIC dividem a porta, então o UDP nunca seria mapeado), mapeia a primeira interface
//! privada que aparecer (vEthernet do WSL/Hyper-V, VPN) e não remove o mapeamento ao encerrar.

use igd_next::aio::tokio::{search_gateway, Tokio};
use igd_next::aio::Gateway;
use igd_next::{AddPortError, PortMappingProtocol, SearchOptions};
use libp2p::{multiaddr::Protocol, Multiaddr};
use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;
use tokio::sync::{mpsc::UnboundedSender, oneshot};

/// Validade pedida ao roteador para cada mapeamento, renovado na metade do prazo
const LEASE_SECS: u32 = 3600;
const RENEW_EVERY: Duration = Duration::from_secs(LEASE_SECS as u64 / 2);
/// Nova tentativa depois de recusa ou perda do mapeamento
const RETRY_EVERY: Duration = Duration::from_secs(5 * 60);
const SEARCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Prazo de cada pedido ao roteador (o cliente HTTP do igd-next não tem prazo próprio)
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Prazo para remover os mapeamentos ao encerrar; se o roteador não responder, o lease vence sozinho
const REMOVE_TIMEOUT: Duration = Duration::from_secs(2);
const DESCRIPTION: &str = "Anarchord";

/// O que o mapeamento de porta tem a dizer ao nó
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpnpEvent {
    /// Porta encaminhada: endereços externos (TCP e/ou QUIC) com o IP público do roteador
    Mapped(Vec<Multiaddr>),
    /// Mapeamento perdido (renovação recusada, roteador sumiu ou trocou de IP público)
    Lost(Vec<Multiaddr>),
    /// Nenhum roteador com UPnP respondeu na rede local
    GatewayNotFound,
    /// O roteador respondeu, mas o IP dele na WAN não é público (CGNAT ou NAT duplo): mapear não adianta
    NonRoutableGateway(IpAddr),
    /// O roteador recusou o mapeamento (UPnP restrito, porta ocupada...). Avisado uma vez só
    MappingRefused(String),
}

/// Para qual IP local o roteador deve encaminhar
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Escuta em todas as interfaces: usa o IP da interface pela qual se chega ao roteador
    Route,
    /// Escuta presa a um IP da rede local
    Fixed(Ipv4Addr),
}

/// Alvo do mapeamento conforme o IP de escuta (`None` = não dá para encaminhar: loopback ou IPv6)
pub fn target_for(listen_ip: Option<&str>) -> Option<Target> {
    match listen_ip.map(str::parse::<IpAddr>) {
        None => Some(Target::Route),
        Some(Ok(IpAddr::V4(ip))) if ip.is_unspecified() => Some(Target::Route),
        Some(Ok(IpAddr::V4(ip))) if !ip.is_loopback() => Some(Target::Fixed(ip)),
        _ => None,
    }
}

/// Mapeamento de porta em andamento. Ao encerrar, use [`UpnpHandle::shutdown`] para remover
/// os mapeamentos do roteador; se o handle só for descartado, a tarefa ainda tenta removê-los.
pub struct UpnpHandle {
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl UpnpHandle {
    /// Para de renovar e remove os mapeamentos ativos, com prazo curto
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = tokio::time::timeout(REMOVE_TIMEOUT + Duration::from_millis(500), &mut self.task).await;
    }
}

/// Procura o roteador e mapeia `port` em TCP e UDP. Precisa de um runtime tokio.
/// `allow_private`: rede de laboratório, em que um IP privado na WAN do roteador vale como público.
pub fn spawn(port: u16, target: Target, allow_private: bool, events: UnboundedSender<UpnpEvent>) -> UpnpHandle {
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(run(port, target, allow_private, events, stopped));
    UpnpHandle { stop: Some(stop), task }
}

async fn run(
    port: u16,
    target: Target,
    allow_private: bool,
    events: UnboundedSender<UpnpEvent>,
    mut stopped: oneshot::Receiver<()>,
) {
    let options = SearchOptions { timeout: Some(SEARCH_TIMEOUT), ..Default::default() };
    let gateway = tokio::select! {
        _ = &mut stopped => return,
        found = search_gateway(options) => match found {
            Ok(gateway) => gateway,
            Err(e) => {
                tracing::debug!("UPnP: nenhum roteador respondeu: {}", e);
                let _ = events.send(UpnpEvent::GatewayNotFound);
                return;
            }
        },
    };
    let local_ip = match target {
        Target::Fixed(ip) => Some(ip),
        Target::Route => local_ipv4_towards(gateway.addr),
    };
    let Some(local_ip) = local_ip else {
        tracing::debug!("UPnP: sem IPv4 local na rota até o roteador {}", gateway.addr);
        return;
    };
    let local = SocketAddrV4::new(local_ip, port);
    tracing::debug!("UPnP: roteador {} encontrado; encaminhando a porta {} para {}", gateway.addr, port, local);

    let mut mappings = Mappings::default();
    let mut first = true;
    loop {
        let results = match timed(gateway.get_external_ip()).await {
            Ok(IpAddr::V4(ip)) if is_routable(ip, allow_private) => {
                let mut results = Vec::new();
                for transport in Transport::ALL {
                    let external_port = mappings.external_port(transport).unwrap_or(port);
                    let result = map(&gateway, transport, local, external_port).await;
                    results.push((transport, result.map(|port| SocketAddrV4::new(ip, port))));
                }
                results
            }
            Ok(ip) if first => {
                tracing::debug!("UPnP: o roteador não tem IP público na WAN ({})", ip);
                let _ = events.send(UpnpEvent::NonRoutableGateway(ip));
                return;
            }
            Ok(ip) => failed_round(format!("o roteador ficou sem IP público ({})", ip)),
            Err(e) => failed_round(e),
        };
        first = false;
        for event in mappings.apply(results) {
            let _ = events.send(event);
        }
        let wait = if mappings.is_active() { RENEW_EVERY } else { RETRY_EVERY };
        tokio::select! {
            _ = &mut stopped => break,
            _ = tokio::time::sleep(wait) => {}
        }
    }

    // Encerramento (pedido ou handle descartado): tira os mapeamentos do roteador
    let _ = tokio::time::timeout(REMOVE_TIMEOUT, async {
        for (transport, external) in mappings.active() {
            match gateway.remove_port(transport.protocol(), external.port()).await {
                Ok(()) => tracing::debug!("UPnP: mapeamento {:?} {} removido", transport, external),
                Err(e) => tracing::debug!("UPnP: falha ao remover o mapeamento {:?} {}: {}", transport, external, e),
            }
        }
    })
    .await;
}

/// Pede (ou renova) o encaminhamento de `local` no roteador. Tenta a mesma porta por fora; se outra
/// máquina da rede já usa essa porta, aceita a que o roteador escolher. Devolve a porta externa.
async fn map(gateway: &Gateway<Tokio>, transport: Transport, local: SocketAddrV4, external_port: u16) -> Result<u16, String> {
    let protocol = transport.protocol();
    let local = SocketAddr::V4(local);
    let request = gateway.add_port(protocol, external_port, local, LEASE_SECS, DESCRIPTION);
    match tokio::time::timeout(REQUEST_TIMEOUT, request).await {
        Err(_) => Err(NO_ANSWER.to_string()),
        Ok(Ok(())) => Ok(external_port),
        // Roteadores antigos só aceitam mapeamento permanente: ele sai no encerramento
        Ok(Err(AddPortError::OnlyPermanentLeasesSupported)) => {
            timed(gateway.add_port(protocol, external_port, local, 0, DESCRIPTION)).await.map(|()| external_port)
        }
        Ok(Err(AddPortError::PortInUse)) => timed(gateway.add_any_port(protocol, local, LEASE_SECS, DESCRIPTION)).await,
        Ok(Err(e)) => Err(e.to_string()),
    }
}

const NO_ANSWER: &str = "o roteador não respondeu a tempo";

/// Pedido ao roteador com prazo; o erro vira texto para os avisos
async fn timed<T, E: std::fmt::Display>(request: impl Future<Output = Result<T, E>>) -> Result<T, String> {
    match tokio::time::timeout(REQUEST_TIMEOUT, request).await {
        Ok(result) => result.map_err(|e| e.to_string()),
        Err(_) => Err(NO_ANSWER.to_string()),
    }
}

fn failed_round(error: String) -> Vec<(Transport, Result<SocketAddrV4, String>)> {
    Transport::ALL.into_iter().map(|t| (t, Err(error.clone()))).collect()
}

/// IP público de verdade na WAN do roteador (CGNAT `100.64/10` e faixas privadas não servem)
fn is_routable(ip: Ipv4Addr, allow_private: bool) -> bool {
    crate::relay::is_public_ipv4(&ip) || (allow_private && !ip.is_loopback() && !ip.is_unspecified())
}

/// IP desta máquina na interface pela qual se chega ao roteador. `connect` em UDP só escolhe a rota,
/// não manda pacote; evita mapear para a vEthernet do WSL/Hyper-V ou para uma VPN.
fn local_ipv4_towards(gateway: SocketAddr) -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(gateway).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

/// Transporte mapeado; os dois usam a porta de escuta (`pick_shared_tcp_udp_port`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Transport {
    Tcp,
    Quic,
}

impl Transport {
    const ALL: [Transport; 2] = [Transport::Tcp, Transport::Quic];

    fn protocol(self) -> PortMappingProtocol {
        match self {
            Transport::Tcp => PortMappingProtocol::TCP,
            Transport::Quic => PortMappingProtocol::UDP,
        }
    }

    /// Endereço que os outros pares discam
    fn multiaddr(self, external: SocketAddrV4) -> Multiaddr {
        let base = Multiaddr::empty().with(Protocol::Ip4(*external.ip()));
        match self {
            Transport::Tcp => base.with(Protocol::Tcp(external.port())),
            Transport::Quic => base.with(Protocol::Udp(external.port())).with(Protocol::QuicV1),
        }
    }
}

/// Mapeamentos ativos e os avisos que cada mudança gera: um por transição, nada a cada renovação
#[derive(Debug, Default)]
struct Mappings {
    /// Transporte -> endereço externo (IP público do roteador e porta) ativo
    active: BTreeMap<Transport, SocketAddrV4>,
    /// Última porta externa obtida por transporte, pedida de novo na renovação e após perda
    ports: BTreeMap<Transport, u16>,
    /// Recusa já avisada, ou já houve mapeamento (daí em diante as quedas saem como `Lost`)
    refusal_warned: bool,
}

impl Mappings {
    fn external_port(&self, transport: Transport) -> Option<u16> {
        self.ports.get(&transport).copied()
    }

    fn is_active(&self) -> bool {
        !self.active.is_empty()
    }

    fn active(&self) -> impl Iterator<Item = (Transport, SocketAddrV4)> + '_ {
        self.active.iter().map(|(t, a)| (*t, *a))
    }

    /// Aplica o resultado de uma rodada de mapeamento ou renovação e devolve os avisos
    fn apply(&mut self, results: Vec<(Transport, Result<SocketAddrV4, String>)>) -> Vec<UpnpEvent> {
        let (mut mapped, mut lost, mut refusal) = (Vec::new(), Vec::new(), None);
        for (transport, result) in results {
            match result {
                Ok(external) => {
                    self.ports.insert(transport, external.port());
                    match self.active.insert(transport, external) {
                        Some(previous) if previous == external => {}
                        Some(previous) => {
                            lost.push(transport.multiaddr(previous));
                            mapped.push(transport.multiaddr(external));
                        }
                        None => mapped.push(transport.multiaddr(external)),
                    }
                }
                Err(error) => {
                    tracing::debug!("UPnP: mapeamento {:?} falhou: {}", transport, error);
                    if let Some(previous) = self.active.remove(&transport) {
                        lost.push(transport.multiaddr(previous));
                    }
                    refusal.get_or_insert(error);
                }
            }
        }
        let mut events = Vec::new();
        if !lost.is_empty() {
            events.push(UpnpEvent::Lost(lost));
        }
        if !mapped.is_empty() {
            self.refusal_warned = true;
            events.push(UpnpEvent::Mapped(mapped));
        }
        // Nunca mapeou e nada perdido agora: é recusa do roteador, avisada uma vez na execução
        if events.is_empty() && !self.is_active() && !self.refusal_warned {
            if let Some(error) = refusal {
                self.refusal_warned = true;
                events.push(UpnpEvent::MappingRefused(error));
            }
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(ip: [u8; 4], port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(ip), port)
    }

    fn addr(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_maps_tcp_and_quic_on_the_same_port() {
        let mut m = Mappings::default();
        let events = m.apply(vec![
            (Transport::Tcp, Ok(ext([8, 8, 8, 8], 4001))),
            (Transport::Quic, Ok(ext([8, 8, 8, 8], 4001))),
        ]);
        assert_eq!(
            events,
            vec![UpnpEvent::Mapped(vec![addr("/ip4/8.8.8.8/tcp/4001"), addr("/ip4/8.8.8.8/udp/4001/quic-v1")])]
        );
        assert!(m.is_active());
        assert_eq!(m.external_port(Transport::Quic), Some(4001));
    }

    #[test]
    fn test_renewal_is_silent_and_loss_warns_once() {
        let mut m = Mappings::default();
        let ok = || vec![(Transport::Tcp, Ok(ext([8, 8, 8, 8], 4001))), (Transport::Quic, Ok(ext([8, 8, 8, 8], 4001)))];
        m.apply(ok());
        assert!(m.apply(ok()).is_empty(), "renovação igual não gera aviso");

        // Renovação do UDP recusada: perde só o QUIC
        let events = m.apply(vec![(Transport::Tcp, Ok(ext([8, 8, 8, 8], 4001))), (Transport::Quic, Err("recusado".into()))]);
        assert_eq!(events, vec![UpnpEvent::Lost(vec![addr("/ip4/8.8.8.8/udp/4001/quic-v1")])]);

        // Roteador sumiu: perde o TCP; tentativas seguintes falhando não repetem aviso
        assert_eq!(m.apply(failed_round("sumiu".into())), vec![UpnpEvent::Lost(vec![addr("/ip4/8.8.8.8/tcp/4001")])]);
        assert!(!m.is_active());
        assert!(m.apply(failed_round("sumiu".into())).is_empty());

        // Voltou: a porta pedida é a mesma de antes
        assert_eq!(m.external_port(Transport::Tcp), Some(4001));
        assert_eq!(m.apply(ok()).len(), 1);
    }

    #[test]
    fn test_public_ip_change_replaces_the_addresses() {
        let mut m = Mappings::default();
        m.apply(vec![(Transport::Tcp, Ok(ext([8, 8, 8, 8], 4001)))]);
        let events = m.apply(vec![(Transport::Tcp, Ok(ext([9, 9, 9, 9], 4001)))]);
        assert_eq!(
            events,
            vec![
                UpnpEvent::Lost(vec![addr("/ip4/8.8.8.8/tcp/4001")]),
                UpnpEvent::Mapped(vec![addr("/ip4/9.9.9.9/tcp/4001")]),
            ]
        );
    }

    #[test]
    fn test_refusal_is_warned_once() {
        let mut m = Mappings::default();
        assert_eq!(m.apply(failed_round("ActionNotAuthorized".into())), vec![UpnpEvent::MappingRefused("ActionNotAuthorized".into())]);
        assert!(m.apply(failed_round("ActionNotAuthorized".into())).is_empty());
    }

    #[test]
    fn test_other_external_port_when_the_router_picks_one() {
        let mut m = Mappings::default();
        let events = m.apply(vec![(Transport::Tcp, Ok(ext([8, 8, 8, 8], 51234)))]);
        assert_eq!(events, vec![UpnpEvent::Mapped(vec![addr("/ip4/8.8.8.8/tcp/51234")])]);
        assert_eq!(m.external_port(Transport::Tcp), Some(51234));
    }

    #[test]
    fn test_target_follows_the_listen_ip() {
        assert_eq!(target_for(None), Some(Target::Route));
        assert_eq!(target_for(Some("0.0.0.0")), Some(Target::Route));
        assert_eq!(target_for(Some("192.168.0.5")), Some(Target::Fixed(Ipv4Addr::new(192, 168, 0, 5))));
        assert_eq!(target_for(Some("127.0.0.1")), None);
        assert_eq!(target_for(Some("::")), None);
        assert_eq!(target_for(Some("lixo")), None);
    }

    #[test]
    fn test_cgnat_and_private_wan_are_not_routable() {
        assert!(is_routable(Ipv4Addr::new(8, 8, 8, 8), false));
        assert!(!is_routable(Ipv4Addr::new(100, 64, 1, 1), false));
        assert!(!is_routable(Ipv4Addr::new(192, 168, 1, 1), false));
        assert!(!is_routable(Ipv4Addr::new(10, 0, 0, 1), false));
        // Laboratório: WAN privada vale, loopback não
        assert!(is_routable(Ipv4Addr::new(10, 0, 0, 1), true));
        assert!(!is_routable(Ipv4Addr::LOCALHOST, true));
    }

    #[test]
    fn test_local_ip_follows_the_route_to_the_gateway() {
        let local = local_ipv4_towards("127.0.0.1:1900".parse().unwrap());
        assert_eq!(local, Some(Ipv4Addr::LOCALHOST));
    }
}
