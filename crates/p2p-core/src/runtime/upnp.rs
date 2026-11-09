//! UPnP (#101): liga o encaminhamento de porta do roteador ao swarm (endereço externo confirmado,
//! Identify, DHT) e à política de relay.

use super::{CoreEvent, NetworkEvent, Runtime};
use crate::upnp::{self, UpnpEvent};
use libp2p::PeerId;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

impl Runtime {
    /// Começa a pedir o encaminhamento da porta ao roteador, se não estiver desligado
    /// (`--no-upnp` ou `network.upnp = false`). Precisa rodar dentro do runtime tokio.
    pub(super) fn start_upnp(&mut self) -> Option<UnboundedReceiver<UpnpEvent>> {
        if !self.config.upnp || !self.dm.node_config.network.upnp {
            tracing::debug!("UPnP desligado pela configuração");
            return None;
        }
        let Some(target) = upnp::target_for(self.config.listen_ip.as_deref()) else {
            tracing::debug!("UPnP: escuta em {:?} não é encaminhável pelo roteador", self.config.listen_ip);
            return None;
        };
        let (tx, rx) = unbounded_channel();
        self.upnp = Some(upnp::spawn(self.node.listen_port, target, self.config.lab, tx));
        Some(rx)
    }

    pub(super) fn on_upnp_event(&mut self, event: UpnpEvent) {
        match event {
            UpnpEvent::Mapped(addrs) => {
                for addr in &addrs {
                    self.node.swarm.add_external_address(addr.clone());
                    // Quem confirma que dá para chegar pelo endereço é o AutoNAT: sonda logo
                    self.node.swarm.behaviour_mut().autonat.probe_address(addr.clone());
                    self.upnp_addrs.insert(addr.clone());
                }
                // Alcançável direto: as reservas em relay deixam de ser anunciadas
                for listener in self.relay_manager.set_upnp_mapped(true) {
                    self.node.swarm.remove_listener(listener);
                }
                // `add_external_address` não gera `SwarmEvent::ExternalAddrConfirmed`: anuncia aqui
                self.reannounce_dht();
                let peers: Vec<PeerId> = self.connected_peers.iter().copied().collect();
                self.node.swarm.behaviour_mut().identify.push(peers);
                tracing::info!("UPnP: porta encaminhada no roteador ({:?})", addrs);
                self.emit(CoreEvent::Network(NetworkEvent::UpnpMapped(addrs.iter().map(ToString::to_string).collect())));
            }
            UpnpEvent::Lost(addrs) => {
                for addr in &addrs {
                    self.node.swarm.remove_external_address(addr);
                    self.upnp_addrs.remove(addr);
                }
                if self.upnp_addrs.is_empty() {
                    self.relay_manager.set_upnp_mapped(false);
                    self.request_relay_reservations();
                }
                tracing::info!("UPnP: mapeamento perdido ({:?})", addrs);
                self.emit(CoreEvent::Network(NetworkEvent::UpnpLost(addrs.iter().map(ToString::to_string).collect())));
            }
            // Sem roteador UPnP nada muda: fica só no log
            UpnpEvent::GatewayNotFound => tracing::debug!("UPnP: nenhum roteador com UPnP na rede local"),
            UpnpEvent::NonRoutableGateway(ip) => self.emit(CoreEvent::Network(NetworkEvent::UpnpUnavailable(format!(
                "o roteador não tem IP público ({}): CGNAT da operadora ou NAT duplo",
                ip
            )))),
            UpnpEvent::MappingRefused(error) => self.emit(CoreEvent::Network(NetworkEvent::UpnpUnavailable(format!(
                "o roteador recusou o encaminhamento ({})",
                error
            )))),
        }
    }

    /// O AutoNAT não conseguiu discar de volta. Com a porta encaminhada, o mapeamento não está
    /// valendo (firewall do sistema, filtro do provedor): volta a reservar relay e avisa uma vez.
    pub(super) fn on_autonat_unreachable(&mut self) {
        if self.relay_manager.upnp_refuted() {
            tracing::info!("UPnP: porta encaminhada, mas o AutoNAT não conseguiu discar de volta; voltando ao relay");
            self.emit(CoreEvent::Network(NetworkEvent::UpnpUnreachable));
            self.request_relay_reservations();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::CoreConfig;
    use crate::UserIdentity;
    use libp2p::Multiaddr;

    fn runtime() -> (Runtime, tokio::sync::mpsc::UnboundedReceiver<CoreEvent>) {
        let (tx, rx) = unbounded_channel();
        let temp = std::env::temp_dir().join(format!("test_upnp_{}", rand::random::<u32>()));
        let config = CoreConfig::new(UserIdentity::generate_with_nick("Alice"), temp.join("servers"), temp.join("downloads"));
        (Runtime::new(config, tx).unwrap(), rx)
    }

    fn network_events(rx: &mut tokio::sync::mpsc::UnboundedReceiver<CoreEvent>) -> Vec<NetworkEvent> {
        std::iter::from_fn(|| rx.try_recv().ok())
            .filter_map(|e| match e {
                CoreEvent::Network(n) => Some(n),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn test_disabled_by_default_in_tests_and_by_config() {
        let (mut rt, _rx) = runtime();
        assert!(rt.start_upnp().is_none(), "CoreConfig::new deixa UPnP desligado");
        rt.config.upnp = true;
        rt.dm.node_config.network.upnp = false;
        assert!(rt.start_upnp().is_none(), "network.upnp = false desliga");
        rt.dm.node_config.network.upnp = true;
        rt.config.listen_ip = Some("127.0.0.1".into());
        assert!(rt.start_upnp().is_none(), "escuta em loopback não tem o que encaminhar");
    }

    #[tokio::test]
    async fn test_mapping_becomes_external_address_and_loss_removes_it() {
        let (mut rt, mut rx) = runtime();
        let tcp: Multiaddr = "/ip4/8.8.8.8/tcp/4001".parse().unwrap();
        let quic: Multiaddr = "/ip4/8.8.8.8/udp/4001/quic-v1".parse().unwrap();

        rt.relay_manager.set_behind_nat(true);
        rt.on_upnp_event(UpnpEvent::Mapped(vec![tcp.clone(), quic.clone()]));
        let external: Vec<Multiaddr> = rt.node.swarm.external_addresses().cloned().collect();
        assert!(external.contains(&tcp) && external.contains(&quic), "{:?}", external);
        assert!(rt.relay_manager.upnp_reachable());
        assert_eq!(
            network_events(&mut rx),
            vec![NetworkEvent::UpnpMapped(vec![tcp.to_string(), quic.to_string()])]
        );

        // Perder só o QUIC mantém o UPnP valendo para a política de relay
        rt.on_upnp_event(UpnpEvent::Lost(vec![quic.clone()]));
        assert!(rt.relay_manager.upnp_reachable());
        rt.on_upnp_event(UpnpEvent::Lost(vec![tcp.clone()]));
        assert!(!rt.relay_manager.upnp_reachable());
        assert_eq!(rt.node.swarm.external_addresses().count(), 0);
        assert_eq!(network_events(&mut rx).len(), 2);
    }

    #[tokio::test]
    async fn test_no_gateway_is_silent_and_autonat_refutes_once() {
        let (mut rt, mut rx) = runtime();
        rt.on_upnp_event(UpnpEvent::GatewayNotFound);
        assert!(network_events(&mut rx).is_empty(), "sem roteador UPnP, nada na tela");

        rt.on_upnp_event(UpnpEvent::NonRoutableGateway("100.64.0.9".parse().unwrap()));
        assert!(matches!(&network_events(&mut rx)[..], [NetworkEvent::UpnpUnavailable(reason)] if reason.contains("CGNAT")));

        // Sem mapeamento, falha do AutoNAT não é com o UPnP
        rt.on_autonat_unreachable();
        assert!(network_events(&mut rx).is_empty());

        rt.on_upnp_event(UpnpEvent::Mapped(vec!["/ip4/8.8.8.8/tcp/4001".parse().unwrap()]));
        network_events(&mut rx);
        rt.on_autonat_unreachable();
        rt.on_autonat_unreachable();
        assert_eq!(network_events(&mut rx), vec![NetworkEvent::UpnpUnreachable]);
        assert!(!rt.relay_manager.upnp_reachable());
    }
}
