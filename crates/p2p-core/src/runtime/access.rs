//! Pedidos de acesso a servidores (#91).
//!
//! Cada servidor tem um tópico de pedidos (`.../server/<id>/access`). Quem não tem passaporte se
//! inscreve nele e publica o pedido **uma vez**; quem pode emitir passaporte (dono e moderadores
//! com `IssueMember`) fica inscrito sempre. A própria inscrição é o pedido: um moderador que chega
//! depois vê quem está esperando sem que ninguém reenvie nada. Como o Gossipsub só mostra a
//! inscrição de pares conectados diretamente, o pedido é republicado quando alguém novo entra no
//! tópico (no máximo a cada 30 s) ou a cada 10 minutos.
//!
//! Do lado de quem emite: lista de pendentes, aviso uma vez por pessoa (repete no máximo a cada
//! 30 minutos) e, em servidor público, emissão automática como antes.

use super::{AccessRequestEntry, CoreEvent, Runtime, ServerNotice};
use crate::community::access_proof::{self, AccessProof, AccessProofBody};
use crate::community::{self, timestamp, PassportPermission, ServerMessage, TimestampAttestation, TrustedTsa};
use libp2p::gossipsub::IdentTopic;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

/// Republicação do pedido de quem espera, se ninguém respondeu
const REQUEST_REPUBLISH_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Alguém novo entrou no tópico (talvez um moderador sem conexão direta antes): republica, no máximo nesse ritmo
const REQUEST_ON_NEW_SUBSCRIBER_INTERVAL: Duration = Duration::from_secs(30);
/// Aviso "X pediu acesso" repetido no máximo nesse intervalo por pessoa
const NOTIFY_AGAIN_AFTER: Duration = Duration::from_secs(30 * 60);
/// Espera crescente do pedido de cadeia de quem ainda não a tem
const CHAIN_REQUEST_FIRST_INTERVAL: Duration = Duration::from_secs(20);
const CHAIN_REQUEST_MAX_INTERVAL: Duration = Duration::from_secs(5 * 60);

#[derive(Default)]
pub(super) struct AccessState {
    /// Servidores em cujo tópico de pedidos estamos inscritos
    subscribed: HashSet<String>,
    /// Quem pede: último pedido publicado, por servidor
    last_request: HashMap<String, Instant>,
    /// Quem emite: pendentes por servidor (pubkey -> visto pela primeira vez, UTC)
    pending: HashMap<String, BTreeMap<String, u64>>,
    /// Último aviso por (servidor, pubkey)
    notified: HashMap<(String, String), Instant>,
    /// Pedidos dispensados localmente
    dismissed: HashSet<(String, String)>,
    /// Pedido de cadeia: (próximo envio, intervalo atual), por servidor
    chain_backoff: HashMap<String, (Instant, Duration)>,
    /// Quem pede: prova de trabalho pronta (e quando ficou pronta), por servidor
    proofs: HashMap<String, (AccessProof, Instant)>,
    /// Quem pede: servidores com prova sendo calculada
    computing: HashSet<String>,
    /// Quem pede: semente à espera de carimbo de testemunha (sem TSA): hash -> (servidor, semente, bits)
    seed_waiting: HashMap<[u8; 32], (String, String, u8)>,
    /// Quem emite: último pedido recebido por mensagem, por (servidor, pubkey) (limite de taxa)
    last_request_from: HashMap<(String, String), Instant>,
    /// Quem emite: última política enviada a quem pediu sem prova, por (servidor, pubkey)
    policy_sent: HashMap<(String, String), Instant>,
    /// Testemunha: último carimbo dado a quem não é membro, por pubkey (limite de taxa)
    stamps_to_strangers: HashMap<String, Instant>,
}

/// Prova de trabalho calculada fora do loop de eventos
pub(super) struct PowResult {
    server_id: String,
    result: Result<AccessProofBody, String>,
}

/// Pedido de acesso repetido do mesmo par é ignorado nesse intervalo (a não ser que traga prova nova)
const REQUEST_RATE_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// Política reenviada a quem continua pedindo sem prova (a primeira resposta pode se perder)
const POLICY_RESEND_INTERVAL: Duration = Duration::from_secs(30);
/// Testemunha dá no máximo um carimbo por minuto a quem não é membro
const STRANGER_STAMP_INTERVAL: Duration = Duration::from_secs(60);
/// Prova pronta é reaproveitada enquanto o carimbo dela ainda for recente (com margem)
const PROOF_REUSE: Duration = Duration::from_secs(access_proof::MAX_PROOF_AGE_SECS - 120);

impl Runtime {
    /// Este nó pode emitir passaporte de membro neste servidor
    fn can_issue_passports(&self, server_id: &str, now: u64) -> bool {
        self.servers.get(server_id).is_some_and(|s| {
            s.is_owner()
                || (s.has_chain()
                    && s.my_passport().is_some_and(|p| {
                        p.allows(PassportPermission::IssueMember) && s.effective_state(now).verify_passport(p, now).is_ok()
                    }))
        })
    }

    /// Ainda não participamos (sem cadeia ou sem passaporte válido): pedimos acesso
    fn wants_access(&self, server_id: &str, now: u64) -> bool {
        let me = self.my_pubkey();
        self.servers.get(server_id).is_some_and(|s| !s.is_owner() && !(s.has_chain() && s.is_allowed(&me, now)))
    }

    /// Ajusta as inscrições nos tópicos de pedidos: quem pede e quem emite ficam inscritos; os
    /// demais saem. Quem pede publica o pedido ao se inscrever e a cada 10 minutos.
    pub(super) fn sync_access_topics(&mut self) {
        let now = super::now_secs();
        let known: Vec<String> = self.servers.list().map(|s| s.server_id.clone()).collect();
        let stale: Vec<String> = self.access.subscribed.iter().filter(|id| !known.contains(id)).cloned().collect();
        for id in stale {
            self.set_access_subscription(&id, false);
        }
        for id in known {
            let wants = self.wants_access(&id, now);
            let wanted = wants || self.can_issue_passports(&id, now);
            let newly = wanted && !self.access.subscribed.contains(&id);
            if wanted != self.access.subscribed.contains(&id) {
                self.set_access_subscription(&id, wanted);
            }
            // Já temos a cadeia e ela exige prova: calcula a prova sem esperar a política de ninguém
            let chain_policy = self
                .servers
                .get(&id)
                .filter(|s| s.has_chain())
                .map(|s| s.effective_state(now))
                .filter(|state| state.access_pow_bits > 0)
                .map(|state| (state.access_pow_bits, state.timestamp_policy.tsas.clone()));
            if let (true, Some((bits, tsas))) = (wants, chain_policy) {
                self.on_access_policy(&id, bits, tsas);
            }
            if !wants {
                self.access.last_request.remove(&id);
            } else if newly || self.access.last_request.get(&id).is_none_or(|t| t.elapsed() >= REQUEST_REPUBLISH_INTERVAL) {
                self.send_access_request(&id);
            }
        }
    }

    fn set_access_subscription(&mut self, server_id: &str, subscribe: bool) {
        let topic = IdentTopic::new(community::access_topic(server_id));
        let gossipsub = &mut self.node.swarm.behaviour_mut().gossipsub;
        if subscribe {
            let _ = gossipsub.subscribe(&topic);
            self.access.subscribed.insert(server_id.to_string());
        } else {
            let _ = gossipsub.unsubscribe(&topic);
            self.access.subscribed.remove(server_id);
            self.access.pending.remove(server_id);
        }
    }

    /// Publica o pedido de acesso no tópico de pedidos (sem ninguém lá, tenta de novo quando alguém entrar)
    fn send_access_request(&mut self, server_id: &str) {
        // Prova pronta e ainda recente vai junto (servidor que exige prova)
        let proof = self
            .access
            .proofs
            .get(server_id)
            .filter(|(_, at)| at.elapsed() < PROOF_REUSE)
            .map(|(proof, _)| proof.clone());
        let topic = IdentTopic::new(community::access_topic(server_id));
        let message = ServerMessage::AccessRequest { server_id: server_id.to_string(), proof };
        let sent = self.publish_gossip(topic, crate::wire::encode(&message));
        if sent.is_ok() {
            self.access.last_request.insert(server_id.to_string(), Instant::now());
        }
    }

    /// Quem pede recebeu a política de um servidor que exige prova: calcula a prova (carimbo de
    /// TSA de uma semente aleatória e depois o trabalho, numa thread) e pede de novo com ela
    pub(super) fn on_access_policy(&mut self, server_id: &str, bits: u8, tsas: Vec<TrustedTsa>) {
        let now = super::now_secs();
        let has_fresh = self.access.proofs.get(server_id).is_some_and(|(_, at)| at.elapsed() < PROOF_REUSE);
        if bits == 0 || !self.wants_access(server_id, now) || has_fresh || self.access.computing.contains(server_id) {
            return;
        }
        let bits = bits.min(access_proof::MAX_POW_BITS);
        self.access.computing.insert(server_id.to_string());
        self.notice(ServerNotice::AccessProofComputing { server: self.server_name(server_id), bits });
        let seed = timestamp::hex(&rand::random::<[u8; 16]>());
        let me = self.my_pubkey();
        let imprint = access_proof::seed_imprint(server_id, &me, &seed);
        // Sem TSA que responda, a semente vai para uma testemunha (rede local)
        self.access.seed_waiting.insert(imprint, (server_id.to_string(), seed.clone(), bits));
        let tx = self.pow_tx.clone();
        let server = server_id.to_string();
        std::thread::spawn(move || {
            let stamp = tsas.iter().find_map(|tsa| timestamp::fetch_rfc3161(tsa, &imprint).ok());
            let result = match stamp {
                Some(stamp) => Ok(access_proof::compute(&server, &me, &seed, stamp, bits)),
                None => Err("nenhuma autoridade de tempo respondeu".to_string()),
            };
            let _ = tx.send(PowResult { server_id: server, result });
        });
    }

    /// Carimbo de testemunha chegou para uma semente nossa: calcula a prova com ele
    fn compute_with_witness_stamp(&mut self, imprint: &[u8; 32], stamp: TimestampAttestation) {
        let Some((server_id, seed, bits)) = self.access.seed_waiting.remove(imprint) else { return };
        let me = self.my_pubkey();
        let tx = self.pow_tx.clone();
        std::thread::spawn(move || {
            let body = access_proof::compute(&server_id, &me, &seed, stamp, bits);
            let _ = tx.send(PowResult { server_id, result: Ok(body) });
        });
    }

    /// Prova calculada (ou falhou a obtenção do carimbo da TSA)
    pub(super) fn on_pow_result(&mut self, result: PowResult) {
        let PowResult { server_id, result } = result;
        match result {
            Ok(body) => {
                self.access.computing.remove(&server_id);
                self.access.seed_waiting.retain(|_, (id, _, _)| *id != server_id);
                let proof = AccessProof::sign(&self.identity, body);
                self.access.proofs.insert(server_id.clone(), (proof, Instant::now()));
                self.send_access_request(&server_id);
            }
            Err(reason) => {
                // Sem TSA: pede o carimbo da semente a uma testemunha, pelo tópico de pedidos
                let waiting = self.access.seed_waiting.iter().find(|(_, (id, _, _))| *id == server_id).map(|(imprint, _)| *imprint);
                if let Some(imprint) = waiting {
                    let message = ServerMessage::StampRequest {
                        server_id: server_id.clone(),
                        imprint: timestamp::hex(&imprint),
                        nonce: timestamp::hex(&rand::random::<[u8; 8]>()),
                    };
                    let _ = self.publish_gossip(IdentTopic::new(community::access_topic(&server_id)), crate::wire::encode(&message));
                }
                self.access.computing.remove(&server_id);
                self.notice(ServerNotice::AccessProofFailed { server: self.server_name(&server_id), reason });
            }
        }
    }

    /// Carimbo recebido: se for de uma semente nossa à espera, vira prova. Devolve `true` se era.
    pub(super) fn on_access_stamp(&mut self, imprint: &str, stamp: &TimestampAttestation) -> bool {
        let Some(imprint) = community::parse_imprint(imprint) else { return false };
        if !self.access.seed_waiting.contains_key(&imprint) {
            return false;
        }
        self.compute_with_witness_stamp(&imprint, stamp.clone());
        true
    }

    /// Testemunha: carimbo para quem ainda não é membro só uma vez por minuto por pessoa, e só pela
    /// testemunha de menor pubkey entre os membros no tópico de pedidos (um estranho não recebe N carimbos)
    pub(super) fn may_stamp_for_stranger(&mut self, server_id: &str, from: &str) -> bool {
        let now = super::now_secs();
        let Some(server) = self.servers.get(server_id).filter(|s| s.has_chain()) else { return false };
        if server.is_allowed(from, now) {
            return true;
        }
        if self.access.stamps_to_strangers.get(from).is_some_and(|t| t.elapsed() < STRANGER_STAMP_INTERVAL) {
            return false;
        }
        let me = self.my_pubkey();
        let topic = IdentTopic::new(community::access_topic(server_id)).hash();
        let smaller_member_present = self.peer_topics.iter().any(|(peer, topics)| {
            topics.contains(&topic)
                && self.peer_metadata.get(peer).is_some_and(|(_, pk)| *pk < me && server.is_allowed(pk, now))
        });
        if smaller_member_present {
            return false;
        }
        self.access.stamps_to_strangers.insert(from.to_string(), Instant::now());
        true
    }

    /// Alguém entrou no tópico de pedidos de um servidor
    pub(super) fn on_access_topic_subscribed(&mut self, server_id: &str, pubkey: Option<String>) {
        let now = super::now_secs();
        // Quem pede: pode ter chegado um moderador que não via nossa inscrição
        if self.access.subscribed.contains(server_id)
            && self.wants_access(server_id, now)
            && self.access.last_request.get(server_id).is_none_or(|t| t.elapsed() >= REQUEST_ON_NEW_SUBSCRIBER_INTERVAL)
        {
            self.send_access_request(server_id);
        }
        // Quem emite: a inscrição já é o pedido
        if let Some(pubkey) = pubkey {
            self.note_access_request(server_id, &pubkey, None, false);
        }
    }

    /// Governança mudou (ex.: ban desfeito): quem já está inscrito no tópico de pedidos não se
    /// inscreve de novo, então a inscrição de cada um é reavaliada como um pedido novo
    pub(super) fn recheck_access_subscribers(&mut self, server_id: &str) {
        if !self.access.subscribed.contains(server_id) || !self.can_issue_passports(server_id, super::now_secs()) {
            return;
        }
        let topic = IdentTopic::new(community::access_topic(server_id)).hash();
        let subscribers: Vec<String> = self
            .node
            .swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .filter(|(_, topics)| topics.contains(&&topic))
            .filter_map(|(peer, _)| crate::api::pubkey_hex_from_peer_id(peer))
            .collect();
        for pubkey in subscribers {
            self.note_access_request(server_id, &pubkey, None, false);
        }
    }

    /// Alguém saiu do tópico de pedidos (recebeu passaporte ou desistiu)
    pub(super) fn on_access_topic_unsubscribed(&mut self, server_id: &str, pubkey: Option<String>) {
        let removed = pubkey.is_some_and(|pk| self.access.pending.get_mut(server_id).is_some_and(|p| p.remove(&pk).is_some()));
        if removed {
            self.emit_access_requests();
        }
    }

    /// Pedido de acesso visto por quem pode emitir (mensagem ou inscrição no tópico)
    pub(super) fn note_access_request(&mut self, server_id: &str, from: &str, proof: Option<&AccessProof>, by_message: bool) {
        let now = super::now_secs();
        if from == self.my_pubkey() || !self.can_issue_passports(server_id, now) {
            return;
        }
        let key = (server_id.to_string(), from.to_string());
        // Limite de taxa: um pedido por mensagem a cada 10 minutos por pessoa (prova nova passa)
        if by_message {
            let repeated = self.access.last_request_from.get(&key).is_some_and(|t| t.elapsed() < REQUEST_RATE_INTERVAL);
            if repeated && proof.is_none() {
                return;
            }
            self.access.last_request_from.insert(key.clone(), Instant::now());
        }
        // Servidor que exige prova de trabalho: sem prova válida, só recebe a política (uma vez a cada 10 min)
        if self.servers.access_proof_ok(server_id, from, proof, now) == Some(false) {
            if self.access.policy_sent.get(&key).is_none_or(|t| t.elapsed() >= POLICY_RESEND_INTERVAL) {
                if let Some(policy) = self.servers.access_policy(server_id, now) {
                    self.access.policy_sent.insert(key, Instant::now());
                    let _ = self.publish_gossip(IdentTopic::new(community::access_topic(server_id)), crate::wire::encode(&policy));
                }
            }
            return;
        }
        // Servidor público (ou reenvio a quem já tem passaporte): responde na hora
        if let Some(offer) = self.servers.answer_access_request(server_id, &self.identity, from, now) {
            if let ServerMessage::PassportOffer { passport, .. } = &offer {
                // Só pede carimbo para passaporte recém-emitido (reenvio já tem os seus)
                let fresh = self
                    .servers
                    .get_mut(server_id)
                    .is_some_and(|s| s.passport_of(&passport.body.holder) != Some(passport) && s.remember_issued(passport, now));
                let imprint = passport.imprint();
                // Pelo tópico de pedidos (onde quem pediu comprovadamente está; a inscrição dele no
                // de controle pode ainda não ser conhecida) e pelo de controle
                let access = IdentTopic::new(community::access_topic(server_id));
                let _ = self.publish_gossip(access, crate::wire::encode(&offer));
                self.publish_server_message(server_id, &offer);
                if fresh {
                    self.request_stamps(server_id, imprint);
                }
            }
            return;
        }
        let Some(server) = self.servers.get(server_id).filter(|s| s.has_chain()) else { return };
        if !server.chain().state().closed || server.is_allowed(from, now) || server.is_banned(from, now) || self.access.dismissed.contains(&key) {
            return;
        }
        let pending = self.access.pending.entry(server_id.to_string()).or_default();
        let added = !pending.contains_key(from);
        pending.entry(from.to_string()).or_insert(now);
        if self.access.notified.get(&key).is_none_or(|t| t.elapsed() >= NOTIFY_AGAIN_AFTER) {
            self.access.notified.insert(key, Instant::now());
            self.notice(ServerNotice::AccessRequested { server: self.server_name(server_id), who: self.nick_for(from) });
        }
        if added {
            self.emit_access_requests();
        }
    }

    /// Lista de pedidos pendentes do servidor atual, para a interface (só para quem pode emitir).
    /// Tira da lista quem já recebeu passaporte ou foi banido.
    pub(super) fn emit_access_requests(&mut self) {
        self.emit_access_requests_as(false);
    }

    /// Lista pedida pelo usuário (`/server requests`): aparece também na aba Sistema
    pub(super) fn show_access_requests(&mut self) {
        self.emit_access_requests_as(true);
    }

    fn emit_access_requests_as(&mut self, explicit: bool) {
        let now = super::now_secs();
        let Some(server_id) = self.active.server_id().map(str::to_string) else { return };
        if !self.can_issue_passports(&server_id, now) {
            return;
        }
        if let (Some(server), Some(pending)) = (self.servers.get(&server_id), self.access.pending.get_mut(&server_id)) {
            pending.retain(|pk, _| !server.is_allowed(pk, now) && !server.is_banned(pk, now));
        }
        let mut requests: Vec<AccessRequestEntry> = self
            .access
            .pending
            .get(&server_id)
            .into_iter()
            .flatten()
            .map(|(pubkey, since)| AccessRequestEntry { nick: self.nick_for(pubkey), pubkey: pubkey.clone(), since: *since })
            .collect();
        requests.sort_by_key(|r| r.since);
        let server = self.server_name(&server_id);
        self.emit(CoreEvent::Server(ServerNotice::AccessRequests { server_id, server, requests, explicit }));
    }

    /// Tira um pedido da lista local (não bane; a pessoa pode pedir de novo mais tarde)
    pub(super) fn dismiss_access_request(&mut self, server_id: &str, pubkey: &str) {
        self.access.dismissed.insert((server_id.to_string(), pubkey.to_string()));
        if let Some(pending) = self.access.pending.get_mut(server_id) {
            pending.remove(pubkey);
        }
        self.emit_access_requests();
    }

    /// Quem ainda não tem a cadeia pede com espera crescente (20 s, 40 s… até 5 min)
    pub(super) fn chain_request_due(&mut self, server_id: &str) -> bool {
        let now = Instant::now();
        match self.access.chain_backoff.get_mut(server_id) {
            Some((next, _)) if now < *next => false,
            Some((next, interval)) => {
                *interval = (*interval * 2).min(CHAIN_REQUEST_MAX_INTERVAL);
                *next = now + *interval;
                true
            }
            None => {
                self.access.chain_backoff.insert(server_id.to_string(), (now + CHAIN_REQUEST_FIRST_INTERVAL, CHAIN_REQUEST_FIRST_INTERVAL));
                true
            }
        }
    }

    /// Entrar de novo pelo comando recomeça a espera do pedido de cadeia
    pub(super) fn reset_chain_backoff(&mut self, server_id: &str) {
        self.access.chain_backoff.remove(server_id);
    }
}
