//! Corrente de chaves do servidor (#99): quem é a Chave do Servidor em cada momento.
//!
//! Fica **fora** do registro de eventos e **nunca é consolidada**: qualquer membro valida a posse
//! desde a Genesis, partindo só do id do servidor (a primeira chave, K0). É pequena (elos raros) e
//! sempre sincronizada inteira.
//!
//! - **Renovação:** a chave em vigor estende a própria validade. Nada é vitalício: todo passaporte
//!   deixa de valer quando a raiz que o emitiu vence.
//! - **Transferência:** a chave em vigor passa a posse a uma chave nova (que assina a aceitação na
//!   máquina do novo dono). É um marco no tempo T: depois dele, elo emitido pela chave antiga só
//!   vale com carimbo de TSA anterior a T, e nada dela vale depois do vencimento.
//!
//! Cada elo é assinado pela chave em vigor, aponta para o elo anterior e precisa de carimbo de
//! **TSA** (testemunha não serve aqui: o horário dela é declarado por ela). Se a mesma chave assinar
//! dois elos sobre o mesmo anterior, vale o de carimbo mais antigo.

use super::chain::Genesis;
use super::passport::UtcSecs;
use super::timestamp::{verify_rfc3161, TimestampAttestation, TrustedTsa};
use crate::identity::{verify_signature_hex, UserIdentity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Validade padrão da chave raiz
pub const DEFAULT_ROOT_VALIDITY_SECS: u64 = 90 * 86_400;
/// Elo anterior do primeiro elo
pub const GENESIS_LINK: &str = "genesis";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum KeyLinkKind {
    /// A chave em vigor estende a própria validade
    Renew { valid_until: UtcSecs },
    /// A chave em vigor passa a posse para `new_key`. `previous_owner`/`new_owner` são as identidades
    /// pessoais de quem entrega e de quem recebe: o primeiro sai da lista de protegidos, o segundo entra.
    Transfer { new_key: String, valid_until: UtcSecs, previous_owner: Option<String>, new_owner: Option<String> },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyLinkBody {
    pub server_id: String,
    /// Id do elo anterior ([`GENESIS_LINK`] no primeiro)
    pub previous: String,
    /// Chave em vigor que assina este elo
    pub key: String,
    pub kind: KeyLinkKind,
}

/// Elo da corrente de chaves
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KeyLink {
    pub body: KeyLinkBody,
    /// Assinatura da chave em vigor
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
    /// Na transferência: assinatura da chave nova (aceitação)
    #[serde(default, with = "crate::b64")]
    pub new_key_signature: Vec<u8>,
    /// Carimbos de TSA sobre [`KeyLink::imprint`]
    #[serde(default)]
    pub stamps: Vec<TimestampAttestation>,
}

pub fn signing_bytes(body: &KeyLinkBody) -> Vec<u8> {
    crate::wire::signing_bytes("key-link", body)
}

impl KeyLink {
    /// Renovação assinada pela chave em vigor
    pub fn renew(key: &UserIdentity, server_id: &str, previous: &str, valid_until: UtcSecs) -> Self {
        let body = KeyLinkBody {
            server_id: server_id.to_string(),
            previous: previous.to_string(),
            key: key.public_key_hex(),
            kind: KeyLinkKind::Renew { valid_until },
        };
        let signature = key.sign(&signing_bytes(&body));
        Self { body, signature, new_key_signature: Vec::new(), stamps: Vec::new() }
    }

    /// Transferência: corpo já aceito (assinado) pela chave nova, assinado agora pela chave em vigor
    pub fn transfer(key: &UserIdentity, body: KeyLinkBody, new_key_signature: Vec<u8>) -> Self {
        let signature = key.sign(&signing_bytes(&body));
        Self { body, signature, new_key_signature, stamps: Vec::new() }
    }

    pub fn id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(signing_bytes(&self.body));
        hasher.update(&self.signature);
        hasher.update(&self.new_key_signature);
        hasher.finalize()[..16].iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn imprint(&self) -> [u8; 32] {
        let mut signatures = self.signature.clone();
        signatures.extend_from_slice(&self.new_key_signature);
        super::timestamp::imprint("key-link", &signing_bytes(&self.body), &signatures)
    }

    /// Assinaturas: a da chave em vigor e, na transferência, a da chave nova
    pub fn verify_signatures(&self, server_id: &str) -> bool {
        let bytes = signing_bytes(&self.body);
        self.body.server_id == server_id
            && verify_signature_hex(&self.body.key, &bytes, &self.signature)
            && match &self.body.kind {
                KeyLinkKind::Renew { .. } => true,
                KeyLinkKind::Transfer { new_key, .. } => new_key != &self.body.key && verify_signature_hex(new_key, &bytes, &self.new_key_signature),
            }
    }

    pub fn add_stamp(&mut self, stamp: TimestampAttestation) -> bool {
        if self.stamps.contains(&stamp) {
            return false;
        }
        self.stamps.push(stamp);
        true
    }

    /// Tempo do elo: o carimbo de TSA aceito mais antigo
    pub fn time(&self, tsas: &[TrustedTsa]) -> Option<UtcSecs> {
        let imprint = self.imprint();
        self.stamps
            .iter()
            .filter_map(|s| match s {
                TimestampAttestation::Rfc3161 { token_der, .. } => verify_rfc3161(token_der, &imprint, tsas).ok().map(|(at, _)| at),
                TimestampAttestation::Peer(_) => None,
            })
            .min()
    }
}

/// Chave raiz que emite passaportes
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RootKey {
    pub pubkey: String,
    /// Desde quando é a raiz em vigor (0 = Genesis)
    pub since: UtcSecs,
    /// Transferida em (marco T)
    pub until: Option<UtcSecs>,
    /// Vencimento da chave (renovável enquanto ela estiver em vigor)
    pub expires_at: UtcSecs,
}

/// Transferência aplicada (para a lista de protegidos)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedTransfer {
    pub at: UtcSecs,
    pub previous_owner: Option<String>,
    pub new_owner: Option<String>,
}

/// Posse resolvida a partir da corrente
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ownership {
    pub roots: Vec<RootKey>,
    pub transfers: Vec<AppliedTransfer>,
    /// Elos no caminho aceito, com o tempo de cada um
    pub path: Vec<(String, UtcSecs)>,
}

impl Ownership {
    /// Id do último elo aceito (onde o próximo deve se apoiar)
    pub fn head(&self) -> String {
        self.path.last().map_or_else(|| GENESIS_LINK.to_string(), |(id, _)| id.clone())
    }
}

/// Todos os elos conhecidos (inclusive os que perderam uma disputa); a posse é resolvida a partir deles
#[derive(Clone, Debug, Default)]
pub struct KeyChain {
    links: BTreeMap<String, KeyLink>,
}

impl KeyChain {
    pub fn links(&self) -> impl Iterator<Item = &KeyLink> {
        self.links.values()
    }

    pub fn contains(&self, id: &str) -> bool {
        self.links.contains_key(id)
    }

    /// Guarda um elo com assinaturas válidas (ou junta carimbos novos a um conhecido).
    /// Devolve `true` se algo mudou.
    pub fn insert(&mut self, link: KeyLink, server_id: &str) -> bool {
        if !link.verify_signatures(server_id) {
            return false;
        }
        match self.links.get_mut(&link.id()) {
            Some(known) => link.stamps.into_iter().fold(false, |changed, s| known.add_stamp(s) || changed),
            None => {
                self.links.insert(link.id(), link);
                true
            }
        }
    }

    /// Resolve a posse: parte da Genesis e segue, a cada passo, o elo assinado pela chave em vigor
    /// com o carimbo de TSA mais antigo (posterior ao elo anterior)
    pub fn resolve(&self, genesis: &Genesis, tsas: &[TrustedTsa]) -> Ownership {
        let server_id = &genesis.body.server_id;
        let mut ownership = Ownership {
            roots: vec![RootKey { pubkey: server_id.clone(), since: 0, until: None, expires_at: genesis.body.root_valid_until }],
            ..Ownership::default()
        };
        let mut head = GENESIS_LINK.to_string();
        let mut head_time: UtcSecs = 0;
        loop {
            let current = ownership.roots.last().expect("sempre há uma raiz").pubkey.clone();
            let next = self
                .links
                .iter()
                .filter(|(_, l)| l.body.previous == head && l.body.key == current && l.body.server_id == *server_id)
                .filter_map(|(id, l)| l.time(tsas).filter(|t| *t >= head_time).map(|t| (t, id.clone(), l)))
                .min_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
            let Some((at, id, link)) = next else { break };
            match &link.body.kind {
                KeyLinkKind::Renew { valid_until } => {
                    let root = ownership.roots.last_mut().expect("sempre há uma raiz");
                    root.expires_at = root.expires_at.max(*valid_until);
                }
                KeyLinkKind::Transfer { new_key, valid_until, previous_owner, new_owner } => {
                    ownership.roots.last_mut().expect("sempre há uma raiz").until = Some(at);
                    ownership.roots.push(RootKey { pubkey: new_key.clone(), since: at, until: None, expires_at: *valid_until });
                    ownership.transfers.push(AppliedTransfer { at, previous_owner: previous_owner.clone(), new_owner: new_owner.clone() });
                }
            }
            ownership.path.push((id.clone(), at));
            head = id;
            head_time = at;
        }
        ownership
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::community::chain::{default_config, Genesis};
    use crate::community::timestamp::{test_tsa::LocalTsa, TimestampPolicy};

    const T0: u64 = 1_800_000_000;

    fn genesis(key: &UserIdentity, tsa: &LocalTsa) -> Genesis {
        let policy = TimestampPolicy { tsas: vec![tsa.trusted("local")], max_delay_secs: 600 };
        Genesis::create(key, default_config("S", "dono", Vec::new(), policy), T0)
    }

    fn stamped(mut link: KeyLink, tsa: &LocalTsa, at: u64) -> KeyLink {
        link.add_stamp(tsa.stamp(&link.imprint(), at));
        link
    }

    fn transfer(from: &UserIdentity, to: &UserIdentity, server_id: &str, previous: &str) -> KeyLink {
        let body = KeyLinkBody {
            server_id: server_id.to_string(),
            previous: previous.to_string(),
            key: from.public_key_hex(),
            kind: KeyLinkKind::Transfer { new_key: to.public_key_hex(), valid_until: T0 + 1000, previous_owner: None, new_owner: None },
        };
        let acceptance = to.sign(&signing_bytes(&body));
        KeyLink::transfer(from, body, acceptance)
    }

    #[test]
    fn test_renewal_and_transfer_resolve_from_genesis() {
        let tsa = LocalTsa::new();
        let k0 = UserIdentity::generate();
        let g = genesis(&k0, &tsa);
        let id = k0.public_key_hex();
        let tsas = [tsa.trusted("local")];
        let mut chain = KeyChain::default();
        assert_eq!(chain.resolve(&g, &tsas).roots[0].expires_at, T0 + DEFAULT_ROOT_VALIDITY_SECS);

        let renew = stamped(KeyLink::renew(&k0, &id, GENESIS_LINK, T0 + 200 * 86_400), &tsa, T0 + 10);
        assert!(chain.insert(renew.clone(), &id));
        let k1 = UserIdentity::generate();
        let t = stamped(transfer(&k0, &k1, &id, &renew.id()), &tsa, T0 + 20);
        assert!(chain.insert(t, &id));
        let o = chain.resolve(&g, &tsas);
        assert_eq!(o.roots.len(), 2);
        assert_eq!(o.roots[0].expires_at, T0 + 200 * 86_400, "renovada");
        assert_eq!(o.roots[0].until, Some(T0 + 20), "marco da transferência");
        assert_eq!(o.roots[1].pubkey, k1.public_key_hex());

        // A chave antiga não assina mais nada depois do marco
        let late = stamped(KeyLink::renew(&k0, &id, &o.head(), T0 + 400 * 86_400), &tsa, T0 + 30);
        chain.insert(late, &id);
        assert_eq!(chain.resolve(&g, &tsas), o);
    }

    #[test]
    fn test_link_needs_tsa_stamp_and_both_signatures() {
        let tsa = LocalTsa::new();
        let k0 = UserIdentity::generate();
        let g = genesis(&k0, &tsa);
        let id = k0.public_key_hex();
        let tsas = [tsa.trusted("local")];
        let mut chain = KeyChain::default();
        let k1 = UserIdentity::generate();
        // Sem carimbo de TSA aceito, o elo não conta
        chain.insert(transfer(&k0, &k1, &id, GENESIS_LINK), &id);
        chain.insert(stamped(transfer(&k0, &k1, &id, GENESIS_LINK), &LocalTsa::new(), T0 + 5), &id);
        assert_eq!(chain.resolve(&g, &tsas).roots.len(), 1);
        // Aceitação assinada por outra chave: recusado
        let mut forged = transfer(&k0, &k1, &id, GENESIS_LINK);
        forged.new_key_signature = UserIdentity::generate().sign(&signing_bytes(&forged.body));
        assert!(!chain.insert(forged, &id));
        // Assinado por quem não é a chave em vigor: ignorado
        let intruder = UserIdentity::generate();
        chain.insert(stamped(transfer(&intruder, &k1, &id, GENESIS_LINK), &tsa, T0 + 5), &id);
        assert_eq!(chain.resolve(&g, &tsas).roots.len(), 1);
    }

    /// A mesma chave assina duas transferências: vale a de carimbo mais antigo
    #[test]
    fn test_fork_resolved_by_earliest_stamp() {
        let tsa = LocalTsa::new();
        let k0 = UserIdentity::generate();
        let g = genesis(&k0, &tsa);
        let id = k0.public_key_hex();
        let tsas = [tsa.trusted("local")];
        let (b, c) = (UserIdentity::generate(), UserIdentity::generate());
        let mut chain = KeyChain::default();
        chain.insert(stamped(transfer(&k0, &c, &id, GENESIS_LINK), &tsa, T0 + 50), &id);
        chain.insert(stamped(transfer(&k0, &b, &id, GENESIS_LINK), &tsa, T0 + 10), &id);
        assert_eq!(chain.resolve(&g, &tsas).roots[1].pubkey, b.public_key_hex());
    }
}
