//! Sistema de configuração agnóstico ao sistema operacional (Windows, Linux, macOS, Android, iOS).
//!
//! Controla limites locais de recursos (como armazenamento em disco e TTL da Mailbox offline)
//! e opções padrão de rede, persistidos em `config.json`.

use crate::community::parse_duration;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const SECS_PER_DAY: u64 = 86_400;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Erro de I/O na configuração: {0}")]
    Io(#[from] std::io::Error),
    #[error("Erro de serialização JSON na configuração: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Chave ou valor de configuração inválido: {0}")]
    InvalidSetting(String),
}

/// Configuração da Mailbox local (guardião de mensagens offline para amigos)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub struct MailboxConfig {
    /// Habilitar serviço de guardião de mensagens offline para amigos
    pub enabled: bool,
    /// Limite máximo total de disco alocado para guardar mensagens offline (em Megabytes)
    pub max_storage_mb: u64,
    /// Limite de cota de armazenamento por amigo (em Megabytes)
    pub max_storage_per_friend_mb: u64,
    /// Tempo de vida máximo padrão/teto que este nó aceita guardar mensagens (em dias)
    pub max_message_ttl_days: u32,
    /// Tamanho máximo de um único envelope/anexo offline (em Kilobytes)
    pub max_envelope_size_kb: u32,
}

impl Default for MailboxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_storage_mb: 50,
            max_storage_per_friend_mb: 5,
            max_message_ttl_days: 7,
            max_envelope_size_kb: 256,
        }
    }
}

/// Configuração padrão de rede do nó
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub struct NetworkConfig {
    pub default_channel: String,
    pub auto_bootstrap: bool,
    pub max_peers: usize,
    pub listen_port: u16,
    /// Pede ao roteador (UPnP) que encaminhe a porta de escuta (#101). Vale na próxima inicialização
    pub upnp: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            default_channel: "geral".to_string(),
            auto_bootstrap: true,
            max_peers: 50,
            listen_port: 0,
            upnp: true,
        }
    }
}

/// Configuração de políticas de Mensagens Diretas (DM) e Firewall de proteção diferenciada (Amigos vs Desconhecidos)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub struct DmPolicyConfig {
    /// Permitir receber DMs de quem não está na sua lista local de amigos
    pub allow_strangers: bool,
    /// Enviar 1 mensagem de cortesia E2EE avisando o remetente quando for bloqueado pelo firewall
    pub send_courtesy_notice: bool,
    /// Limite de DMs por minuto vindas de um amigo (na sua lista local)
    pub friend_rate_limit_per_min: u32,
    /// Limite de DMs por minuto vindas de um desconhecido (fora da sua lista local)
    pub stranger_rate_limit_per_min: u32,
    /// Tamanho máximo do texto de DM vindo de um amigo (em bytes)
    pub friend_max_message_bytes: usize,
    /// Tamanho máximo do texto de DM vindo de um desconhecido (em bytes)
    pub stranger_max_message_bytes: usize,
    /// Limite de mensagens offline (vindas da Mailbox) que aceita abrir de um mesmo desconhecido por hora
    pub stranger_offline_limit_per_hour: u32,
}

impl Default for DmPolicyConfig {
    fn default() -> Self {
        Self {
            allow_strangers: true,
            send_courtesy_notice: true,
            friend_rate_limit_per_min: 30,
            stranger_rate_limit_per_min: 3,
            friend_max_message_bytes: 8192,
            stranger_max_message_bytes: 1024,
            stranger_offline_limit_per_hour: 3,
        }
    }
}

/// Configuração do Firewall unificado do nó (`NodeFirewall` - Issue #48)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub struct FirewallConfig {
    /// Isentar amigos (na sua lista local) dos limites de taxa de chat, controle e chunks
    pub exempt_friends: bool,
    /// Quando o nó atua como servidor de Circuit Relay v2, aceitar reservas e circuitos apenas de amigos
    pub relay_friends_only: bool,
    /// Limite de mensagens de chat por 10s para um amigo
    pub friend_chat_per_10s: u32,
    /// Limite de mensagens de chat por 10s para um desconhecido
    pub stranger_chat_per_10s: u32,
    /// Limite de mensagens de controle (ChainRequest, KeyPackage, Subscribe, FileOffer, Peers) por 10s para amigo
    pub friend_control_per_10s: u32,
    /// Limite de mensagens de controle por 10s para desconhecido
    pub stranger_control_per_10s: u32,
    /// Limite de pedidos de pedaços de arquivo (ChunkRequest) por 10s para amigo
    pub friend_chunk_reqs_per_10s: u32,
    /// Limite de pedidos de pedaços de arquivo (ChunkRequest) por 10s para desconhecido
    pub stranger_chunk_reqs_per_10s: u32,
    /// Limite de pacotes inválidos (assinatura falsa, formato corrompido ou tamanho excessivo) por minuto
    pub invalid_packets_per_min: u32,
    /// Disjuntor global (Under Attack): limite máximo de pacotes por 10s somando todos os desconhecidos
    pub stranger_global_msgs_per_10s: u32,
    /// Limite máximo de conexões simultâneas vindas do mesmo IP externo para desconhecidos
    pub max_connections_per_ip: usize,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            exempt_friends: false,
            relay_friends_only: false,
            friend_chat_per_10s: 60,
            stranger_chat_per_10s: 15,
            friend_control_per_10s: 60,
            stranger_control_per_10s: 15,
            friend_chunk_reqs_per_10s: 500,
            stranger_chunk_reqs_per_10s: 150,
            invalid_packets_per_min: 3,
            stranger_global_msgs_per_10s: 200,
            max_connections_per_ip: 8,
        }
    }
}

/// Configuração completa do nó Anarchord
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(default)]
pub struct NodeConfig {
    pub version: u32,
    pub network: NetworkConfig,
    pub mailbox: MailboxConfig,
    pub dm: DmPolicyConfig,
    pub firewall: FirewallConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            version: 1,
            network: NetworkConfig::default(),
            mailbox: MailboxConfig::default(),
            dm: DmPolicyConfig::default(),
            firewall: FirewallConfig::default(),
        }
    }
}

impl NodeConfig {
    /// Resolve o caminho padrão multiplataforma do `config.json`:
    /// - Windows: `%APPDATA%\anarchord\config.json`
    /// - macOS: `~/Library/Application Support/anarchord/config.json`
    /// - Linux / Unix: `$XDG_CONFIG_HOME/anarchord/config.json` ou `~/.config/anarchord/config.json`
    /// - Fallback (Android/iOS/ambientes restritos): `./config.json`
    pub fn default_path() -> PathBuf {
        if cfg!(target_os = "windows") {
            if let Ok(appdata) = std::env::var("APPDATA") {
                return PathBuf::from(appdata).join("anarchord").join("config.json");
            }
        } else if cfg!(target_os = "macos") {
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(home)
                    .join("Library")
                    .join("Application Support")
                    .join("anarchord")
                    .join("config.json");
            }
        } else {
            if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
                if !xdg.is_empty() {
                    return PathBuf::from(xdg).join("anarchord").join("config.json");
                }
            }
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(home).join(".config").join("anarchord").join("config.json");
            }
        }
        PathBuf::from("config.json")
    }

    /// Carrega a configuração do disco ou cria com os valores padrão se não existir
    pub fn load_or_default(path: Option<&Path>) -> Result<Self, ConfigError> {
        let target = path.map(PathBuf::from).unwrap_or_else(Self::default_path);
        if target.exists() {
            let bytes = fs::read(&target)?;
            let cfg: Self = serde_json::from_slice(&bytes)?;
            Ok(cfg)
        } else {
            let cfg = Self::default();
            // Tenta salvar no primeiro boot; se o diretório não for gravável, segue em memória
            let _ = cfg.save(Some(&target));
            Ok(cfg)
        }
    }

    /// Salva a configuração em formato JSON legível
    pub fn save(&self, path: Option<&Path>) -> Result<(), ConfigError> {
        let target = path.map(PathBuf::from).unwrap_or_else(Self::default_path);
        if let Some(parent) = target.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&target, json)?;
        Ok(())
    }

    /// Teto máximo de TTL deste nó em segundos
    pub fn max_ttl_secs(&self) -> u64 {
        (self.mailbox.max_message_ttl_days as u64).saturating_mul(SECS_PER_DAY)
    }

    /// Calcula o TTL efetivo segundo a Regra do Menor Tempo:
    /// `TTL_Efetivo = min(sugerido_pelo_remetente, max_local_do_guardiao)`
    pub fn calculate_effective_ttl(&self, requested_ttl_secs: Option<u64>) -> u64 {
        let max_local = self.max_ttl_secs();
        match requested_ttl_secs {
            Some(req) if req > 0 => req.min(max_local),
            _ => max_local,
        }
    }

    /// Limite total da mailbox em bytes
    pub fn max_storage_bytes(&self) -> u64 {
        self.mailbox.max_storage_mb.saturating_mul(1024 * 1024)
    }

    /// Limite por amigo na mailbox em bytes
    pub fn max_friend_storage_bytes(&self) -> u64 {
        self.mailbox.max_storage_per_friend_mb.saturating_mul(1024 * 1024)
    }

    /// Limite de um envelope individual em bytes
    pub fn max_envelope_bytes(&self) -> usize {
        (self.mailbox.max_envelope_size_kb as usize).saturating_mul(1024)
    }

    /// Altera uma chave de configuração via string (`chave`, `valor`)
    pub fn set_key(&mut self, key: &str, value: &str) -> Result<(), ConfigError> {
        let val = value.trim();
        match key.trim() {
            "mailbox.enabled" => {
                self.mailbox.enabled = match val {
                    "true" | "1" | "on" | "sim" => true,
                    "false" | "0" | "off" | "nao" | "não" => false,
                    _ => return Err(ConfigError::InvalidSetting(format!("booleano inválido: {}", val))),
                };
            }
            "mailbox.max_storage_mb" => {
                let n: u64 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("max_storage_mb deve ser > 0".into()));
                }
                self.mailbox.max_storage_mb = n;
            }
            "mailbox.max_storage_per_friend_mb" | "mailbox.max_friend_mb" => {
                let n: u64 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("max_storage_per_friend_mb deve ser > 0".into()));
                }
                self.mailbox.max_storage_per_friend_mb = n;
            }
            "mailbox.max_ttl_days" | "mailbox.max_message_ttl_days" => {
                let n: u32 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("max_ttl_days deve ser > 0".into()));
                }
                self.mailbox.max_message_ttl_days = n;
            }
            "mailbox.max_envelope_size_kb" => {
                let n: u32 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("max_envelope_size_kb deve ser > 0".into()));
                }
                self.mailbox.max_envelope_size_kb = n;
            }
            "network.default_channel" => {
                if val.is_empty() {
                    return Err(ConfigError::InvalidSetting("default_channel não pode ser vazio".into()));
                }
                self.network.default_channel = val.to_string();
            }
            "network.max_peers" => {
                let n: usize = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                self.network.max_peers = n;
            }
            "network.listen_port" => {
                let n: u16 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                self.network.listen_port = n;
            }
            "network.upnp" => {
                self.network.upnp = match val {
                    "true" | "1" | "on" | "sim" => true,
                    "false" | "0" | "off" | "nao" | "não" => false,
                    _ => return Err(ConfigError::InvalidSetting(format!("booleano inválido: {}", val))),
                };
            }
            "dm.allow_strangers" => {
                self.dm.allow_strangers = match val {
                    "true" | "1" | "on" | "sim" => true,
                    "false" | "0" | "off" | "nao" | "não" => false,
                    _ => return Err(ConfigError::InvalidSetting(format!("booleano inválido: {}", val))),
                };
            }
            "dm.send_courtesy_notice" => {
                self.dm.send_courtesy_notice = match val {
                    "true" | "1" | "on" | "sim" => true,
                    "false" | "0" | "off" | "nao" | "não" => false,
                    _ => return Err(ConfigError::InvalidSetting(format!("booleano inválido: {}", val))),
                };
            }
            "dm.friend_rate_limit_per_min" => {
                let n: u32 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("friend_rate_limit_per_min deve ser > 0".into()));
                }
                self.dm.friend_rate_limit_per_min = n;
            }
            "dm.stranger_rate_limit_per_min" => {
                let n: u32 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("stranger_rate_limit_per_min deve ser > 0".into()));
                }
                self.dm.stranger_rate_limit_per_min = n;
            }
            "dm.friend_max_message_bytes" => {
                let n: usize = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("friend_max_message_bytes deve ser > 0".into()));
                }
                self.dm.friend_max_message_bytes = n;
            }
            "dm.stranger_max_message_bytes" => {
                let n: usize = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("stranger_max_message_bytes deve ser > 0".into()));
                }
                self.dm.stranger_max_message_bytes = n;
            }
            "dm.stranger_offline_limit_per_hour" => {
                let n: u32 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("stranger_offline_limit_per_hour deve ser > 0".into()));
                }
                self.dm.stranger_offline_limit_per_hour = n;
            }
            "firewall.exempt_friends" => {
                self.firewall.exempt_friends = match val {
                    "true" | "1" | "on" | "sim" => true,
                    "false" | "0" | "off" | "nao" | "não" => false,
                    _ => return Err(ConfigError::InvalidSetting(format!("booleano inválido: {}", val))),
                };
            }
            "firewall.relay_friends_only" => {
                self.firewall.relay_friends_only = match val {
                    "true" | "1" | "on" | "sim" => true,
                    "false" | "0" | "off" | "nao" | "não" => false,
                    _ => return Err(ConfigError::InvalidSetting(format!("booleano inválido: {}", val))),
                };
            }
            "firewall.friend_chat_per_10s" => {
                let n: u32 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("friend_chat_per_10s deve ser > 0".into()));
                }
                self.firewall.friend_chat_per_10s = n;
            }
            "firewall.stranger_chat_per_10s" => {
                let n: u32 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("stranger_chat_per_10s deve ser > 0".into()));
                }
                self.firewall.stranger_chat_per_10s = n;
            }
            "firewall.friend_control_per_10s" => {
                let n: u32 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("friend_control_per_10s deve ser > 0".into()));
                }
                self.firewall.friend_control_per_10s = n;
            }
            "firewall.stranger_control_per_10s" => {
                let n: u32 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("stranger_control_per_10s deve ser > 0".into()));
                }
                self.firewall.stranger_control_per_10s = n;
            }
            "firewall.friend_chunk_reqs_per_10s" => {
                let n: u32 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("friend_chunk_reqs_per_10s deve ser > 0".into()));
                }
                self.firewall.friend_chunk_reqs_per_10s = n;
            }
            "firewall.stranger_chunk_reqs_per_10s" => {
                let n: u32 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("stranger_chunk_reqs_per_10s deve ser > 0".into()));
                }
                self.firewall.stranger_chunk_reqs_per_10s = n;
            }
            "firewall.invalid_packets_per_min" => {
                let n: u32 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("invalid_packets_per_min deve ser > 0".into()));
                }
                self.firewall.invalid_packets_per_min = n;
            }
            "firewall.stranger_global_msgs_per_10s" => {
                let n: u32 = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("stranger_global_msgs_per_10s deve ser > 0".into()));
                }
                self.firewall.stranger_global_msgs_per_10s = n;
            }
            "firewall.max_connections_per_ip" => {
                let n: usize = val.parse().map_err(|_| ConfigError::InvalidSetting(val.to_string()))?;
                if n == 0 {
                    return Err(ConfigError::InvalidSetting("max_connections_per_ip deve ser > 0".into()));
                }
                self.firewall.max_connections_per_ip = n;
            }
            other => {
                return Err(ConfigError::InvalidSetting(format!(
                    "chave desconhecida '{}'. Chaves válidas: mailbox.*, network.*, dm.*, firewall.*",
                    other
                )));
            }
        }
        Ok(())
    }
}

/// Converte uma string de duração opcional (ex: "2h", "30m", "7d", "120s" ou número em segundos)
pub fn parse_ttl_arg(spec: &str) -> Option<u64> {
    let trimmed = spec.trim();
    if let Ok(secs) = trimmed.parse::<u64>() {
        return (secs > 0).then_some(secs);
    }
    if let Some(s) = trimmed.strip_suffix('s') {
        return s.parse::<u64>().ok().filter(|&v| v > 0);
    }
    parse_duration(trimmed).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values_and_effective_ttl() {
        let cfg = NodeConfig::default();
        assert!(cfg.mailbox.enabled);
        assert_eq!(cfg.mailbox.max_storage_mb, 50);
        assert_eq!(cfg.mailbox.max_storage_per_friend_mb, 5);
        assert_eq!(cfg.mailbox.max_message_ttl_days, 7);
        assert_eq!(cfg.mailbox.max_envelope_size_kb, 256);

        let seven_days = 7 * 86_400;
        // Sem sugestão -> usa o máximo de Carol (7 dias)
        assert_eq!(cfg.calculate_effective_ttl(None), seven_days);
        // Alice pede 2 horas -> menor que 7 dias, Carol aceita 2 horas
        assert_eq!(cfg.calculate_effective_ttl(Some(7200)), 7200);
        // Alice pede 30 dias -> maior que 7 dias, Carol limita em 7 dias
        assert_eq!(cfg.calculate_effective_ttl(Some(30 * 86_400)), seven_days);
    }

    #[test]
    fn test_save_load_and_partial_migration() {
        let dir = std::env::temp_dir().join(format!("anarchord_cfg_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("config.json");

        // Primeiro boot gera o arquivo padrão
        let mut cfg = NodeConfig::load_or_default(Some(&path)).unwrap();
        assert!(path.exists());
        assert_eq!(cfg.mailbox.max_storage_mb, 50);

        // Alterar via set_key e salvar
        cfg.set_key("mailbox.max_storage_mb", "120").unwrap();
        cfg.set_key("mailbox.max_ttl_days", "14").unwrap();
        cfg.set_key("mailbox.enabled", "false").unwrap();
        cfg.save(Some(&path)).unwrap();

        let reloaded = NodeConfig::load_or_default(Some(&path)).unwrap();
        assert_eq!(reloaded.mailbox.max_storage_mb, 120);
        assert_eq!(reloaded.mailbox.max_message_ttl_days, 14);
        assert!(!reloaded.mailbox.enabled);

        // Migração de JSON parcial (campos novos ganham default)
        fs::write(&path, r#"{"version": 1, "mailbox": {"max_storage_mb": 80}}"#).unwrap();
        let migrated = NodeConfig::load_or_default(Some(&path)).unwrap();
        assert_eq!(migrated.mailbox.max_storage_mb, 80);
        assert_eq!(migrated.mailbox.max_message_ttl_days, 7);
        assert_eq!(migrated.network.default_channel, "geral");
        // config.json anterior ao #101 (sem network.upnp): UPnP ligado
        assert!(migrated.network.upnp);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_upnp_can_be_turned_off() {
        let mut cfg = NodeConfig::default();
        assert!(cfg.network.upnp);
        cfg.set_key("network.upnp", "off").unwrap();
        assert!(!cfg.network.upnp);
        assert!(cfg.set_key("network.upnp", "talvez").is_err());
    }

    #[test]
    fn test_parse_ttl_arg() {
        assert_eq!(parse_ttl_arg("2h"), Some(7200));
        assert_eq!(parse_ttl_arg("30m"), Some(1800));
        assert_eq!(parse_ttl_arg("3d"), Some(3 * 86_400));
        assert_eq!(parse_ttl_arg("90s"), Some(90));
        assert_eq!(parse_ttl_arg("300"), Some(300));
        assert_eq!(parse_ttl_arg("0"), None);
        assert_eq!(parse_ttl_arg("invalido"), None);
    }
}
