//! Texto em português dos eventos do core. O core só manda eventos tipados; a escolha das
//! palavras (e dos emojis) é da interface.

use p2p_core::community::{format_duration, short_id, ModKind};
use p2p_core::config::NodeConfig;
use p2p_core::dm::FirewallBlockEntry;
use p2p_core::files::{FileEvent, FileState, FileSummary};
use p2p_core::runtime::{
    CoreError, CoreEvent, FriendStatus, NetworkEvent, Role, ScreenEvent, ServerChange, ServerInfo, ServerNotice, SpaceInfo, VoiceEvent,
};

/// Ajuda dos comandos de servidor
pub const SERVER_HELP: &str = "Comandos: /server create <nome> | join <id> | accept | list | switch <nome|id|lobby> | info | history | bans \
| invite | mod add <par> | mod remove <par> | channel add <nome> [voz] | channel remove <nome> | passport issue <par> [mod] [duração] | passport show | passport flatten \
| ban <par> [30m|12h|3d|2w|perm] [motivo] | unban <par> | revoke <par> | requests | dismiss <par> | close (privado) | open (público) \
| policy <validade> <janela> (ex.: 7d 2d) | tsa add <nome> <url> <chave-base64> | tsa remove <nome> | rotate-key | leave  (atalho: /lobby)";

pub fn space_label(space: &SpaceInfo) -> String {
    match space {
        SpaceInfo::Lobby => "🌐 Lobby".to_string(),
        SpaceInfo::Server { name: Some(name), .. } => format!("🏰 {}", name),
        SpaceInfo::Server { id, name: None } => format!("🏰 {}", short_id(id)),
    }
}

pub fn human_size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 30 => format!("{:.1} GB", b as f64 / (1u64 << 30) as f64),
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.0} KB", b as f64 / 1024.0),
        b => format!("{} B", b),
    }
}

/// Data UTC legível ("2026-11-02 18:20 UTC"), sem depender de biblioteca de datas
pub fn fmt_utc(secs: u64) -> String {
    // Algoritmo de datas civis de Howard Hinnant (dias desde 1970-01-01 -> ano/mês/dia)
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", year, month, day, rem / 3600, rem % 3600 / 60)
}

/// Linhas de texto para a aba Sistema (ou para o terminal do daemon). Eventos que a interface
/// mostra de outro jeito (mensagens de chat, listas de membros, progresso) não geram texto.
pub fn describe(event: &CoreEvent) -> Vec<String> {
    let one = |s: String| vec![s];
    match event {
        CoreEvent::Started { .. } => Vec::new(),
        CoreEvent::Network(e) => one(network(e)),
        CoreEvent::PeerIdentified { .. } | CoreEvent::PeerLeft { .. } => Vec::new(),
        CoreEvent::Peers { anarchord, connections, peers } => {
            let mut lines = vec![format!(
                "Pares Anarchord conectados: {} (conexões totais, incluindo DHT: {})",
                anarchord, connections
            )];
            for p in peers {
                let neg = match p.negotiated_version {
                    Some(v) => format!("negociado: v{}", v),
                    None => "incompatível ⚠️".to_string(),
                };
                let caps = if p.capabilities.is_empty() {
                    "nenhuma".to_string()
                } else {
                    p.capabilities.join(",")
                };
                lines.push(format!(
                    "   • {} ({}) · nº seg: {} · protocolo {} ({}) · app {} · caps: [{}]",
                    p.nick,
                    short_id(&p.pubkey),
                    p2p_core::identity::safety_number(&p.pubkey),
                    p.announced_versions,
                    neg,
                    p.app_version,
                    caps
                ));
            }
            lines
        }
        CoreEvent::PeerIncompatible {
            nick,
            peer_version,
            supported_versions,
            ..
        } => one(format!(
            "⚠️ {} usa uma versão incompatível ({}; suportado: {}); atualize",
            nick, peer_version, supported_versions
        )),
        CoreEvent::AudioDevices { inputs, outputs } => {
            vec![format!("🎤 Entradas: {}", inputs.join(" | ")), format!("🔊 Saídas: {}", outputs.join(" | "))]
        }
        CoreEvent::SpaceChanged { .. } | CoreEvent::ServersChanged(_) | CoreEvent::ChannelMembers { .. } | CoreEvent::RoomKey(_) => Vec::new(),
        CoreEvent::ChannelEntered { space, channel } => one(format!("🚀 {} #{}", space_label(space), channel)),
        CoreEvent::ChatMessage { .. } | CoreEvent::EncryptedMessage { .. } => Vec::new(),
        CoreEvent::InviteReceived { from, known: false, .. } => one(format!("💡 Convite de {}: digite /server accept para entrar", from)),
        CoreEvent::InviteReceived { .. } => Vec::new(),
        CoreEvent::Voice(e) => voice(e).into_iter().collect(),
        CoreEvent::Screen(e) => screen(e),
        CoreEvent::File(e) => file(e).into_iter().collect(),
        CoreEvent::Files(list) => files(list),
        CoreEvent::Friends(list) => friends(list),
        CoreEvent::FriendPresence { public_key, alias, online } => {
            let name = alias.clone().unwrap_or_else(|| short_id(public_key).to_string());
            one(format!("{} Amigo {} está {}", if *online { "🟢" } else { "⚪" }, name, if *online { "online" } else { "offline" }))
        }
        CoreEvent::FriendUpdated { pubkey, alias, removed } => {
            let name = alias.clone().unwrap_or_else(|| short_id(pubkey).to_string());
            one(if *removed { format!("💔 Amigo {} removido", name) } else { format!("💚 Amigo {} adicionado", name) })
        }
        CoreEvent::FriendRequestReceived { pubkey, sender_nick, message, offline_delivery } => {
            let tag = if *offline_delivery { " [offline]" } else { "" };
            let msg_part = message.as_ref().map(|m| format!(": \"{}\"", m)).unwrap_or_default();
            one(format!(
                "📩 Pedido de amizade recebido de {} ({}){}{}. Digite '/friend accept {}' ou '/friend reject {}'",
                sender_nick,
                short_id(pubkey),
                tag,
                msg_part,
                sender_nick,
                sender_nick
            ))
        }
        CoreEvent::FriendRequestAccepted { pubkey, peer_name, offline_delivery } => {
            let tag = if *offline_delivery { " (entregue via guardião)" } else { "" };
            one(format!("💚 {} ({}) aceitou seu pedido de amizade!{}", peer_name, short_id(pubkey), tag))
        }
        CoreEvent::FriendRequestRejected { pubkey, peer_name, offline_delivery } => {
            let tag = if *offline_delivery { " (entregue via guardião)" } else { "" };
            one(format!("🚫 {} ({}) recusou seu pedido de amizade.{}", peer_name, short_id(pubkey), tag))
        }
        CoreEvent::DmOpened { peer_name, channel, .. } => {
            one(format!("💬 Conversa direta aberta com {} ({}). Suas mensagens vão cifradas de ponta a ponta.", peer_name, channel))
        }
        CoreEvent::DirectMessage { .. } => Vec::new(),
        CoreEvent::MailboxQueued { recipient_name, envelope_id, suggested_ttl, .. } => {
            let ttl_str = suggested_ttl.map(|s| format_duration(Some(s))).unwrap_or_else(|| "padrão".to_string());
            one(format!(
                "📬 {} está offline: DM assinada e lacrada na mailbox dos amigos guardiões (id {}, validade {}).",
                recipient_name,
                short_id(envelope_id),
                ttl_str
            ))
        }
        CoreEvent::MailboxStoredForFriend { sender_name, recipient_short, envelope_id, effective_ttl_secs } => one(format!(
            "🛡️ Guardando envelope offline de {} para {} (id {}, retido por {}).",
            sender_name,
            recipient_short,
            short_id(envelope_id),
            format_duration(Some(*effective_ttl_secs))
        )),
        CoreEvent::ConfigStatus { config, mailbox_used_bytes, mailbox_envelope_count } => {
            config_status(config, *mailbox_used_bytes, *mailbox_envelope_count)
        }
        CoreEvent::ConfigUpdated { key, value } => one(format!("⚙️ Configuração '{}' atualizada para '{}'.", key, value)),
        CoreEvent::PeerBlocked { pubkey, peer_name, is_friend, reason, duration_secs, offense_level, courtesy_sent, .. } => {
            let role = if *is_friend { "amigo" } else { "desconhecido" };
            let courtesy = if *courtesy_sent { " · aviso de cortesia enviado" } else { "" };
            let tip = if *is_friend {
                format!("Use /firewall unblock {}", peer_name)
            } else {
                format!("Use /friend add {} ou /firewall unblock {}", short_id(pubkey), peer_name)
            };
            one(format!(
                "🛡️ Firewall: {} ({}, {}) bloqueado por {} [nível {}]{}: {}. ({})",
                peer_name,
                short_id(pubkey),
                role,
                format_duration(Some(*duration_secs)),
                offense_level,
                courtesy,
                reason,
                tip
            ))
        }
        CoreEvent::PeerUnblocked { pubkey, peer_name } => {
            one(format!("🕊️ Firewall: {} ({}) foi desbloqueado.", peer_name, short_id(pubkey)))
        }
        CoreEvent::FirewallStatus(blocks) => firewall_status(blocks),
        CoreEvent::EncryptionKeyRotated { epoch, public_key } => {
            one(format!("🔑 Chave de criptografia X25519 rotacionada (época {}, chave {})", epoch, short_id(public_key)))
        }
        CoreEvent::FilePreparing { name } => one(format!("📁 Preparando '{}' para compartilhar...", name)),
        CoreEvent::Server(notice) => server(notice),
        CoreEvent::Error(e) => one(error(e)),
        CoreEvent::Stopped => one("👋 Anarchord encerrado.".to_string()),
    }
}

fn network(event: &NetworkEvent) -> String {
    match event {
        NetworkEvent::Listening(addr) => format!("Endereço de escuta: {}", addr),
        NetworkEvent::ExternalAddress(addr) => format!("🌐 Endereço externo confirmado: {}", addr),
        NetworkEvent::DhtBootstrap { nodes } => format!("🌍 DHT Amino: {} nós de bootstrap registrados", nodes),
        NetworkEvent::Dialing(addr) => format!("⏳ Conectando ao par remoto: {}", addr),
        NetworkEvent::TrackerPeer(addr) => format!("📡 Par descoberto via BitTorrent Tracker: {}", addr),
        NetworkEvent::BehindNat => "🧱 AutoNAT: nó atrás de NAT. Buscando relays públicos...".to_string(),
        NetworkEvent::RelayRequested { relay, .. } => format!("🛰️ Pedindo reserva no relay {}", relay),
        NetworkEvent::RelayReserved(relay) => format!("🛰️ Reserva aceita no relay {}", relay),
        NetworkEvent::HolePunched(peer) => format!("🕳️ Hole punching OK: conexão direta com {}", peer),
        NetworkEvent::HolePunchFailed { peer_id, error } => format!("🕳️ Hole punching com {} falhou (segue via relay): {}", peer_id, error),
        NetworkEvent::Connected { peer_id, relayed, .. } => {
            format!("🔗 Conectado a {} ({})", peer_id, if *relayed { "via relay" } else { "direto" })
        }
        NetworkEvent::ConnectionClosed { peer_id, cause } => format!("👋 Conexão fechada com {} ({})", peer_id, cause),
        NetworkEvent::PeerExchange { from, dialed } => format!("🤝 {} par(es) novo(s) indicados por {}", dialed, from),
        NetworkEvent::AudioUnavailable(reason) => format!("⚠️ Áudio nativo indisponível: {}", reason),
    }
}

fn voice(event: &VoiceEvent) -> Option<String> {
    Some(match event {
        VoiceEvent::Joined(room) => format!("🔊 Conectado à sala de voz [🔊 {}]", room),
        VoiceEvent::Left(room) => format!("🔇 Saiu da sala de voz [{}].", room),
        VoiceEvent::Members(_) => return None,
        VoiceEvent::Speaking { nick, speaking: true } => format!("🔊 [VOZ] {} começou a falar...", nick),
        VoiceEvent::Speaking { nick, speaking: false } => format!("🔇 [VOZ] {} parou de falar.", nick),
        VoiceEvent::Muted(true) => "Microfone MUTADO.".to_string(),
        VoiceEvent::Muted(false) => "Microfone ATIVADO.".to_string(),
        VoiceEvent::AudioReady => "🎤 Subsistema de áudio ativado.".to_string(),
        VoiceEvent::SynthStarted => "📻 Sintetizador 8-bits tocando na sala de voz (Opus).".to_string(),
    })
}

fn screen(event: &ScreenEvent) -> Vec<String> {
    vec![match event {
        ScreenEvent::Monitors(screens) => {
            let list: Vec<String> = screens
                .iter()
                .enumerate()
                .map(|(i, s)| format!("[{}] {} ({}x{}){}", i, s.name, s.width, s.height, if s.is_primary { " (Primária)" } else { "" }))
                .collect();
            format!("Telas locais detectadas ({}): {}", screens.len(), list.join(" | "))
        }
        ScreenEvent::ShareStarted { stream_id, synthetic: true, .. } => {
            format!("📺 [VÍDEO H.264] Transmissão animada iniciada a 30 FPS (Stream ID: {})", stream_id)
        }
        ScreenEvent::ShareStarted { stream_id, quality, .. } => {
            format!("📺 Transmissão H.264 (30 FPS, {}p) INICIADA (Stream ID: {}). Use /screen stop para encerrar.", quality, stream_id)
        }
        ScreenEvent::ShareStopped => "📺 Transmissão de tela ENCERRADA.".to_string(),
        ScreenEvent::FrameSent { seq, bytes } => format!("📺 [VÍDEO ENVIADO] Quadro #{} transmitido na malha ({:.1} KB)", seq, *bytes as f32 / 1024.0),
        ScreenEvent::StreamAvailable { nick, .. } => format!("📺 Nova tela compartilhada por '{}'. Digite /screen watch {}", nick, nick),
        ScreenEvent::FrameReceived { nick, seq, bytes, width, height } => format!(
            "📺 [DAEMON VÍDEO] Recebendo transmissão de '{}': quadro #{} ({:.1} KB, {}x{})",
            nick,
            seq,
            *bytes as f32 / 1024.0,
            width,
            height
        ),
        ScreenEvent::Watching { nick, .. } => format!("📺 Assistindo transmissão de '{}'. Pressione ESC na janela para fechar.", nick),
        ScreenEvent::WatchEnded => "📺 Janela de vídeo fechada.".to_string(),
    }]
}

fn file(event: &FileEvent) -> Option<String> {
    Some(match event {
        FileEvent::Offered { cid, name, size, from, direct } => format!(
            "📎 {} {} '{}' ({}). Baixe com /get {}",
            from,
            if *direct { "te enviou" } else { "compartilhou" },
            name,
            human_size(*size),
            cid.short()
        ),
        FileEvent::Shared { cid, name } => format!("📤 '{}' compartilhado (id {}). Fica disponível enquanto o app estiver aberto.", name, cid.short()),
        FileEvent::Started { name, .. } => format!("📥 Baixando '{}'...", name),
        FileEvent::Progress { .. } => return None,
        FileEvent::Completed { name, path, .. } => {
            format!("💾 '{}' salvo em {}. Agora você também compartilha com quem pedir.", name, path.display())
        }
        FileEvent::Failed { name, reason, .. } => format!("❌ '{}': {}", name, reason),
        FileEvent::Dismissed { name } => format!("Oferta de '{}' recusada.", name),
        FileEvent::Unshared { name } => format!("📁 '{}' não está mais sendo compartilhado nem baixado.", name),
        FileEvent::LocalFileRemoved { cid, name, from } => format!(
            "🗑️ '{}' foi removido do disco local e deixou de ser compartilhado. Ainda disponível de {} com /get {}",
            name,
            from,
            cid.short()
        ),
    })
}

fn files(list: &[FileSummary]) -> Vec<String> {
    if list.is_empty() {
        return vec!["📁 Nenhum arquivo. Compartilhe com /share <arquivo>.".to_string()];
    }
    list.iter()
        .map(|file| {
            let state = match &file.state {
                FileState::Offered => format!("oferecido por {} · /get {}", file.from, file.cid.short()),
                FileState::Downloading { progress, peers } => format!("baixando {:.0}% de {} par(es)", progress * 100.0, peers),
                FileState::Seeding => "compartilhando".to_string(),
            };
            format!("📁 [{}] {} ({}) — {}", file.cid.short(), file.name, human_size(file.size), state)
        })
        .collect()
}

fn moderation_text(target: &str, kind: &ModKind, at: u64) -> String {
    match kind {
        ModKind::Ban { until } => format!("baniu {} ({})", target, format_duration(until.map(|u| u.saturating_sub(at)))),
        ModKind::Unban => format!("desfez o próprio ban de {}", target),
        ModKind::Renounce { .. } => "saiu do servidor (renunciou ao passaporte)".to_string(),
        ModKind::Revoke { serial } => format!("revogou o passaporte {} de {}", serial, target),
    }
}

fn server(notice: &ServerNotice) -> Vec<String> {
    let one = |s: String| vec![s];
    match notice {
        ServerNotice::Created { id, name } => one(format!(
            "🏰 Servidor '{}' criado (id {}). Você é o dono. Chat, voz e tela do servidor são cifrados de ponta a ponta. \
             Use /server invite para convidar. Carimbos de tempo: FreeTSA (/server tsa para mudar).",
            name,
            short_id(id)
        )),
        ServerNotice::Searching { id } => one(format!(
            "⏳ Procurando membros online do servidor {}... você entra assim que a configuração chegar \
             (servidor privado: um moderador precisa emitir seu passaporte).",
            short_id(id)
        )),
        ServerNotice::WaitingConfig { id } => one(format!("⏳ A configuração de {} ainda não chegou; você entra assim que chegar.", short_id(id))),
        ServerNotice::Left { name, was_owner } => one(format!(
            "👋 Você saiu do servidor '{}'.{}",
            name,
            if *was_owner { " A chave de dono continua salva em disco." } else { "" }
        )),
        ServerNotice::Synced { name, height, .. } => one(format!("📜 '{}' sincronizado ({} eventos).", name, height)),
        ServerNotice::Changed { change, .. } => one(match change {
            ServerChange::ChannelAdded { name, voice } => format!("✅ Canal {}{} criado.", if *voice { "🔊 " } else { "#" }, name),
            ServerChange::ChannelRemoved(name) => format!("🗑️ Canal {} removido.", name),
            ServerChange::ModeratorAdded { who, validity_secs } => format!(
                "🛡️ Passaporte de moderador enviado a {} (validade padrão {}).",
                who,
                format_duration(Some(*validity_secs))
            ),
            ServerChange::ModeratorRemoved { who } => {
                format!("🛡️ Passaporte de moderador de {} revogado. Ações posteriores dele não valem.", who)
            }
            ServerChange::Closed => {
                "🔒 Servidor privado: só entra quem recebe passaporte de um moderador (/server passport issue <par>).".to_string()
            }
            ServerChange::Opened => "🔓 Servidor público: moderadores online emitem passaporte automaticamente a quem pedir.".to_string(),
            ServerChange::Policy { validity_secs, renewal_window_secs } => format!(
                "⏳ Passaportes: validade {}, renovação nos últimos {}.",
                format_duration(Some(*validity_secs)),
                format_duration(Some(*renewal_window_secs))
            ),
            ServerChange::TsaAdded(name) => format!("🕰️ Autoridade de tempo '{}' adicionada à configuração do servidor.", name),
            ServerChange::TsaRemoved(name) => format!("🕰️ Autoridade de tempo '{}' removida da configuração do servidor.", name),
            ServerChange::AccessPow(0) => "⛏️ Pedidos de acesso sem prova de trabalho.".to_string(),
            ServerChange::AccessPow(bits) => format!("⛏️ Pedidos de acesso exigem prova de trabalho ({} bits).", bits),
        }),
        ServerNotice::Moderated { target, kind, at, .. } => {
            let what = match kind {
                ModKind::Ban { until } => format!("🔨 {} foi banido ({}).", target, format_duration(until.map(|u| u.saturating_sub(*at)))),
                ModKind::Unban => format!("🕊️ {} foi desbanido.", target),
                ModKind::Renounce { .. } => format!("🚪 {} renunciou ao passaporte.", target),
                ModKind::Revoke { .. } => format!("🎫 Passaporte de {} revogado.", target),
            };
            one(format!("{} Vale quando o carimbo de tempo chegar.", what))
        }
        ServerNotice::ModerationReceived { server, by, target, kind, at, reason } => {
            let reason = if reason.is_empty() { String::new() } else { format!(" — motivo: {}", reason) };
            one(format!("🔨 [{}] {} {}{}", server, by, moderation_text(target, kind, *at), reason))
        }
        ServerNotice::EventRejected { server, description, reason } => {
            one(format!("↩️ [{}] Alteração recusada ({}): {}.", server, description, reason))
        }
        ServerNotice::BanStatus { server, banned: true } => {
            one(format!("⛔ Você foi banido de '{}': suas mensagens serão ignoradas pelos membros.", server))
        }
        ServerNotice::BanStatus { server, banned: false } => one(format!("🕊️ Seu ban em '{}' acabou.", server)),
        ServerNotice::Role { server, moderator: true } => one(format!("🛡️ Você agora é moderador em '{}'.", server)),
        ServerNotice::Role { server, moderator: false } => one(format!("🛡️ Você não é mais moderador em '{}'.", server)),
        // Atualização automática da lista: só alimenta o menu do servidor
        ServerNotice::AccessRequests { explicit: false, .. } => Vec::new(),
        ServerNotice::AccessProofComputing { server, bits } => one(format!("⛏️ [{}] Calculando prova de trabalho ({} bits) para pedir acesso…", server, bits)),
        ServerNotice::AccessProofFailed { server, reason } => one(format!("⚠️ [{}] Sem carimbo de TSA ({}); pedindo a uma testemunha da rede.", server, reason)),
        ServerNotice::AccessRequests { server, requests, .. } => {
            if requests.is_empty() {
                return one(format!("🎫 [{}] Nenhum pedido de acesso pendente.", server));
            }
            let mut lines = vec![format!("🎫 [{}] Pedidos de acesso pendentes ({}):", server, requests.len())];
            for r in requests {
                lines.push(format!("   {} ({}) desde {}", r.nick, short_id(&r.pubkey), fmt_utc(r.since)));
            }
            lines.push("   Emita com /server passport issue <par> [mod] ou pelo menu do servidor; dispense com /server dismiss <par>.".to_string());
            lines
        }
        ServerNotice::AccessRequested { server, who } => one(format!(
            "🎫 [{}] {} pediu acesso. Servidor privado: emita com /server passport issue {}.",
            server, who, who
        )),
        ServerNotice::StampObtained { server, source } => one(format!("🕰️ [{}] Carimbo de tempo obtido de {}.", server, source)),
        ServerNotice::StampFailed { server, tsa, reason } => {
            one(format!("⚠️ [{}] Sem carimbo de {} ({}); valem as testemunhas da rede.", server, tsa, reason))
        }
        ServerNotice::KeyGranted { to } => one(format!("🔐 {} recebeu a chave do grupo cifrado.", to)),
        ServerNotice::PassportUpdated { server } => one(format!("🎫 Passaporte de '{}' atualizado com sucesso.", server)),
        ServerNotice::PassportInfo { server, holder, issuer, chain_depth, stamps, expires_at, permissions } => {
            let exp_str = match expires_at {
                Some(exp) => fmt_utc(*exp),
                None => "Vitalício (Sem expiração)".to_string(),
            };
            vec![
                format!("🎫 Passaporte do Servidor '{}':", server),
                format!("   Titular: {}", short_id(holder)),
                format!("   Emissor: {}", short_id(issuer)),
                format!("   Cadeia: {} elo(s) | Carimbos de tempo: {}", chain_depth, stamps),
                format!("   Validade: {}", exp_str),
                format!("   Permissões: {}", permissions.join(", ")),
            ]
        }
        ServerNotice::KeyReceived { server } => {
            one(format!("🔐 Chave do grupo de '{}' recebida: chat, voz e tela cifrados de ponta a ponta.", server))
        }
        ServerNotice::LeaderChanged { server, leader, you } => one(match (leader, you) {
            (_, true) => format!("👑 [{}] Você é o novo líder do grupo cifrado (admite quem entra e troca a chave).", server),
            (Some(leader), false) => format!("👑 [{}] Novo líder do grupo cifrado: {}.", server, leader),
            (None, _) => format!("👑 [{}] Grupo cifrado sem líder no momento (aguardando membros).", server),
        }),
        ServerNotice::KeyChain { server, roots, mine } => {
            let mut lines = vec![format!("🔑 Corrente de chaves de '{}'{}:", server, if *mine { " (a chave em vigor está com você)" } else { "" })];
            for (pubkey, since, until, expires_at) in roots {
                let since = if *since == 0 { "desde a criação".to_string() } else { format!("desde {}", fmt_utc(*since)) };
                let state = match until {
                    Some(t) => format!("transferida em {}", fmt_utc(*t)),
                    None => format!("em vigor, vence em {}", fmt_utc(*expires_at)),
                };
                lines.push(format!("   {}… {} — {}", short_id(pubkey), since, state));
            }
            lines
        }
        ServerNotice::KeyLinkRequested { server, transfer } => one(format!(
            "⏳ [{}] {} pedida: vale quando chegar o carimbo da autoridade de tempo (TSA).",
            server,
            if *transfer { "Transferência da Chave do Servidor" } else { "Renovação da Chave do Servidor" }
        )),
        ServerNotice::TransferOffered { server, target } => {
            one(format!("🔑 [{}] Proposta de transferência da Chave do Servidor enviada a {}. Ele precisa aceitar (/server key accept).", server, target))
        }
        ServerNotice::TransferOfferReceived { server, from } => one(format!(
            "🔑 [{}] {} quer transferir a Chave do Servidor para você. Para aceitar: /server key accept (a chave nova é gerada nesta máquina).",
            server, from
        )),
        ServerNotice::TransferAccepted { server } => {
            one(format!("🔑 [{}] Transferência aceita: a chave nova foi gerada e guardada aqui. Vale quando o carimbo da TSA chegar.", server))
        }
        ServerNotice::OwnershipChanged { server, owner, expires_at } => one(if *owner {
            format!("👑 [{}] A Chave do Servidor em vigor está com você (vence em {}).", server, fmt_utc(*expires_at))
        } else {
            format!("🔑 [{}] Corrente de chaves atualizada (a chave em vigor vence em {}).", server, fmt_utc(*expires_at))
        }),
        ServerNotice::RootExpiring { server, expires_at } => one(format!(
            "⚠️ [{}] A Chave do Servidor vence em {}. Renove com /server key renew: depois do vencimento, todos os passaportes do servidor deixam de valer.",
            server,
            fmt_utc(*expires_at)
        )),
        ServerNotice::KeyRotated { server, epoch } => {
            one(format!("🔄 Chave do grupo MLS de '{}' rotacionada (época {}).", server, epoch))
        }
        ServerNotice::RemovedFromGroup { server } => {
            one(format!("🔐 Você foi removido do grupo cifrado de '{}': não recebe mais o conteúdo do servidor.", server))
        }
        ServerNotice::InviteSent { server } => {
            one(format!("📨 Convite para '{}' publicado no 🌐 Lobby #geral. Quem estiver lá digita /server accept.", server))
        }
        ServerNotice::InviteManual { id } => one(format!("⚠️ Ninguém no 🌐 Lobby #geral agora. Id do servidor para convite manual: {}", id)),
        ServerNotice::InviteNeedsPassport => {
            one("🔒 Servidor privado: emita o passaporte com /server passport issue <par> para a pessoa conseguir entrar.".to_string())
        }
        ServerNotice::Bans { server, bans } => {
            if bans.is_empty() {
                one(format!("🔨 Servidor '{}': nenhum membro banido no momento.", server))
            } else {
                let mut lines = vec![format!("🔨 Servidor '{}' — {} ban(s) ativo(s):", server, bans.len())];
                for b in bans {
                    let dur = b.until.map_or("permanente".to_string(), |u| format!("até {}", fmt_utc(u)));
                    let name = if b.target_nick.is_empty() { short_id(&b.target).to_string() } else { format!("{} ({})", b.target_nick, short_id(&b.target)) };
                    let reason = if b.reason.is_empty() { String::new() } else { format!(" — motivo: {}", b.reason) };
                    lines.push(format!("  • {} — {} por {}{}", name, dur, b.by, reason));
                }
                lines
            }
        }
        ServerNotice::List { lobby_current, servers } => {
            let marker = |on: bool| if on { "▶" } else { " " };
            let mut lines = vec![format!("{} 🌐 Lobby  (/server switch lobby)", marker(*lobby_current))];
            if servers.is_empty() {
                lines.push("  Nenhum servidor. Crie com /server create <nome> ou aceite um convite.".to_string());
            }
            for s in servers {
                let mut tags = Vec::new();
                if s.owner {
                    tags.push("dono".to_string());
                } else if s.moderator {
                    tags.push("moderador".to_string());
                }
                if s.pending {
                    tags.push("aguardando configuração".into());
                }
                if s.closed {
                    tags.push("privado".into());
                }
                if s.banned {
                    tags.push("banido".into());
                }
                let tags = if tags.is_empty() { String::new() } else { format!(" [{}]", tags.join(", ")) };
                lines.push(format!("{} 🏰 {} ({}){}", marker(s.current), s.name, short_id(&s.id), tags));
            }
            lines
        }
        ServerNotice::Info(info) => server_info(info),
        ServerNotice::History(history) => {
            let mut lines = vec![format!("📜 Histórico de alterações ({} blocos, mais recentes por último):", history.len())];
            for entry in history.iter().skip(history.len().saturating_sub(15)) {
                lines.push(format!("   #{} {} — {}", entry.height, fmt_utc(entry.timestamp), entry.description));
            }
            lines
        }
        ServerNotice::Help => one(SERVER_HELP.to_string()),
    }
}

fn server_info(info: &ServerInfo) -> Vec<String> {
    let channels: Vec<String> = info.channels.iter().map(|c| format!("{}{}", if c.voice { "🔊 " } else { "#" }, c.name)).collect();
    let role = match info.role {
        Role::Owner => "dono".to_string(),
        Role::Moderator => "moderador".to_string(),
        Role::Member => "membro".to_string(),
    };
    let access = format!(
        "{}, {} passaporte(s) conhecido(s)",
        if info.closed { "privado (passaporte manual)" } else { "público (passaporte automático)" },
        info.passports_known
    );
    let mods: Vec<String> = info
        .moderators
        .iter()
        .map(|(nick, perms, until)| {
            let until = until.map_or("vitalício".to_string(), |u| format!("até {}", fmt_utc(u)));
            format!("{} ({}; {})", nick, perms.join("/"), until)
        })
        .collect();
    let bans: Vec<String> = info
        .bans
        .iter()
        .map(|(nick, until, by)| {
            let until = until.map_or("permanente".to_string(), |u| format!("até {}", fmt_utc(u)));
            format!("{} ({}, por {})", nick, until, by)
        })
        .collect();
    let tsas: Vec<String> = info.tsas.iter().map(|(name, url)| format!("{} <{}>", name, url)).collect();
    let none_or = |list: Vec<String>| if list.is_empty() { "nenhum".to_string() } else { list.join(", ") };
    let mls_str = match (&info.mls_leader, info.mls_epoch) {
        (Some(leader), Some(epoch)) => format!("líder MLS: {} (época {})", leader, epoch),
        _ => "grupo MLS: aguardando sincronização".to_string(),
    };
    let safety_str = if info.safety_number.is_empty() {
        p2p_core::identity::safety_number(&info.id)
    } else {
        info.safety_number.clone()
    };
    vec![
        format!("🏰 {} | bloco {} ({}) | id {}", info.name, info.height, info.updated_at.map(fmt_utc).unwrap_or_default(), info.id),
        format!("   🔐 Nº de Segurança: {} | {}", safety_str, mls_str),
        format!("   Canais: {}", channels.join(", ")),
        format!("   Você: {} | Acesso: {}", role, access),
        format!("   Moderadores: {}", none_or(mods)),
        format!("   Banidos: {}", none_or(bans)),
        format!("   Autoridades de tempo: {} (+ testemunhas da rede)", none_or(tsas)),
        format!(
            "   Passaportes: validade {}, renovação nos últimos {} | Alterações aguardando carimbo: {}",
            format_duration(Some(info.passport_validity_secs)),
            format_duration(Some(info.renewal_window_secs)),
            info.pending_actions
        ),
    ]
}

fn friends(list: &[FriendStatus]) -> Vec<String> {
    if list.is_empty() {
        return vec!["Nenhum amigo ainda. Use /friend add <pubkey> [apelido]".to_string()];
    }
    let mut lines = vec![format!("👥 Amigos ({}):", list.len())];
    for f in list {
        let name = f.alias.clone().or_else(|| f.current_nick.clone()).unwrap_or_else(|| "(sem nome)".to_string());
        let (icon, status_label) = match f.state {
            p2p_core::identity::FriendState::Confirmed => (
                if f.online { "🟢" } else { "⚪" },
                if f.online { "online" } else { "offline" },
            ),
            p2p_core::identity::FriendState::PendingOutgoing => (
                if f.online { "🟢" } else { "⚪" },
                "pendente (enviado)",
            ),
            p2p_core::identity::FriendState::PendingIncoming => (
                "📩",
                "pedido recebido",
            ),
            p2p_core::identity::FriendState::Rejected => (
                "🚫",
                "recusado",
            ),
        };
        lines.push(format!(
            "   {} {} · {} · nº seg: {} · {}",
            icon,
            name,
            short_id(&f.public_key),
            p2p_core::identity::safety_number(&f.public_key),
            status_label
        ));
    }
    lines
}

fn config_status(cfg: &NodeConfig, used_bytes: u64, envelope_count: usize) -> Vec<String> {
    let mb = &cfg.mailbox;
    let net = &cfg.network;
    let dm = &cfg.dm;
    vec![
        "⚙️ Configuração do Nó (/config set <chave> <valor>):".to_string(),
        format!(
            "   mailbox.enabled = {} | mailbox.max_message_ttl_days = {} | mailbox.max_envelope_size_kb = {}",
            mb.enabled, mb.max_message_ttl_days, mb.max_envelope_size_kb
        ),
        format!(
            "   mailbox.max_storage_mb = {} ({} em uso, {} envelope(s)) | mailbox.max_storage_per_friend_mb = {}",
            mb.max_storage_mb,
            human_size(used_bytes),
            envelope_count,
            mb.max_storage_per_friend_mb
        ),
        format!(
            "   dm.allow_strangers = {} | dm.send_courtesy_notice = {} | dm.friend_rate_limit_per_min = {} | dm.stranger_rate_limit_per_min = {}",
            dm.allow_strangers, dm.send_courtesy_notice, dm.friend_rate_limit_per_min, dm.stranger_rate_limit_per_min
        ),
        format!(
            "   dm.friend_max_message_bytes = {} | dm.stranger_max_message_bytes = {} | dm.stranger_offline_limit_per_hour = {}",
            dm.friend_max_message_bytes, dm.stranger_max_message_bytes, dm.stranger_offline_limit_per_hour
        ),
        format!(
            "   firewall.exempt_friends = {} | firewall.relay_friends_only = {} | firewall.invalid_packets_per_min = {} | firewall.stranger_global_msgs_per_10s = {}",
            cfg.firewall.exempt_friends, cfg.firewall.relay_friends_only, cfg.firewall.invalid_packets_per_min, cfg.firewall.stranger_global_msgs_per_10s
        ),
        format!(
            "   firewall.friend_chat_per_10s = {} | firewall.stranger_chat_per_10s = {} | firewall.friend_control_per_10s = {} | firewall.stranger_control_per_10s = {}",
            cfg.firewall.friend_chat_per_10s, cfg.firewall.stranger_chat_per_10s, cfg.firewall.friend_control_per_10s, cfg.firewall.stranger_control_per_10s
        ),
        format!(
            "   network.default_channel = {} | network.auto_bootstrap = {} | network.max_peers = {} | network.listen_port = {}",
            net.default_channel, net.auto_bootstrap, net.max_peers, net.listen_port
        ),
    ]
}

fn firewall_status(blocks: &[FirewallBlockEntry]) -> Vec<String> {
    if blocks.is_empty() {
        return vec!["🛡️ Firewall: nenhum par bloqueado no momento.".to_string()];
    }
    let mut lines = vec![format!("🛡️ Firewall — Pares bloqueados ({}):", blocks.len())];
    for b in blocks {
        lines.push(format!(
            "   ⛔ {} · nível {} · até {} — {} (/firewall unblock {})",
            short_id(&b.pubkey),
            b.offense_level,
            fmt_utc(b.blocked_until),
            b.reason,
            short_id(&b.pubkey)
        ));
    }
    lines
}

fn error(error: &CoreError) -> String {
    match error {
        CoreError::Friend(message) => format!("❌ Amigos: {}", message),
        CoreError::Config(message) => format!("❌ Configuração: {}", message),
        CoreError::PeerNotFound(query) => format!("❌ Par '{}' não encontrado. Use o nick de alguém conectado ou a pubkey completa.", query),
        CoreError::NoStream(query) => format!("⚠️ Nenhuma tela ativa encontrada para '{}'. Verifique os pares ou aguarde.", query),
        CoreError::AlreadyStreaming => "Você já está transmitindo sua tela. Use /screen stop para parar.".to_string(),
        CoreError::NotStreaming => "Nenhuma transmissão de tela em andamento.".to_string(),
        CoreError::NotInVoice => "⚠️ Você não está conectado a nenhuma sala de voz.".to_string(),
        CoreError::NoSuchChannel { name, voice: true } => format!("❌ Não há sala de voz '{}' neste servidor. Veja o painel de canais.", name),
        CoreError::NoSuchChannel { name, voice: false } => format!("❌ #{} não existe neste servidor. Veja o painel de canais.", name),
        CoreError::NoGroupKey => {
            "🔐 Aguardando a chave do grupo cifrado deste servidor (sincronizando com o líder presente na sala).".to_string()
        }
        CoreError::BannedHere => "⛔ Você está banido deste servidor: os outros membros ignoram suas mensagens.".to_string(),
        CoreError::NoPassport => "🎫 Você ainda não tem passaporte neste servidor: suas mensagens são ignoradas até um moderador emitir.".to_string(),
        CoreError::InLobby => "Você está no 🌐 Lobby. Entre num servidor primeiro (/server list, /server switch <nome>).".to_string(),
        CoreError::SelfModeration => "❌ Você não pode moderar a si mesmo.".to_string(),
        CoreError::NoInvite => "Nenhum convite recebido ainda. Peça para alguém usar /server invite no Lobby.".to_string(),
        CoreError::ServerNotFound(query) => format!("❌ Servidor '{}' não encontrado. Veja /server list.", query),
        CoreError::Server(message) | CoreError::File(message) | CoreError::Network(message) => format!("❌ {}", message),
        CoreError::Io { context, message } => format!("❌ Erro ao ler '{}': {}", context, message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2p_core::runtime::ServerListEntry;

    #[test]
    fn test_every_kind_of_event_has_sensible_text() {
        assert_eq!(describe(&CoreEvent::ChannelEntered { space: SpaceInfo::Lobby, channel: "geral".into() }), vec!["🚀 🌐 Lobby #geral"]);
        assert!(describe(&CoreEvent::Voice(VoiceEvent::Speaking { nick: "Alice".into(), speaking: true }))[0].contains("Alice começou a falar"));
        assert!(describe(&CoreEvent::Screen(ScreenEvent::StreamAvailable { stream_id: "s".into(), nick: "Alice".into() }))[0]
            .contains("Nova tela compartilhada por 'Alice'"));
        let list = describe(&CoreEvent::Server(ServerNotice::List {
            lobby_current: false,
            servers: vec![ServerListEntry {
                id: "ab".repeat(32),
                name: "Guilda".into(),
                current: true,
                owner: true,
                moderator: false,
                pending: false,
                closed: true,
                banned: false,
            }],
        }));
        assert_eq!(list.len(), 2);
        assert!(list[1].starts_with("▶ 🏰 Guilda") && list[1].contains("[dono, privado]"), "{}", list[1]);
        assert!(describe(&CoreEvent::Error(CoreError::InLobby))[0].contains("Lobby"));
        assert!(describe(&CoreEvent::ChatMessage {
            channel: "geral".into(),
            author: "a".into(),
            author_pubkey: "p".into(),
            text: "t".into(),
            timestamp: 0
        })
        .is_empty());
    }

    #[test]
    fn test_utc_dates_and_sizes() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(fmt_utc(1_798_000_000), "2026-12-23 04:26 UTC");
        assert_eq!(human_size(3 * 1024 * 1024 + 300_000), "3.3 MB");
        assert_eq!(human_size(512), "512 B");
    }
}
