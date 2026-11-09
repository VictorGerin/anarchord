//! Menus da TUI (menu principal e menus de contexto) e caixas de diálogo.
//! Cada item gera um comando de texto igual ao que o usuário digitaria, então o backend não
//! precisa saber de menus.

/// Estado resumido de um arquivo exibido no popup de `/files` e usado no autocompletar da TUI
#[derive(Debug, Clone, PartialEq)]
pub enum FileUiState {
    Offered,
    Downloading { progress: f32, peers: usize },
    Seeding,
}

/// Arquivo exibido no popup de `/files` e registrado para autocompletar com `Tab`
#[derive(Debug, Clone, PartialEq)]
pub struct FileUiEntry {
    /// ID curto do manifesto (`cid.short()`, ex.: `"bafk1234"`)
    pub id: String,
    pub name: String,
    pub size: String,
    pub from: String,
    pub state: FileUiState,
}

/// Amigo exibido nos menus e painel lateral (enviado pelo backend em `UiEvent::FriendsChanged`)
#[derive(Debug, Clone, PartialEq)]
pub struct FriendUiEntry {
    pub public_key: String,
    pub display_name: String,
    pub online: bool,
    pub state: p2p_core::identity::FriendState,
}

/// Servidor exibido nos menus (enviado pelo backend em `UiEvent::ServersChanged`)
#[derive(Debug, Clone, PartialEq)]
pub struct ServerEntry {
    pub name: String,
    /// Id completo do servidor (usado em `/server switch <id>`)
    pub id: String,
    pub current: bool,
    pub owner: bool,
    pub moderator: bool,
    pub pending: bool,
    pub closed: bool,
}

/// Detalhes de um ban ativo para exibição no menu de bans
#[derive(Debug, Clone, PartialEq)]
pub struct BanUiEntry {
    pub target: String,
    pub target_nick: String,
    pub until: Option<u64>,
    pub reason: String,
    pub by: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MenuAction {
    /// Executa o comando como se tivesse sido digitado
    Run(String),
    /// Pergunta um texto e executa `template` com `{}` trocado pela resposta
    Ask { prompt: String, template: String },
    /// Abre um submenu
    Submenu(Menu),
    /// Alterna um item de checkbox no menu atual
    ToggleCheckbox,
    /// Aplica permissões selecionadas via checkboxes
    ApplyPermissions { nick: String },
    /// Abre a tela de ajuda
    Help,
    /// Copia `text` para a área de transferência; `what` descreve o que foi copiado
    Copy { text: String, what: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct MenuItem {
    pub label: String,
    pub action: MenuAction,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Menu {
    pub title: String,
    pub items: Vec<MenuItem>,
    pub selected: usize,
}

fn run(label: impl Into<String>, command: impl Into<String>) -> MenuItem {
    MenuItem { label: label.into(), action: MenuAction::Run(command.into()) }
}

fn copy(label: &str, text: &str, what: &str) -> MenuItem {
    MenuItem { label: label.to_string(), action: MenuAction::Copy { text: text.to_string(), what: what.to_string() } }
}

fn ask(label: &str, prompt: impl Into<String>, template: impl Into<String>) -> MenuItem {
    MenuItem { label: label.to_string(), action: MenuAction::Ask { prompt: prompt.into(), template: template.into() } }
}

impl Menu {
    pub fn new(title: impl Into<String>, items: Vec<MenuItem>) -> Self {
        Self { title: title.into(), items, selected: 0 }
    }

    pub fn up(&mut self) {
        self.selected = if self.selected == 0 { self.items.len().saturating_sub(1) } else { self.selected - 1 };
    }

    pub fn down(&mut self) {
        self.selected = if self.selected + 1 >= self.items.len() { 0 } else { self.selected + 1 };
    }

    pub fn current(&self) -> Option<&MenuItem> {
        self.items.get(self.selected)
    }

    #[cfg(test)]
    pub fn find(&self, label_start: &str) -> Option<usize> {
        self.items.iter().position(|i| i.label.contains(label_start))
    }
}

/// O que a interface sabe do contexto atual, para montar menus que fazem sentido
#[derive(Debug, Clone)]
pub struct MenuContext<'a> {
    pub in_server: bool,
    pub is_server_closed: bool,
    pub in_voice: bool,
    pub is_muted: bool,
    pub is_screen_sharing: bool,
    pub servers: &'a [ServerEntry],
    /// Pedidos de acesso pendentes do servidor atual: (nick, pubkey)
    pub access_requests: &'a [(String, String)],
    pub friends: &'a [FriendUiEntry],
}

/// Menu principal (F1) categorizado logicamente por seções
pub fn main_menu(ctx: &MenuContext) -> Menu {
    let items = vec![
        MenuItem {
            label: "🔀 Espaços e Servidores ▸".into(),
            action: MenuAction::Submenu(spaces_category_menu(ctx)),
        },
        MenuItem {
            label: "👥 Amigos e DMs ▸".into(),
            action: MenuAction::Submenu(friends_menu(ctx.friends)),
        },
        MenuItem {
            label: "📁 Arquivos e Transferências ▸".into(),
            action: MenuAction::Submenu(files_category_menu()),
        },
        MenuItem {
            label: "🔊 Áudio, Vídeo e Dispositivos ▸".into(),
            action: MenuAction::Submenu(media_category_menu(ctx)),
        },
        MenuItem {
            label: "⚙️ Configurações e Preferências ▸".into(),
            action: MenuAction::Submenu(config_category_menu(ctx)),
        },
        MenuItem { label: "❓ Ajuda e atalhos".into(), action: MenuAction::Help },
        run("⏻ Sair do Anarchord", "/quit"),
    ];
    Menu::new(" Menu Principal ", items)
}

/// Submenu da categoria Espaços e Servidores
pub fn spaces_category_menu(ctx: &MenuContext) -> Menu {
    let mut items = Vec::new();
    if ctx.in_server {
        // Pedidos de acesso pendentes (só chegam a quem pode emitir passaporte)
        if !ctx.access_requests.is_empty() {
            items.push(MenuItem {
                label: format!("🎫 Pedidos de acesso ({}) ▸", ctx.access_requests.len()),
                action: MenuAction::Submenu(access_requests_menu(ctx.access_requests)),
            });
        }
        items.push(run("📨 Convidar para este servidor", "/server invite"));
        items.push(ask("➕ Criar canal de texto…", "Nome do canal", "/server channel add {}"));
        items.push(ask("➕ Criar sala de voz…", "Nome da sala de voz", "/server channel add {} voz"));
        if let Some(current) = ctx.servers.iter().find(|s| s.current) {
            items.push(copy("📋 Copiar ID do servidor", &current.id, "ID do servidor"));
        }
        items.push(run("ℹ️ Informações do servidor", "/server info"));
        items.push(run("🔨 Membros banidos (/server bans)", "/server bans"));
        // Toggle inteligente de privacidade do servidor
        if ctx.is_server_closed {
            items.push(run("🔓 Tornar público (passaporte automático)", "/server open"));
        } else {
            items.push(run("🔒 Tornar privado (passaporte manual)", "/server close"));
        }
        items.push(run("📜 Histórico de alterações", "/server history"));
        let owner = ctx.servers.iter().any(|s| s.current && s.owner);
        let mut key_items = vec![run("🔑 Ver corrente de chaves", "/server key"), run("✅ Aceitar transferência recebida", "/server key accept")];
        if owner {
            key_items.insert(1, run("🔄 Renovar validade da chave", "/server key renew"));
            key_items.insert(2, ask("🤝 Transferir a chave para…", "Nick ou pubkey do novo dono", "/server key transfer {}"));
        }
        items.push(MenuItem { label: "🔑 Chave do Servidor ▸".into(), action: MenuAction::Submenu(Menu::new(" Chave do Servidor ", key_items)) });
        items.push(ask("⏳ Política de passaportes…", "Validade e janela de renovação (ex.: 7d 2d)", "/server policy {}"));
        items.push(MenuItem { label: "🚪 Sair deste servidor ▸".into(), action: MenuAction::Submenu(leave_menu()) });
    } else {
        items.push(ask("# Entrar em canal do Lobby…", "Nome do canal", "/join {}"));
    }
    items.push(MenuItem {
        label: "🔀 Trocar de espaço ▸".into(),
        action: MenuAction::Submenu(spaces_menu(ctx.servers)),
    });
    items.push(ask("🏰 Criar novo servidor…", "Nome do novo servidor", "/server create {}"));
    items.push(run("📨 Aceitar último convite", "/server accept"));
    items.push(ask("🔗 Entrar em servidor pelo id…", "Id do servidor (64 caracteres)", "/server join {}"));

    Menu::new(" Espaços e Servidores ", items)
}

/// Submenu da categoria Arquivos e Transferências
pub fn files_category_menu() -> Menu {
    Menu::new(
        " Arquivos e Transferências ",
        vec![
            run("📁 Gerenciador de arquivos (/files)", "/files"),
            ask("📎 Compartilhar arquivo na sala…", "Caminho do arquivo", "/share \"{}\""),
        ],
    )
}

/// Submenu da categoria Áudio, Vídeo e Dispositivos com toggles de estado
pub fn media_category_menu(ctx: &MenuContext) -> Menu {
    let mut items = Vec::new();

    // Toggle de voz
    if ctx.in_voice {
        items.push(run("🔇 Sair da sala de voz", "/voice leave"));
    } else {
        items.push(ask("🔊 Entrar em sala de voz…", "Nome da sala de voz", "/voice join {}"));
    }

    // Toggle de microfone
    if ctx.is_muted {
        items.push(run("🎙️ Desmutar microfone", "/mute"));
    } else {
        items.push(run("🔇 Mutar microfone", "/mute"));
    }

    // Toggle de transmissão de tela
    if ctx.is_screen_sharing {
        items.push(run("⏹️ Parar compartilhamento de tela", "/screen stop"));
    } else {
        items.push(run("📺 Compartilhar minha tela", "/screen start"));
    }

    items.push(run("🎧 Dispositivos de áudio", "/devices"));
    items.push(run("👥 Pares conectados", "/peers"));

    Menu::new(" Áudio, Vídeo e Dispositivos ", items)
}

/// Submenu da categoria Configurações e Preferências
pub fn config_category_menu(ctx: &MenuContext) -> Menu {
    let mut items = vec![
        run("📋 Ver configurações atuais (/config show)", "/config show"),
        ask("✏️ Alterar configuração…", "Chave e valor (ex.: mailbox.max_message_ttl_days 14)", "/config set {}"),
        run("🛡️ Firewall e IPs bloqueados (/firewall)", "/firewall"),
    ];
    if ctx.in_server {
        items.push(run("🔑 Rotacionar chave criptográfica do servidor", "/server rotate-key"));
    }
    Menu::new(" Configurações e Preferências ", items)
}

/// Submenu com o Lobby e os servidores conhecidos
pub fn spaces_menu(servers: &[ServerEntry]) -> Menu {
    let in_server = servers.iter().any(|s| s.current);
    let mut items = vec![run(if in_server { "  🌐 Lobby" } else { "▶ 🌐 Lobby" }, "/server switch lobby")];
    for s in servers {
        let mut tags = Vec::new();
        if s.owner {
            tags.push("dono");
        }
        if s.pending {
            tags.push("aguardando");
        }
        let tags = if tags.is_empty() { String::new() } else { format!(" [{}]", tags.join(", ")) };
        let label = format!("{} 🏰 {}{}", if s.current { "▶" } else { " " }, s.name, tags);
        items.push(MenuItem { label, action: MenuAction::Run(format!("/server switch {}", s.id)) });
    }
    Menu::new(" Trocar de espaço ", items)
}

/// Submenu de Amigos e Mensagens Diretas (DMs)
pub fn friends_menu(friends: &[FriendUiEntry]) -> Menu {
    let mut items = vec![
        ask("➕ Adicionar amigo…", "Pubkey (64 hex) ou nick conectado [apelido opcional]", "/friend add {}"),
        ask("💬 Enviar DM rápida…", "Destinatário e mensagem (ex.: Bob olá!)", "/dm {}"),
        run("📋 Listar amigos no log (/friends)", "/friends"),
    ];
    for f in friends {
        let (icon, sub_items) = match f.state {
            p2p_core::identity::FriendState::Confirmed => {
                let icon = if f.online { "🟢" } else { "⚪" };
                let items = vec![
                    run("💬 Abrir conversa direta (DM)", format!("/dm open {}", f.display_name)),
                    ask("📨 Enviar mensagem direta…", format!("Mensagem para {}", f.display_name), format!("/dm {} {{}}", f.display_name)),
                    run("💔 Remover dos amigos", format!("/friend remove {}", f.public_key)),
                ];
                (icon, items)
            }
            p2p_core::identity::FriendState::PendingIncoming => {
                let icon = "📩";
                let items = vec![
                    run("✅ Aceitar pedido de amizade", format!("/friend accept {}", f.public_key)),
                    run("❌ Rejeitar pedido de amizade", format!("/friend reject {}", f.public_key)),
                    run("💔 Remover / ignorar", format!("/friend remove {}", f.public_key)),
                ];
                (icon, items)
            }
            p2p_core::identity::FriendState::PendingOutgoing => {
                let icon = "⏳";
                let items = vec![
                    run("🔄 Reenviar pedido de amizade", format!("/friend resend {}", f.public_key)),
                    run("💔 Cancelar / remover pedido", format!("/friend remove {}", f.public_key)),
                ];
                (icon, items)
            }
            p2p_core::identity::FriendState::Rejected => {
                let icon = "🚫";
                let items = vec![
                    run("🔄 Reenviar pedido de amizade", format!("/friend resend {}", f.public_key)),
                    run("💔 Remover da lista", format!("/friend remove {}", f.public_key)),
                ];
                (icon, items)
            }
        };
        let mut sub_items = sub_items;
        sub_items.push(copy("📋 Copiar chave pública", &f.public_key, &format!("Chave pública de {}", f.display_name)));
        let short_pk = if f.public_key.len() >= 8 { &f.public_key[..8] } else { &f.public_key };
        let label = format!("{} {} ({}) ▸", icon, f.display_name, short_pk);
        let sub = Menu::new(format!(" {} ", f.display_name), sub_items);
        items.push(MenuItem { label, action: MenuAction::Submenu(sub) });
    }
    Menu::new(" Amigos e DMs ", items)
}

/// Menu de contexto de um membro da sala, com toggles inteligentes e convites ubíquos
pub fn member_menu(
    nick: &str,
    pubkey: Option<&str>,
    is_friend: bool,
    in_server: bool,
    can_moderate: bool,
    is_moderator: bool,
    inviteable_servers: &[ServerEntry],
) -> Menu {
    let mut items = vec![
        run("💬 Abrir conversa direta (DM)", format!("/dm open {}", nick)),
        ask("📨 Enviar mensagem direta…", format!("Mensagem privada para {}", nick), format!("/dm {} {{}}", nick)),
        ask("📁 Enviar arquivo…", format!("Caminho do arquivo para {}", nick), format!("/send {} \"{{}}\"", nick)),
        run("📺 Assistir tela", format!("/screen watch {}", nick)),
    ];
    if let Some(pubkey) = pubkey {
        items.push(copy("📋 Copiar chave pública", pubkey, &format!("Chave pública de {}", nick)));
    }

    // Toggle de Amizade (nunca exibe os dois simultaneamente)
    if is_friend {
        items.push(run("💔 Remover dos amigos", format!("/friend remove {}", nick)));
    } else {
        items.push(run("💚 Adicionar aos amigos", format!("/friend add {}", nick)));
    }

    // Convidar para Servidor (Ubíquo: em qualquer lugar onde o usuário tem autoridade)
    let invite_items = if inviteable_servers.is_empty() {
        vec![MenuItem {
            label: "Nenhum servidor administrado".into(),
            action: MenuAction::Run("/server list".into()),
        }]
    } else {
        inviteable_servers
            .iter()
            .map(|s| MenuItem {
                label: format!("🏰 {}", s.name),
                action: MenuAction::Run(format!("/server invite {} {}", s.id, nick)),
            })
            .collect()
    };
    items.push(MenuItem {
        label: "🏰 Convidar para Servidor ▸".into(),
        action: MenuAction::Submenu(Menu::new(format!(" Convidar {} ", nick), invite_items)),
    });

    if in_server && can_moderate {
        let mod_item = if is_moderator {
            run("🛡️ Remover moderador", format!("/server mod remove {}", nick))
        } else {
            run("🛡️ Tornar moderador", format!("/server mod add {}", nick))
        };
        items.extend([
            MenuItem {
                label: "🛡️ Permissões e Moderação ▸".into(),
                action: MenuAction::Submenu(permissions_menu(nick, is_moderator)),
            },
            mod_item,
            MenuItem { label: "🔨 Banir ▸".into(), action: MenuAction::Submenu(ban_menu(nick)) },
            run("🎫 Emitir passaporte de membro", format!("/server passport issue {}", nick)),
            run("🚫 Revogar passaporte", format!("/server revoke {}", nick)),
        ]);
    }

    Menu::new(format!(" {} ", nick), items)
}

/// Submenu interativo com checkboxes para seleção de permissões de moderador
pub fn permissions_menu(nick: &str, _is_moderator: bool) -> Menu {
    let items = vec![
        MenuItem {
            label: "[X] 🚪 Acessar Servidor (EnterServer)".into(),
            action: MenuAction::ToggleCheckbox,
        },
        MenuItem {
            label: "[X] 🔨 Banir Membros (Ban)".into(),
            action: MenuAction::ToggleCheckbox,
        },
        MenuItem {
            label: "[X] 🎫 Emitir Membro (IssueMember)".into(),
            action: MenuAction::ToggleCheckbox,
        },
        MenuItem {
            label: "[ ] 👑 Delegar Moderadores (Delegate)".into(),
            action: MenuAction::ToggleCheckbox,
        },
        MenuItem {
            label: "[ ] 💬 Gerenciar Canais (ManageChannels)".into(),
            action: MenuAction::ToggleCheckbox,
        },
        MenuItem {
            label: "[ ] ⚙️ Gerenciar Servidor (ManageConfig)".into(),
            action: MenuAction::ToggleCheckbox,
        },
        MenuItem {
            label: "💾 Aplicar Permissões Selecionadas".into(),
            action: MenuAction::ApplyPermissions { nick: nick.to_string() },
        },
        MenuItem {
            label: "🛡️ Aplicar Perfil Padrão (Ban + Convidar)".into(),
            action: MenuAction::Run(format!("/server mod add {}", nick)),
        },
        MenuItem {
            label: "❌ Revogar Moderação".into(),
            action: MenuAction::Run(format!("/server mod remove {}", nick)),
        },
    ];
    Menu::new(format!(" Permissões de {} ", nick), items)
}

/// Menu interativo de membros banidos com desbanimento em 1 clique
pub fn bans_menu(server_name: &str, bans: &[BanUiEntry]) -> Menu {
    let items = if bans.is_empty() {
        vec![MenuItem {
            label: "Nenhum membro banido no momento".into(),
            action: MenuAction::Run("/server info".into()),
        }]
    } else {
        bans.iter()
            .map(|b| {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                let dur = b.until.map_or("permanente".to_string(), |u| {
                    format!("expira em {}", p2p_core::community::cert::format_duration(Some(u.saturating_sub(now))))
                });
                let name = if b.target_nick.is_empty() {
                    if b.target.len() >= 8 { &b.target[..8] } else { &b.target }
                } else {
                    &b.target_nick
                };
                let label = format!("🕊️ Desbanir {} ({})", name, dur);
                MenuItem {
                    label,
                    action: MenuAction::Run(format!("/server unban {}", b.target)),
                }
            })
            .collect()
    };
    Menu::new(format!(" Membros Banidos ({}) ", server_name), items)
}

/// Duração do ban; cada opção pergunta o motivo (opcional)
/// Pedidos de acesso pendentes: cada um abre as ações de emitir passaporte (membro ou moderador)
/// ou dispensar, sem precisar digitar nada
pub fn access_requests_menu(requests: &[(String, String)]) -> Menu {
    let items = requests
        .iter()
        .map(|(nick, pubkey)| MenuItem {
            label: format!("{} ({}) ▸", nick, &pubkey[..pubkey.len().min(8)]),
            action: MenuAction::Submenu(Menu::new(
                format!(" Pedido de {} ", nick),
                vec![
                    run("✅ Emitir passaporte de membro", format!("/server passport issue {}", pubkey)),
                    run("🛡️ Emitir passaporte de moderador", format!("/server passport issue {} mod", pubkey)),
                    run("🙈 Dispensar (não bane; pode pedir de novo)", format!("/server dismiss {}", pubkey)),
                ],
            )),
        })
        .collect();
    Menu::new(" Pedidos de acesso ", items)
}

/// Confirmação de saída: sair renuncia ao passaporte (Esc cancela)
pub fn leave_menu() -> Menu {
    Menu::new(
        " Sair do servidor? ",
        vec![run("✅ Sair e renunciar ao passaporte (em servidor privado, só volta com um novo)", "/server leave")],
    )
}

pub fn ban_menu(nick: &str) -> Menu {
    let option = |label: &str, duration: &str| {
        ask(label, format!("Motivo do ban de {} (opcional)", nick), format!("/server ban {} {} {{}}", nick, duration))
    };
    Menu::new(
        format!(" Banir {} ", nick),
        vec![option("⏱️ 1 hora", "1h"), option("📅 1 dia", "1d"), option("🗓️ 7 dias", "7d"), option("⛔ Permanente", "perm")],
    )
}

/// Menu de contexto de um canal do painel de canais
pub fn channel_menu(name: &str, is_voice: bool) -> Menu {
    let items = if is_voice {
        vec![
            run("🔊 Entrar na sala de voz", format!("/voice join {}", name)),
            run("🔇 Sair da sala de voz", "/voice leave"),
        ]
    } else {
        vec![run("# Entrar no canal", format!("/join {}", name))]
    };
    Menu::new(format!(" {}{} ", if is_voice { "🔊 " } else { "#" }, name), items)
}

/// Popup interativo e clicável de arquivos (`/files`), permitindo clicar num arquivo para
/// baixar (`/get`), recusar (`/reject`) ou parar de compartilhar (`/unshare`).
pub fn files_menu(files: &[FileUiEntry]) -> Menu {
    let mut items = Vec::new();
    for f in files {
        let (icon, status, actions) = match &f.state {
            FileUiState::Offered => (
                "📥",
                format!("oferecido por {} · clique para baixar", f.from),
                vec![
                    run(format!("📥 Baixar '{}' (/get {})", f.name, f.id), format!("/get {}", f.id)),
                    run(format!("❌ Recusar oferta (/reject {})", f.id), format!("/reject {}", f.id)),
                ],
            ),
            FileUiState::Downloading { progress, peers } => (
                "⏳",
                format!("baixando {:.0}% ({} par(es))", progress * 100.0, peers),
                vec![
                    run(format!("🛑 Cancelar download (/unshare {})", f.id), format!("/unshare {}", f.id)),
                ],
            ),
            FileUiState::Seeding => (
                "📤",
                "compartilhando".to_string(),
                vec![
                    run(format!("🛑 Parar de compartilhar (/unshare {})", f.id), format!("/unshare {}", f.id)),
                ],
            ),
        };
        let size_part = if f.size.is_empty() { String::new() } else { format!(" ({})", f.size) };
        let label = format!("{} [{}] {}{} — {} ▸", icon, f.id, f.name, size_part, status);
        let sub = Menu::new(format!(" 📁 {} [{}] ", f.name, f.id), actions);
        items.push(MenuItem { label, action: MenuAction::Submenu(sub) });
    }
    items.push(ask("📎 Compartilhar novo arquivo na sala…", "Caminho do arquivo", "/share \"{}\""));
    let title = if files.is_empty() {
        " 📁 Arquivos (nenhum arquivo ativo) ".to_string()
    } else {
        format!(" 📁 Arquivos ({}) — clique ou Enter para escolher ", files.len())
    };
    Menu::new(title, items)
}

/// Comando para entrar num canal ao clicar nele
pub fn channel_command(name: &str, is_voice: bool) -> String {
    if is_voice {
        format!("/voice join {}", name)
    } else {
        format!("/join {}", name)
    }
}

/// Texto da tela de ajuda
pub const HELP_LINES: &[&str] = &[
    "ATALHOS",
    "  F1 ou Ctrl+K     abre o menu principal (Servidores, Amigos, DMs, Voz)",
    "  Clique           membro/amigo: ações (DM, arquivo, tela, amigo) · canal: entrar",
    "  ↑ / ↓            histórico do que você digitou",
    "  ← → Home End     move o cursor · Delete apaga à frente",
    "  Tab              completa comandos e nicks",
    "  F2               alterna entre as abas Chat e Sistema (ou clique no nome da aba)",
    "  PgUp / PgDn      rola a aba atual (roda do mouse também)",
    "  Esc              fecha menus e diálogos · Ctrl+C sai",
    "",
    "COMANDOS",
    "  /join <canal>            /voice join <sala>     /voice leave     /mute",
    "  /friend add <pk|nick> [apelido]   /friend remove <pk|apelido>    /friends",
    "  /dm open <par>           /dm <par> <mensagem> [--ttl 2h|7d]",
    "  /config show             /config set <chave> <valor>",
    "  /firewall                /firewall unblock <par>",
    "  /share <arquivo>         compartilha na sala atual (quem quiser baixa com /get)",
    "  /send <par> <arquivo>    /get <id>      /reject <id>      /files      /unshare <id>",
    "  /screen start [monitor] [720|1080]   /screen stop   /screen watch <par>",
    "  /server create <nome>    /server accept         /server switch <nome|lobby>",
    "  /server invite           /server channel add <nome> [voz]",
    "  /server mod add <par>    /server ban <par> [motivo]   /server unban <par>",
    "  /server list · info · leave      /lobby      /peers      /devices      /quit",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, current: bool) -> ServerEntry {
        ServerEntry {
            name: name.into(),
            id: format!("{}-id", name),
            current,
            owner: true,
            moderator: false,
            pending: false,
            closed: false,
        }
    }

    #[test]
    fn test_main_menu_depends_on_context() {
        let lobby_ctx = MenuContext {
            in_server: false,
            is_server_closed: false,
            in_voice: false,
            is_muted: false,
            is_screen_sharing: false,
            servers: &[],
            access_requests: &[],
            friends: &[],
        };
        let lobby = main_menu(&lobby_ctx);
        assert!(lobby.find("Espaços e Servidores").is_some());
        assert!(lobby.find("Amigos e DMs").is_some());
        assert!(lobby.find("Arquivos e Transferências").is_some());
        assert!(lobby.find("Áudio, Vídeo e Dispositivos").is_some());
        assert!(lobby.find("Configurações").is_some());

        let spaces_lobby = spaces_category_menu(&lobby_ctx);
        assert!(spaces_lobby.find("Criar novo servidor").is_some());
        assert!(spaces_lobby.find("Convidar").is_none(), "no Lobby não há servidor para convidar");

        let server_ctx = MenuContext {
            in_server: true,
            is_server_closed: false,
            in_voice: true,
            is_muted: false,
            is_screen_sharing: true,
            servers: &[],
            access_requests: &[],
            friends: &[],
        };
        let spaces_server = spaces_category_menu(&server_ctx);
        assert!(spaces_server.find("Convidar").is_some());
        assert!(spaces_server.find("Criar canal de texto").is_some());
        assert!(spaces_server.find("Tornar privado").is_some(), "servidor aberto mostra opção de fechar");
        assert!(spaces_server.find("Tornar público").is_none());

        // Teste de toggle de privacidade quando fechado
        let mut server_closed_ctx = server_ctx.clone();
        server_closed_ctx.is_server_closed = true;
        let spaces_closed = spaces_category_menu(&server_closed_ctx);
        assert!(spaces_closed.find("Tornar público").is_some());
        assert!(spaces_closed.find("Tornar privado").is_none());

        // Teste de toggles de mídia
        let media = media_category_menu(&server_ctx);
        assert!(media.find("Sair da sala de voz").is_some());
        assert!(media.find("Mutar microfone").is_some());
        assert!(media.find("Parar compartilhamento de tela").is_some(), "já compartilhando");
        assert!(media.find("Compartilhar minha tela").is_none());
    }

    #[test]
    fn test_spaces_menu_marks_current_space() {
        let menu = spaces_menu(&[entry("Guild", true), entry("Outro", false)]);
        assert_eq!(menu.items.len(), 3);
        assert_eq!(menu.items[0].label, "  🌐 Lobby");
        assert!(menu.items[1].label.starts_with("▶ 🏰 Guild"));
        assert_eq!(menu.items[2].action, MenuAction::Run("/server switch Outro-id".into()));
    }

    #[test]
    fn test_member_menu_moderation_and_toggles() {
        let servers = vec![entry("Minha Guild", false)];

        // No Lobby e sem amizade
        let lobby_non_friend = member_menu("Bob", None, false, false, false, false, &servers);
        assert!(lobby_non_friend.find("Banir").is_none());
        assert!(lobby_non_friend.find("Adicionar aos amigos").is_some());
        assert!(lobby_non_friend.find("Remover dos amigos").is_none());
        assert!(lobby_non_friend.find("Convidar para Servidor").is_some(), "convite ubíquo presente");

        // Já amigo (toggle)
        let friend_menu = member_menu("Bob", None, true, false, false, false, &servers);
        assert!(friend_menu.find("Adicionar aos amigos").is_none());
        assert!(friend_menu.find("Remover dos amigos").is_some());

        // Em servidor com autoridade de moderação
        let menu = member_menu("Bob", None, false, true, true, false, &servers);
        let ban = &menu.items[menu.find("Banir").unwrap()];
        let MenuAction::Submenu(durations) = &ban.action else { panic!("Banir abre as durações") };
        let day = &durations.items[durations.find("1 dia").unwrap()];
        assert_eq!(day.action, MenuAction::Ask { prompt: "Motivo do ban de Bob (opcional)".into(), template: "/server ban Bob 1d {}".into() });
        assert!(menu.find("Tornar moderador").is_some());
        assert!(menu.find("Remover moderador").is_none());
        assert!(menu.find("Emitir passaporte").is_some());
        let file = &menu.items[menu.find("Enviar arquivo").unwrap()];
        assert!(matches!(&file.action, MenuAction::Ask { template, .. } if template == "/send Bob \"{}\""));

        // Se o alvo já for moderador
        let mod_target_menu = member_menu("Bob", None, false, true, true, true, &servers);
        assert!(mod_target_menu.find("Remover moderador").is_some());
        assert!(mod_target_menu.find("Tornar moderador").is_none());
    }

    #[test]
    fn test_bans_menu_actions() {
        let bans = vec![BanUiEntry {
            target: "1122334455667788".into(),
            target_nick: "Spammer".into(),
            until: None,
            reason: "flood".into(),
            by: "Admin".into(),
        }];
        let menu = bans_menu("Meu Servidor", &bans);
        assert_eq!(menu.items.len(), 1);
        assert!(menu.items[0].label.contains("Desbanir Spammer"));
        assert_eq!(menu.items[0].action, MenuAction::Run("/server unban 1122334455667788".into()));
    }

    #[test]
    fn test_permissions_menu_structure_and_actions() {
        let menu = permissions_menu("Carol", false);
        assert!(menu.find("Acessar Servidor").is_some());
        assert!(menu.find("Banir Membros").is_some());
        assert!(menu.find("Gerenciar Canais").is_some());
        assert!(menu.find("Gerenciar Servidor").is_some());
        assert!(menu.find("Aplicar Permissões").is_some());

        let ban_item = &menu.items[menu.find("Banir Membros").unwrap()];
        assert_eq!(ban_item.action, MenuAction::ToggleCheckbox);

        let apply_item = &menu.items[menu.find("Aplicar Permissões").unwrap()];
        assert_eq!(apply_item.action, MenuAction::ApplyPermissions { nick: "Carol".into() });
    }

    #[test]
    fn test_menu_navigation_wraps() {
        let mut menu = channel_menu("voz", true);
        assert_eq!(menu.selected, 0);
        menu.up();
        assert_eq!(menu.selected, 1);
        menu.down();
        assert_eq!(menu.selected, 0);
    }
}
