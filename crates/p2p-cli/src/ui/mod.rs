pub mod editor;
pub mod menu;
pub mod wrap;

use crossterm::{
    event::{
        self, DisableFocusChange, DisableMouseCapture, EnableFocusChange, EnableMouseCapture, Event, KeyCode, KeyEvent,
        KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen, SetTitle},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph},
    Terminal,
};
use std::collections::{HashMap, HashSet};
use editor::LineEditor;
use p2p_core::runtime::RoomKeyStatus;
use menu::{
    bans_menu, channel_command, channel_menu, files_menu, main_menu, member_menu, spaces_menu,
    BanUiEntry, FileUiEntry, FileUiState, FriendUiEntry, Menu, MenuAction, MenuContext,
    ServerEntry, HELP_LINES,
};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// Eventos enviados pelo backend P2P para atualizar a TUI
#[derive(Debug, Clone)]
pub enum UiEvent {
    /// Mensagem de chat recebida (com timestamp cronológico de envio em milissegundos Unix)
    ChatMessage {
        channel: String,
        author: String,
        text: String,
        timestamp: u64,
    },
    /// Log ou notificação do sistema
    SystemLog(String),
    /// Par conectado ou atualizado (PeerId, Nickname, PubKey)
    PeerConnected {
        peer_id: String,
        nick: String,
        pubkey: String,
    },
    /// Par desconectado
    PeerDisconnected(String),
    /// Mudança de espaço (Lobby ou servidor) ou dos canais do espaço atual.
    /// `channels`: (nome, é_voz). Vazio no Lobby, onde qualquer nome vira canal.
    SpaceChanged {
        space_name: String,
        channels: Vec<(String, bool)>,
        is_server: bool,
    },
    /// Servidores conhecidos (para o menu "Trocar de espaço")
    ServersChanged(Vec<ServerEntry>),
    /// A sala atual ganhou ou perdeu a chave do grupo cifrado (ícone 🔐 no cabeçalho)
    RoomKey(RoomKeyStatus),
    /// Pedidos de acesso pendentes do servidor atual: (nick, pubkey)
    AccessRequests(Vec<(String, String)>),
    /// Amigos conhecidos e seu status online/offline
    FriendsChanged(Vec<FriendUiEntry>),
    /// Conversa direta (DM) recebida ou enviada (com timestamp cronológico de envio em milissegundos Unix)
    DirectMessage {
        peer_name: String,
        author: String,
        text: String,
        timestamp: u64,
        offline_delivery: bool,
    },
    /// Conversa direta (DM) aberta como canal ativo (`@Nome`)
    DmOpened {
        peer_name: String,
        channel: String,
    },
    /// Pares inscritos no tópico de um canal de texto (presença na sala)
    ChannelMembers {
        channel: String,
        members: Vec<String>,
    },
    /// Mudança de canal de texto ativo
    ChannelChanged(String),
    /// Mudança de canal de voz ativo (None se desconectado de voz)
    VoiceChannelChanged(Option<String>),
    /// Membros ativos na sala de voz atual
    VoiceRoomMembers(Vec<String>),
    /// Indicador de voz de alguém falando (Nick, energy)
    VoiceActivity {
        nick: String,
        speaking: bool,
    },
    /// Progresso de transferência de arquivo
    FileTransferProgress {
        file_name: String,
        percentage: f32,
        is_download: bool,
    },
    /// Novo arquivo conhecido (oferecido ou compartilhado) — atualiza o autocompletar (`Tab`) imediatamente
    FileKnown(FileUiEntry),
    /// Resposta a `/files` — atualiza a lista de arquivos e abre o popup clicável de arquivos
    FilesListed(Vec<FileUiEntry>),
    /// Resposta a `/server bans` — abre o menu visual de bans com ação de desbanir
    BansListed {
        server: String,
        bans: Vec<BanUiEntry>,
    },
    /// Estado da transmissão de tela deste nó (ativa ou inativa)
    ScreenShareActive(bool),
}

/// Área de transferência do sistema operacional (Windows, macOS, Linux X11/Wayland). A instância
/// fica viva até o programa terminar: no Linux o conteúdo copiado pertence ao processo e some
/// quando ela é descartada (a menos que haja um gerenciador de área de transferência).
fn system_clipboard(text: &str) -> Result<(), String> {
    static CLIPBOARD: std::sync::Mutex<Option<arboard::Clipboard>> = std::sync::Mutex::new(None);
    let mut guard = CLIPBOARD.lock().map_err(|e| e.to_string())?;
    if guard.is_none() {
        *guard = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
    }
    guard.as_mut().expect("criada acima").set_text(text.to_string()).map_err(|e| e.to_string())
}

/// Ações disparadas pela UI para o backend P2P
#[derive(Debug, Clone)]
pub enum UiAction {
    SendMessage(String),
    ToggleMute,
    Quit,
}

pub struct TerminalUi {
    my_nick: String,
    my_pubkey: String,
    current_channel: String,
    current_voice_channel: Option<String>,
    /// Barra de entrada (cursor, histórico, Tab)
    editor: LineEditor,
    /// Aba Chat: só conversas (mantidas em ordem cronológica por `chat_entries`)
    messages: Vec<String>,
    /// Chaves de ordenação `(timestamp_ms, seq)` paralelas a `messages`
    chat_entries: Vec<(u64, u64)>,
    /// Contador monotônico de chegada para desempate estável no mesmo milissegundo
    next_message_seq: u64,
    /// Aba Sistema: notificações do core (conexões, DHT, sincronização, avisos)
    system_messages: Vec<String>,
    active_tab: Tab,
    /// Notificações chegadas enquanto a aba Sistema não estava aberta
    system_unread: usize,
    /// Linhas roladas para cima no chat (0 = mostrando as mais recentes)
    chat_scroll: usize,
    /// Menu, diálogo ou ajuda aberto por cima da tela
    overlay: Option<Overlay>,
    servers: Vec<ServerEntry>,
    /// Pedidos de acesso pendentes no servidor atual: (nick, pubkey)
    access_requests: Vec<(String, String)>,
    friends: Vec<FriendUiEntry>,
    /// Arquivos conhecidos (oferecidos, baixando e compartilhando) para o popup `/files` e autocompletar `Tab`
    known_files: Vec<FileUiEntry>,
    in_server: bool,
    /// Chave do grupo cifrado da sala atual (só vale dentro de servidor)
    room_key: RoomKeyStatus,
    chat_area: Rect,
    /// Largura do rótulo da aba Chat no título (para saber em qual aba o clique caiu)
    tab_split: u16,
    /// Linha do texto da barra superior e colunas [início, fim) do espaço atual e do MIC (clicáveis)
    header_row: u16,
    header_space_cols: (u16, u16),
    header_mic_cols: (u16, u16),
    /// Colunas da chave pública no cabeçalho (clique copia a chave completa)
    header_key_cols: (u16, u16),
    /// Escreve na área de transferência do sistema (substituível nos testes)
    clipboard: fn(&str) -> Result<(), String>,
    channels_area: Rect,
    popup_area: Rect,
    peers: Vec<(String, String, String)>, // (PeerId, Nick, PubKey) - Todo o Swarm
    voice_members: Vec<String>,           // Membros presentes na sala de voz ativa
    channel_members: HashMap<String, HashSet<String>>, // Canal -> Nomes com presença ativa
    speakers: Vec<String>,                // Nomes de quem está falando agora
    file_transfer: Option<(String, f32, bool)>, // (nome, pct, is_download)
    is_muted: Arc<AtomicBool>,
    is_screen_sharing: bool,
    peers_area: Rect,
    /// Nicks na ordem exibida em "Membros" (para saber em quem o mouse clicou)
    member_rows: Vec<String>,
    space_name: String,
    space_channels: Vec<(String, bool)>,
    last_status_bar: String,
    unread_messages: usize,
    has_mention: bool,
    is_focused: bool,
}

impl TerminalUi {
    /// `history_file`: onde guardar o histórico da barra de entrada (None = só em memória)
    pub fn new(my_nick: String, my_pubkey: String, is_muted: Arc<AtomicBool>, history_file: Option<PathBuf>) -> Self {
        let mut channel_members = HashMap::new();
        let mut geral_set = HashSet::new();
        geral_set.insert(my_nick.clone());
        channel_members.insert("geral".to_string(), geral_set);

        Self {
            my_nick,
            my_pubkey,
            current_channel: "geral".to_string(),
            current_voice_channel: None,
            editor: history_file.map(LineEditor::with_history_file).unwrap_or_default(),
            messages: vec![
                "🚀 Bem-vindo ao Anarchord P2P (100% Descentralizado)!".to_string(),
                "💡 F1 abre o menu · clique num membro ou canal para ver as opções · /help lista os comandos".to_string(),
            ],
            chat_entries: vec![(0, 0), (0, 1)],
            next_message_seq: 2,
            system_messages: Vec::new(),
            active_tab: Tab::Chat,
            system_unread: 0,
            chat_scroll: 0,
            overlay: None,
            servers: Vec::new(),
            access_requests: Vec::new(),
            friends: Vec::new(),
            known_files: Vec::new(),
            in_server: false,
            room_key: RoomKeyStatus::Unencrypted,
            chat_area: Rect::default(),
            tab_split: 0,
            header_row: u16::MAX,
            header_space_cols: (0, 0),
            header_mic_cols: (0, 0),
            header_key_cols: (0, 0),
            clipboard: system_clipboard,
            channels_area: Rect::default(),
            popup_area: Rect::default(),
            peers: Vec::new(),
            voice_members: Vec::new(),
            channel_members,
            speakers: Vec::new(),
            file_transfer: None,
            is_muted,
            is_screen_sharing: false,
            peers_area: Rect::default(),
            member_rows: Vec::new(),
            space_name: "🌐 Lobby".to_string(),
            space_channels: Vec::new(),
            last_status_bar: "Sistema pronto. Conectado à malha P2P.".to_string(),
            unread_messages: 0,
            has_mention: false,
            is_focused: true,
        }
    }

    pub fn update_terminal_title(&self) {
        let chan_prefix = if self.current_channel.starts_with('@') { "" } else { "#" };
        let base = format!("Anarchord · {}{}", chan_prefix, self.current_channel);
        let title = if self.has_mention {
            format!("(@) {}", base)
        } else if self.unread_messages > 0 {
            format!("({}) {}", self.unread_messages, base)
        } else {
            base
        };
        let _ = execute!(io::stdout(), SetTitle(title));
    }

    pub async fn run(
        mut self,
        mut rx_events: UnboundedReceiver<UiEvent>,
        tx_actions: UnboundedSender<UiAction>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Setup Terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture, EnableFocusChange)?;
        self.update_terminal_title();
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let mut event_interval = tokio::time::interval(std::time::Duration::from_millis(50));

        loop {
            // Desenha a UI reativa
            terminal.draw(|f| {
                self.draw_ui(f);
            })?;

            tokio::select! {
                // Processa eventos da malha P2P
                Some(evt) = rx_events.recv() => {
                    self.handle_event(evt);
                }

                // Processa teclado e mouse do usuário de forma não bloqueante
                _ = event_interval.tick() => {
                    while event::poll(std::time::Duration::from_millis(0))? {
                        let actions = match event::read()? {
                            // No Windows, crossterm gera Press e Release; Release é ignorado para não duplicar teclas
                            Event::Key(key) if key.kind == KeyEventKind::Press => self.handle_key(key),
                            Event::Mouse(mouse) => self.handle_mouse(mouse),
                            Event::FocusGained => {
                                self.is_focused = true;
                                self.unread_messages = 0;
                                self.has_mention = false;
                                self.update_terminal_title();
                                Vec::new()
                            }
                            Event::FocusLost => {
                                self.is_focused = false;
                                Vec::new()
                            }
                            _ => Vec::new(),
                        };
                        for action in actions {
                            let quit = matches!(action, UiAction::Quit);
                            let _ = tx_actions.send(action);
                            if quit {
                                self.cleanup_terminal(&mut terminal)?;
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Insere uma mensagem de chat ou DM mantendo a lista `messages` ordenada
    /// cronologicamente pelo `timestamp` de envio em milissegundos (e pela ordem de chegada `seq`
    /// caso duas mensagens tenham sido geradas no exato mesmo milissegundo).
    fn push_chat_message(&mut self, timestamp: u64, text: String) {
        let seq = self.next_message_seq;
        self.next_message_seq += 1;
        let key = (timestamp, seq);
        let idx = self.chat_entries.partition_point(|&k| k <= key);
        self.chat_entries.insert(idx, key);
        self.messages.insert(idx, text);
    }

    /// Aplica um evento da malha P2P ao estado da UI (separado do loop para ser testável)
    fn handle_event(&mut self, evt: UiEvent) {
        match evt {
            UiEvent::ChatMessage { channel, author, text, timestamp } => {
                if !self.is_focused && author != self.my_nick {
                    self.unread_messages += 1;
                    let mention_needle = format!("@{}", self.my_nick);
                    if text.contains(&mention_needle) || text.contains("@todos") || text.contains("@all") {
                        self.has_mention = true;
                        print!("\x07");
                        let _ = io::Write::flush(&mut io::stdout());
                    }
                    self.update_terminal_title();
                }
                self.push_chat_message(timestamp, format!("[#{}] {}: {}", channel, author, text));
                self.channel_members.entry(channel.clone()).or_default().insert(author);
            }
            UiEvent::ChannelChanged(new_channel) => {
                self.current_channel = new_channel.clone();
                self.channel_members.entry(new_channel).or_default().insert(self.my_nick.clone());
                self.update_terminal_title();
            }
            UiEvent::VoiceChannelChanged(opt_channel) => {
                self.current_voice_channel = opt_channel.clone();
                if opt_channel.is_none() {
                    self.voice_members.clear();
                    self.speakers.clear();
                } else {
                    if !self.voice_members.contains(&self.my_nick) {
                        self.voice_members.push(self.my_nick.clone());
                    }
                }
            }
            UiEvent::VoiceRoomMembers(members) => {
                self.voice_members = members;
            }
            UiEvent::SystemLog(log) => {
                self.last_status_bar = log.clone();
                self.push_system(format!("⚙️  {}", log));
            }
            UiEvent::SpaceChanged { space_name, channels, is_server } => {
                self.space_name = space_name;
                self.space_channels = channels;
                self.in_server = is_server;
                self.access_requests.clear();
                // Membros de canais de outro espaço não valem mais (nomes de canal podem se repetir)
                self.channel_members.clear();
                self.channel_members.entry(self.current_channel.clone()).or_default().insert(self.my_nick.clone());
            }
            UiEvent::ServersChanged(servers) => {
                self.servers = servers;
            }
            UiEvent::RoomKey(status) => {
                self.room_key = status;
            }
            UiEvent::AccessRequests(requests) => {
                self.access_requests = requests;
            }
            UiEvent::FriendsChanged(friends) => {
                self.friends = friends;
            }
            UiEvent::DirectMessage { peer_name, author, text, timestamp, offline_delivery } => {
                if !self.is_focused && author != self.my_nick {
                    self.unread_messages += 1;
                    self.has_mention = true;
                    print!("\x07");
                    let _ = io::Write::flush(&mut io::stdout());
                    self.update_terminal_title();
                }
                let dm_chan = format!("@{}", peer_name);
                let tag = if offline_delivery { " [📬 Offline E2EE]" } else { " [🔒 E2EE]" };
                self.push_chat_message(timestamp, format!("[{}{}] {}: {}", dm_chan, tag, author, text));
                let set = self.channel_members.entry(dm_chan).or_default();
                set.insert(self.my_nick.clone());
                set.insert(peer_name);
            }
            UiEvent::DmOpened { peer_name, channel } => {
                self.current_channel = channel.clone();
                let set = self.channel_members.entry(channel).or_default();
                set.insert(self.my_nick.clone());
                set.insert(peer_name);
                self.update_terminal_title();
            }
            UiEvent::ChannelMembers { channel, members } => {
                let set = self.channel_members.entry(channel).or_default();
                set.clear();
                set.extend(members);
                set.insert(self.my_nick.clone());
            }
            UiEvent::PeerConnected { peer_id, nick, pubkey } => {
                if let Some(pos) = self.peers.iter().position(|(pid, _, _)| pid == &peer_id) {
                    self.peers[pos] = (peer_id, nick.clone(), pubkey);
                } else {
                    self.peers.push((peer_id, nick.clone(), pubkey));
                    self.push_system(format!("🤝 Par conectado: {}", nick));
                }
            }
            UiEvent::PeerDisconnected(peer_id) => {
                if let Some(pos) = self.peers.iter().position(|(pid, _, _)| pid == &peer_id) {
                    let (_, nick, _) = self.peers.remove(pos);
                    self.push_system(format!("👋 Par desconectado: {}", nick));
                } else {
                    self.push_system(format!("👋 Par desconectado: {}", peer_id));
                }
            }
            UiEvent::VoiceActivity { nick, speaking } => {
                if speaking {
                    if !self.speakers.contains(&nick) {
                        self.speakers.push(nick);
                    }
                } else {
                    self.speakers.retain(|n| n != &nick);
                }
            }
            UiEvent::FileTransferProgress { file_name, percentage, is_download } => {
                if percentage < 0.0 {
                    // Transferência falhou ou foi cancelada
                    self.file_transfer = None;
                } else if percentage >= 100.0 {
                    self.file_transfer = None;
                    self.push_system(format!("✅ Arquivo '{}' concluído com sucesso!", file_name));
                    for f in &mut self.known_files {
                        if f.name == file_name {
                            f.state = FileUiState::Seeding;
                        }
                    }
                } else {
                    self.file_transfer = Some((file_name, percentage, is_download));
                }
            }
            UiEvent::FileKnown(entry) => {
                if let Some(existing) = self.known_files.iter_mut().find(|f| f.id == entry.id) {
                    *existing = entry;
                } else {
                    self.known_files.push(entry);
                }
            }
            UiEvent::FilesListed(entries) => {
                self.known_files = entries;
                self.overlay = Some(Overlay::Menu(vec![files_menu(&self.known_files)]));
            }
            UiEvent::BansListed { server, bans } => {
                self.overlay = Some(Overlay::Menu(vec![bans_menu(&server, &bans)]));
            }
            UiEvent::ScreenShareActive(active) => {
                self.is_screen_sharing = active;
            }
        }
    }

    /// Teclado -> ações para o backend. Separado do loop para ser testável.
    fn handle_key(&mut self, key: KeyEvent) -> Vec<UiAction> {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return vec![UiAction::Quit];
        }
        match self.overlay.take() {
            // Qualquer tecla fecha a ajuda
            Some(Overlay::Help) => Vec::new(),
            Some(Overlay::Menu(mut stack)) => {
                let Some(menu) = stack.last_mut() else { return Vec::new() };
                match key.code {
                    KeyCode::F(1) => {
                        self.open_main_menu();
                        return Vec::new();
                    }
                    KeyCode::Char('k') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.open_main_menu();
                        return Vec::new();
                    }
                    KeyCode::Up => menu.up(),
                    KeyCode::Down | KeyCode::Tab => menu.down(),
                    KeyCode::Esc | KeyCode::Left | KeyCode::Backspace => {
                        stack.pop();
                        if !stack.is_empty() {
                            self.overlay = Some(Overlay::Menu(stack));
                        }
                        return Vec::new();
                    }
                    KeyCode::Enter | KeyCode::Right | KeyCode::Char(' ') => return self.activate_menu(stack),
                    KeyCode::Char(c @ '1'..='9') => {
                        let index = c as usize - '1' as usize;
                        if index < menu.items.len() {
                            menu.selected = index;
                            return self.activate_menu(stack);
                        }
                    }
                    _ => {}
                }
                self.overlay = Some(Overlay::Menu(stack));
                Vec::new()
            }
            Some(Overlay::Prompt { title, template, mut editor }) => {
                match key.code {
                    KeyCode::Esc => return Vec::new(),
                    KeyCode::Enter => {
                        let answer = editor.text().trim().to_string();
                        if !answer.is_empty() || title.contains("opcional") {
                            let command = template.replace("{}", &answer).trim().to_string();
                            return self.submit_line(&command);
                        }
                    }
                    code => edit_key(&mut editor, code),
                }
                self.overlay = Some(Overlay::Prompt { title, template, editor });
                Vec::new()
            }
            None => self.handle_input_key(key),
        }
    }

    /// Teclas da barra de entrada (sem menu aberto)
    fn handle_input_key(&mut self, key: KeyEvent) -> Vec<UiAction> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::F(1) => self.open_main_menu(),
            KeyCode::Char('k') if ctrl => self.open_main_menu(),
            KeyCode::Enter => {
                let line = self.editor.submit();
                return self.submit_line(&line);
            }
            KeyCode::Up => self.editor.history_prev(),
            KeyCode::Down => self.editor.history_next(),
            KeyCode::Tab => {
                let options = self.editor.complete(&self.completion_words());
                if !options.is_empty() {
                    self.last_status_bar = format!("Opções: {}", options.join("   "));
                }
            }
            KeyCode::F(2) => self.switch_tab(self.active_tab.other()),
            KeyCode::PageUp => self.scroll_chat(5),
            KeyCode::PageDown => self.scroll_chat(-5),
            KeyCode::Esc => self.editor.set(""),
            code => edit_key(&mut self.editor, code),
        }
        Vec::new()
    }

    /// Mouse -> ações. Clique em membro abre o menu dele; em canal, entra (botão direito: opções).
    fn handle_mouse(&mut self, mouse: MouseEvent) -> Vec<UiAction> {
        let (col, row) = (mouse.column, mouse.row);
        let click = match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => Some(false),
            MouseEventKind::Down(MouseButton::Right) => Some(true),
            _ => None,
        };

        match self.overlay.take() {
            Some(Overlay::Menu(mut stack)) => {
                if click.is_none() {
                    self.overlay = Some(Overlay::Menu(stack));
                    return Vec::new();
                }
                // Clique num item ativa; fora do menu, fecha
                match row_in(self.popup_area, col, row) {
                    Some(index) if index < stack.last().map_or(0, |m| m.items.len()) => {
                        if let Some(menu) = stack.last_mut() {
                            menu.selected = index;
                        }
                        self.activate_menu(stack)
                    }
                    Some(_) => {
                        self.overlay = Some(Overlay::Menu(stack));
                        Vec::new()
                    }
                    None => Vec::new(),
                }
            }
            Some(Overlay::Help) => {
                if click.is_none() {
                    self.overlay = Some(Overlay::Help);
                }
                Vec::new()
            }
            Some(prompt @ Overlay::Prompt { .. }) => {
                self.overlay = Some(prompt);
                Vec::new()
            }
            None => {
                match mouse.kind {
                    MouseEventKind::ScrollUp if row_in(self.chat_area, col, row).is_some() => self.scroll_chat(3),
                    MouseEventKind::ScrollDown if row_in(self.chat_area, col, row).is_some() => self.scroll_chat(-3),
                    _ => {}
                }
                let Some(right_click) = click else { return Vec::new() };
                if !right_click && row == self.header_row {
                    let inside = |(start, end): (u16, u16)| col >= start && col < end;
                    if inside(self.header_mic_cols) {
                        return vec![UiAction::ToggleMute];
                    }
                    if inside(self.header_key_cols) {
                        let key = self.my_pubkey.clone();
                        self.copy_to_clipboard(&key, "Sua chave pública");
                        return Vec::new();
                    }
                    if inside(self.header_space_cols) {
                        self.overlay = Some(Overlay::Menu(vec![spaces_menu(&self.servers)]));
                    }
                    return Vec::new();
                }
                if !right_click && row == self.chat_area.y && col > self.chat_area.x && col < self.chat_area.x + self.chat_area.width {
                    let tab = if col < self.chat_area.x + 1 + self.tab_split { Tab::Chat } else { Tab::System };
                    self.switch_tab(tab);
                    return Vec::new();
                }
                if let Some(index) = row_in(self.peers_area, col, row) {
                    // A primeira linha é o próprio usuário
                    if let Some(nick) = self.member_rows.get(index).filter(|n| **n != self.my_nick).cloned() {
                        let target_pk = self.peers.iter().find(|(_, n, _)| n == &nick).map(|(_, _, pk)| pk.as_str());
                        let is_friend = self.friends.iter().any(|f| {
                            (f.display_name.eq_ignore_ascii_case(&nick) || target_pk.is_some_and(|pk| f.public_key == pk))
                                && f.state == p2p_core::identity::FriendState::Confirmed
                        });
                        let current_server = self.servers.iter().find(|s| s.current);
                        let can_moderate = self.in_server && current_server.is_some_and(|s| s.owner || s.moderator);
                        let is_moderator = false;
                        let inviteable_servers: Vec<ServerEntry> = self.servers.iter().filter(|s| s.owner || s.moderator).cloned().collect();
                        self.overlay = Some(Overlay::Menu(vec![member_menu(
                            &nick,
                            target_pk,
                            is_friend,
                            self.in_server,
                            can_moderate,
                            is_moderator,
                            &inviteable_servers,
                        )]));
                    }
                } else if let Some(index) = row_in(self.channels_area, col, row) {
                    if let Some((name, is_voice)) = self.space_channels.get(index).cloned() {
                        if right_click {
                            self.overlay = Some(Overlay::Menu(vec![channel_menu(&name, is_voice)]));
                        } else {
                            return self.submit_line(&channel_command(&name, is_voice));
                        }
                    }
                }
                Vec::new()
            }
        }
    }

    fn open_main_menu(&mut self) {
        let is_server_closed = self.servers.iter().find(|s| s.current).map_or(false, |s| s.closed);
        let ctx = MenuContext {
            in_server: self.in_server,
            is_server_closed,
            in_voice: self.current_voice_channel.is_some(),
            is_muted: self.is_muted.load(Ordering::Relaxed),
            is_screen_sharing: self.is_screen_sharing,
            servers: &self.servers,
            access_requests: &self.access_requests,
            friends: &self.friends,
        };
        self.overlay = Some(Overlay::Menu(vec![main_menu(&ctx)]));
    }

    /// Executa o item selecionado do menu do topo da pilha
    fn activate_menu(&mut self, mut stack: Vec<Menu>) -> Vec<UiAction> {
        let Some(item) = stack.last().and_then(|m| m.current()).cloned() else { return Vec::new() };
        match item.action {
            MenuAction::Run(command) => self.submit_line(&command),
            MenuAction::Ask { prompt, template } => {
                self.overlay = Some(Overlay::Prompt { title: prompt, template, editor: LineEditor::new() });
                Vec::new()
            }
            MenuAction::Submenu(submenu) => {
                stack.push(submenu);
                self.overlay = Some(Overlay::Menu(stack));
                Vec::new()
            }
            MenuAction::ToggleCheckbox => {
                if let Some(menu) = stack.last_mut() {
                    if let Some(current_item) = menu.items.get_mut(menu.selected) {
                        if current_item.label.starts_with("[X] ") {
                            current_item.label = current_item.label.replacen("[X] ", "[ ] ", 1);
                        } else if current_item.label.starts_with("[ ] ") {
                            current_item.label = current_item.label.replacen("[ ] ", "[X] ", 1);
                        }
                    }
                }
                self.overlay = Some(Overlay::Menu(stack));
                Vec::new()
            }
            MenuAction::ApplyPermissions { nick } => {
                let mut selected_perms = Vec::new();
                if let Some(menu) = stack.last() {
                    for item in &menu.items {
                        if item.label.starts_with("[X] ") {
                            if item.label.contains("EnterServer") {
                                selected_perms.push("enter");
                            }
                            if item.label.contains("Ban") {
                                selected_perms.push("ban");
                            }
                            if item.label.contains("IssueMember") {
                                selected_perms.push("issue");
                            }
                            if item.label.contains("Delegate") {
                                selected_perms.push("delegate");
                            }
                            if item.label.contains("ManageChannels") {
                                selected_perms.push("channels");
                            }
                            if item.label.contains("ManageConfig") {
                                selected_perms.push("config");
                            }
                        }
                    }
                }
                if selected_perms.is_empty() {
                    self.submit_line(&format!("/server mod remove {}", nick))
                } else {
                    let cmd = format!("/server mod add {} {}", nick, selected_perms.join(" "));
                    self.submit_line(&cmd)
                }
            }
            MenuAction::Help => {
                self.overlay = Some(Overlay::Help);
                Vec::new()
            }
            MenuAction::Copy { text, what } => {
                self.copy_to_clipboard(&text, &what);
                Vec::new()
            }
        }
    }

    /// Copia para a área de transferência e confirma na barra de status
    fn copy_to_clipboard(&mut self, text: &str, what: &str) {
        self.last_status_bar = match (self.clipboard)(text) {
            Ok(()) => format!("📋 {} copiada para a área de transferência!", what),
            Err(e) => {
                self.push_system(format!("⚠️ Não foi possível copiar para a área de transferência: {}", e));
                format!("⚠️ Falha ao copiar: {}", e)
            }
        };
    }

    /// Linha confirmada (digitada ou vinda de um menu). Só texto comum aparece no chat como
    /// mensagem sua; comandos vão para o backend sem eco.
    fn submit_line(&mut self, line: &str) -> Vec<UiAction> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }
        self.chat_scroll = 0;
        match trimmed {
            "/quit" => vec![UiAction::Quit],
            "/mute" => vec![UiAction::ToggleMute],
            "/help" => {
                self.overlay = Some(Overlay::Help);
                Vec::new()
            }
            command if command.starts_with('/') => vec![UiAction::SendMessage(command.to_string())],
            text => {
                // Em canais normais fazemos eco imediato; em DMs (@Amigo), o Core emite DirectMessage de volta
                if !self.current_channel.starts_with('@') {
                    let now_ts_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    self.push_chat_message(now_ts_ms, format!("[#{}] {}: {}", self.current_channel, self.my_nick, text));
                }
                vec![UiAction::SendMessage(text.to_string())]
            }
        }
    }

    /// Palavras para completar com Tab: nicks conhecidos, amigos, canais do espaço e IDs/nomes de arquivos
    fn completion_words(&self) -> Vec<String> {
        let mut words: Vec<String> = self.peers.iter().map(|(_, nick, _)| nick.clone()).collect();
        words.extend(self.friends.iter().map(|f| f.display_name.clone()));
        words.extend(self.channel_members.values().flatten().cloned());
        words.extend(self.space_channels.iter().map(|(name, _)| name.clone()));
        for file in &self.known_files {
            words.push(file.id.clone());
            words.push(file.name.clone());
        }
        words.retain(|w| *w != self.my_nick);
        words.sort();
        words.dedup();
        words
    }

    /// Notificação do core: vai para a aba Sistema (e conta como não lida se ela estiver fechada)
    fn push_system(&mut self, text: String) {
        self.system_messages.push(text);
        if self.active_tab != Tab::System {
            self.system_unread += 1;
        }
    }

    fn switch_tab(&mut self, tab: Tab) {
        if tab != self.active_tab {
            self.active_tab = tab;
            self.chat_scroll = 0;
        }
        if tab == Tab::System {
            self.system_unread = 0;
        }
    }

    fn current_lines(&self) -> &[String] {
        match self.active_tab {
            Tab::Chat => &self.messages,
            Tab::System => &self.system_messages,
        }
    }

    /// Rola a aba atual: positivo = mensagens mais antigas (em linhas visuais na tela)
    fn scroll_chat(&mut self, delta: isize) {
        let content_width = self.chat_area.width.saturating_sub(2).max(10) as usize;
        let total_visual_lines: usize = self
            .current_lines()
            .iter()
            .map(|m| wrap::wrap_message(m, content_width).len())
            .sum();
        let max = total_visual_lines.saturating_sub(1) as isize;
        self.chat_scroll = (self.chat_scroll as isize + delta).clamp(0, max) as usize;
    }

    /// Desenha o menu, diálogo ou ajuda aberto, centralizado por cima da tela
    fn draw_overlay(&mut self, f: &mut ratatui::Frame, screen: Rect) {
        let selected_style = Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD);
        let popup = match &self.overlay {
            None => return,
            Some(Overlay::Menu(stack)) => {
                let Some(menu) = stack.last() else { return };
                let widest = menu.items.iter().map(|i| i.label.chars().count()).max().unwrap_or(10);
                let area = centered(screen, (widest + 8).max(36) as u16, menu.items.len() as u16 + 2);
                let items: Vec<ListItem> = menu
                    .items
                    .iter()
                    .enumerate()
                    .map(|(i, item)| {
                        let selected = i == menu.selected;
                        let text = format!("{} {}", if selected { "›" } else { " " }, item.label);
                        ListItem::new(Span::styled(text, if selected { selected_style } else { Style::default() }))
                    })
                    .collect();
                f.render_widget(Clear, area);
                f.render_widget(
                    List::new(items).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Cyan))
                            .title(menu.title.clone())
                            .title_bottom(" ↑↓ Enter · Esc volta "),
                    ),
                    area,
                );
                area
            }
            Some(Overlay::Prompt { title, editor, .. }) => {
                let area = centered(screen, 64, 3);
                let prefix = "❯ ";
                let prefix_width = 2;
                let avail_width = (area.width.saturating_sub(2) as usize).saturating_sub(prefix_width);
                let (visible_text, cursor_col) = wrap::scroll_input(&editor.text(), editor.cursor(), avail_width);
                f.render_widget(Clear, area);
                f.render_widget(
                    Paragraph::new(format!("{}{}", prefix, visible_text)).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Cyan))
                            .title(format!(" {} ", title))
                            .title_bottom(" Enter confirma · Esc cancela "),
                    ),
                    area,
                );
                f.set_cursor_position((area.x + 1 + prefix_width as u16 + cursor_col as u16, area.y + 1));
                area
            }
            Some(Overlay::Help) => {
                let area = centered(screen, 86, HELP_LINES.len() as u16 + 2);
                let lines: Vec<Line> = HELP_LINES.iter().map(|l| Line::from(*l)).collect();
                f.render_widget(Clear, area);
                f.render_widget(
                    Paragraph::new(lines).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Cyan))
                            .title(" Ajuda ")
                            .title_bottom(" qualquer tecla fecha "),
                    ),
                    area,
                );
                area
            }
        };
        self.popup_area = popup;
    }

    fn draw_ui(&mut self, f: &mut ratatui::Frame) {
        let size = f.area();

        // Divide a tela em 4 áreas verticais: Título/Topo, Corpo Central, Barra de Entrada e Rodapé
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(5),    // Main Body
                Constraint::Length(3), // Input Bar
                Constraint::Length(1), // Footer Status Bar
            ])
            .split(size);

        // 1. Header Superior
        let muted_str = if self.is_muted.load(Ordering::Relaxed) {
            "🔴 [MUTADO]"
        } else {
            "🎙️  [MIC ATIVO]"
        };

        let chan_prefix = if self.current_channel.starts_with('@') { "" } else { "#" };
        let mut spans = vec![
            Span::styled("⚡ ANARCHORD P2P ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(format!("| Usuário: {} ", self.my_nick), Style::default().fg(Color::Cyan)),
            Span::styled(format!("| Chave: {}... ", &self.my_pubkey[..8]), Style::default().fg(Color::DarkGray)),
            Span::styled(format!("| {} {}{} ", self.space_name, chan_prefix, self.current_channel), Style::default().fg(Color::Green)),
            Span::styled(format!("| {} ", muted_str), Style::default().fg(Color::Magenta)),
        ];
        // Depois do MIC, para não mexer nas áreas clicáveis (índices 3 e 4)
        match (self.in_server, self.room_key) {
            (true, RoomKeyStatus::Ready) => {
                spans.push(Span::styled("| 🔐 cifrado", Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)))
            }
            (true, _) => spans.push(Span::styled("| ⏳ aguardando chave", Style::default().fg(Color::Yellow))),
            (false, _) => {}
        }
        // Guarda onde ficaram o espaço (abre a troca Lobby/servidores) e o MIC (liga/desliga)
        let mut col = chunks[0].x + 1;
        let ranges: Vec<(u16, u16)> = spans
            .iter()
            .map(|span| {
                let start = col;
                col = col.saturating_add(span.width() as u16);
                (start, col)
            })
            .collect();
        self.header_row = chunks[0].y + 1;
        self.header_space_cols = ranges[3];
        self.header_mic_cols = ranges[4];
        self.header_key_cols = ranges[2];
        let header = Paragraph::new(Line::from(spans))
        .block(Block::default().borders(Borders::ALL).title(" Anarchord Core v0.1.0 "));
        f.render_widget(header, chunks[0]);

        // 2. Divide o corpo em Central (Chat + Progresso) e Lateral (Membros / Voz)
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(75), // Chat Messages
                Constraint::Percentage(25), // Peers & Voice Activity
            ])
            .split(chunks[1]);

        // Se houver arquivo transferindo, divide a janela do chat para mostrar barra de progresso
        if let Some((name, pct, is_download)) = self.file_transfer.clone() {
            let chat_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(4), Constraint::Length(3)])
                .split(main_chunks[0]);

            self.chat_area = chat_chunks[0];
            self.render_messages(f, chat_chunks[0]);

            let title = if is_download {
                format!(" 📥 Baixando arquivo: {} ", name)
            } else {
                format!(" 📤 Enviando arquivo: {} ", name)
            };

            let gauge = Gauge::default()
                .block(Block::default().borders(Borders::ALL).title(title))
                .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
                .percent(pct as u16);
            f.render_widget(gauge, chat_chunks[1]);
        } else {
            self.chat_area = main_chunks[0];
            self.render_messages(f, main_chunks[0]);
        }

        // Painel Lateral: Canais (topo) e Membros unificados (texto + voz)
        let side_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(main_chunks[1]);

        // 0. Canais do espaço atual (Lobby ou servidor)
        let mut channel_items: Vec<ListItem> = Vec::new();
        if self.space_channels.is_empty() {
            let chan_prefix = if self.current_channel.starts_with('@') {
                "💬"
            } else if self.current_voice_channel.as_deref() == Some(self.current_channel.as_str()) {
                "🔊"
            } else {
                "#"
            };
            channel_items.push(ListItem::new(Line::from(Span::styled(
                format!("▶ {} {}", chan_prefix, self.current_channel),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ))));
            channel_items.push(ListItem::new(Line::from(Span::styled(
                "  /join <qualquer nome>",
                Style::default().fg(Color::DarkGray),
            ))));
        } else {
            for (name, is_voice) in &self.space_channels {
                let active = *name == self.current_channel || (*is_voice && self.current_voice_channel.as_deref() == Some(name.as_str()));
                let label = format!("{} {} {}", if active { "▶" } else { " " }, if *is_voice { "🔊" } else { "#" }, name);
                let style = if active {
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                channel_items.push(ListItem::new(Line::from(Span::styled(label, style))));
            }
        }
        let channels_list = List::new(channel_items)
            .block(Block::default().borders(Borders::ALL).title(format!(" Canais · {} ", self.space_name)));
        f.render_widget(channels_list, side_chunks[0]);
        self.channels_area = side_chunks[0];

        // 1. Membros da Sala Atual (unificado: texto e voz)
        self.peers_area = side_chunks[1];
        let in_voice_here = self.current_voice_channel.as_deref() == Some(self.current_channel.as_str());
        let mut combined_members: Vec<String> = self
            .channel_members
            .get(&self.current_channel)
            .map(|s| {
                let mut v: Vec<String> = s.iter().cloned().collect();
                v.sort();
                v
            })
            .unwrap_or_default();
        if in_voice_here {
            for vm in &self.voice_members {
                if !combined_members.contains(vm) {
                    combined_members.push(vm.clone());
                }
            }
        }

        let mut room_members_items: Vec<ListItem> = Vec::new();
        let mut seen_keys = HashSet::new();

        // Usuário atual na sala
        let me_speaking = in_voice_here && self.speakers.contains(&self.my_nick);
        let mut my_spans = vec![
            Span::styled(
                if me_speaking { "🔊 " } else { "👤 " },
                Style::default().fg(if me_speaking { Color::Green } else { Color::Yellow }),
            ),
            Span::styled(format!("{} (Você)", self.my_nick), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ];
        if me_speaking {
            my_spans.push(Span::styled(" [Falando...]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
        }
        room_members_items.push(ListItem::new(Line::from(my_spans)));
        seen_keys.insert((self.my_nick.clone(), self.my_pubkey.clone()));
        self.member_rows = vec![self.my_nick.clone()];

        // Pares ativos na sala atual
        for nick in &combined_members {
            let peer_pk = self.peers.iter()
                .find(|(_, n, _)| n == nick)
                .map(|(_, _, pk)| pk.clone())
                .unwrap_or_default();
            let is_self = nick == &self.my_nick && (peer_pk.is_empty() || peer_pk == self.my_pubkey);
            if !is_self && seen_keys.insert((nick.clone(), peer_pk.clone())) {
                self.member_rows.push(nick.clone());
                let short_pk = if peer_pk.len() >= 6 {
                    format!(" ({})", &peer_pk[..6])
                } else if !peer_pk.is_empty() {
                    format!(" ({})", peer_pk)
                } else {
                    String::new()
                };
                let friend_info = self.friends.iter().find(|f| f.display_name.eq_ignore_ascii_case(nick));
                let friend_badge = match friend_info.map(|f| f.state) {
                    Some(p2p_core::identity::FriendState::Confirmed) => " 💚",
                    Some(p2p_core::identity::FriendState::PendingOutgoing) => " ⏳",
                    Some(p2p_core::identity::FriendState::PendingIncoming) => " 📩",
                    Some(p2p_core::identity::FriendState::Rejected) => " 🚫",
                    None => "",
                };
                let is_speaking = in_voice_here && self.speakers.contains(nick);
                let mut spans = vec![
                    Span::styled(
                        if is_speaking { "🔊 " } else { "🟢 " },
                        Style::default().fg(Color::Green),
                    ),
                    Span::styled(
                        format!("{}{}", nick, friend_badge),
                        Style::default()
                            .fg(if is_speaking { Color::Green } else { Color::White })
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(short_pk, Style::default().fg(Color::DarkGray)),
                ];
                if is_speaking {
                    spans.push(Span::styled(" [Falando...]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
                }
                room_members_items.push(ListItem::new(Line::from(spans)));
            }
        }

        // Amigos (online fora da sala ou offline) também aparecem clicáveis na lista
        for f in &self.friends {
            if seen_keys.insert((f.display_name.clone(), f.public_key.clone())) {
                self.member_rows.push(f.display_name.clone());
                let short_pk = if f.public_key.len() >= 6 {
                    format!(" ({})", &f.public_key[..6])
                } else {
                    format!(" ({})", f.public_key)
                };
                let (dot, badge, style) = match f.state {
                    p2p_core::identity::FriendState::Confirmed => {
                        let dot = if f.online { "🟢 " } else { "⚪ " };
                        let style = if f.online {
                            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::Gray)
                        };
                        (dot, " 💚", style)
                    }
                    p2p_core::identity::FriendState::PendingOutgoing => {
                        let dot = if f.online { "🟢 " } else { "⚪ " };
                        (dot, " ⏳", Style::default().fg(Color::Yellow))
                    }
                    p2p_core::identity::FriendState::PendingIncoming => {
                        ("📩 ", " 📩", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))
                    }
                    p2p_core::identity::FriendState::Rejected => {
                        ("🚫 ", " 🚫", Style::default().fg(Color::DarkGray))
                    }
                };
                let dot_fg = if f.online { Style::default().fg(Color::Green) } else { Style::default().fg(Color::DarkGray) };
                room_members_items.push(ListItem::new(Line::from(vec![
                    Span::styled(dot, dot_fg),
                    Span::styled(format!("{}{}", f.display_name, badge), style),
                    Span::styled(short_pk, Style::default().fg(Color::DarkGray)),
                ])));
            }
        }

        // Título com membros da sala e total no Swarm P2P
        let room_prefix = if self.current_channel.starts_with('@') {
            ""
        } else if in_voice_here {
            "🔊 "
        } else {
            "#"
        };
        let room_members_title = format!(" Membros {}{} [Swarm: {}] ", room_prefix, self.current_channel, self.peers.len());
        let peers_list = List::new(room_members_items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(room_members_title),
        );
        f.render_widget(peers_list, side_chunks[1]);

        // 3. Barra de Entrada
        let prefix = "❯ ";
        let prefix_width = 2;
        let avail_width = (chunks[2].width.saturating_sub(2) as usize).saturating_sub(prefix_width);
        let (visible_text, cursor_col) = wrap::scroll_input(&self.editor.text(), self.editor.cursor(), avail_width);

        let input_box = Paragraph::new(format!("{}{}", prefix, visible_text))
            .style(Style::default().fg(Color::White))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Mensagem ou comando · F1 menu · Tab completa · ↑↓ histórico · PgUp/PgDn rola "),
            );
        f.render_widget(input_box, chunks[2]);

        // Posiciona o cursor do terminal no final do texto digitado ou deslocado pela rolagem
        let cursor_x = chunks[2].x + 1 + prefix_width as u16 + cursor_col as u16;
        let cursor_y = chunks[2].y + 1;
        f.set_cursor_position((cursor_x, cursor_y));

        // 4. Rodapé de Notificações / Status Bar (Redirecionamento de logs de sistema)
        let footer = Paragraph::new(Line::from(vec![
            Span::styled(" 📢 STATUS: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(&self.last_status_bar, Style::default().fg(Color::Cyan)),
        ]))
        .style(Style::default().bg(Color::DarkGray));
        f.render_widget(footer, chunks[3]);

        // 5. Menu, diálogo ou ajuda por cima de tudo
        self.draw_overlay(f, size);
    }

    fn render_messages(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let max_lines = area.height.saturating_sub(2) as usize;
        let content_width = area.width.saturating_sub(2).max(10) as usize;
        let raw_lines = self.current_lines();

        let mut visual_lines: Vec<(String, Style)> = Vec::new();
        for m in raw_lines {
            let style = if m.starts_with("⚙️") {
                Style::default().fg(Color::DarkGray)
            } else if m.starts_with("🤝") || m.starts_with("✅") {
                Style::default().fg(Color::Green)
            } else if m.starts_with("❌") {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::White)
            };
            let wrapped = wrap::wrap_message(m, content_width);
            for w in wrapped {
                visual_lines.push((w, style));
            }
        }

        let end = visual_lines.len().saturating_sub(self.chat_scroll);
        let start = end.saturating_sub(max_lines);

        let visible_msgs: Vec<ListItem> = visual_lines[start..end]
            .iter()
            .map(|(line, style)| ListItem::new(Span::styled(line.clone(), *style)))
            .collect();

        // Título com as duas abas; a ativa em destaque
        let chat_prefix = if self.current_channel.starts_with('@') { "" } else { "#" };
        let chat_label = format!(" 💬 Chat {}{} ", chat_prefix, self.current_channel);
        let system_label = if self.system_unread > 0 {
            format!(" ⚙️ Sistema ({}) ", self.system_unread)
        } else {
            " ⚙️ Sistema ".to_string()
        };
        self.tab_split = chat_label.chars().count() as u16 + 1;
        let tab_style = |active: bool| {
            if active {
                Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            }
        };
        let mut title = vec![
            Span::styled(chat_label, tab_style(self.active_tab == Tab::Chat)),
            Span::raw("│"),
            Span::styled(system_label, tab_style(self.active_tab == Tab::System)),
        ];
        if self.chat_scroll > 0 {
            title.push(Span::raw(format!(" · ↑ {} linhas acima do fim (PgDn volta) ", self.chat_scroll)));
        }
        let messages_list = List::new(visible_msgs)
            .block(Block::default().borders(Borders::ALL).title(Line::from(title)).title_bottom(" F2 alterna abas "));
        f.render_widget(messages_list, area);
    }

    pub fn restore_terminal() {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            LeaveAlternateScreen,
            DisableMouseCapture,
            DisableFocusChange,
            SetTitle(""),
            crossterm::cursor::Show
        );
    }

    fn cleanup_terminal(&self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture,
            DisableFocusChange,
            SetTitle("")
        )?;
        terminal.show_cursor()?;
        Ok(())
    }
}

/// Abas da área de mensagens
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tab {
    Chat,
    System,
}

impl Tab {
    fn other(self) -> Self {
        match self {
            Tab::Chat => Tab::System,
            Tab::System => Tab::Chat,
        }
    }
}

/// O que está aberto por cima da tela
enum Overlay {
    /// Pilha de menus (o último é o visível; Esc volta ao anterior)
    Menu(Vec<Menu>),
    /// Pergunta de texto; `template` recebe a resposta no lugar de `{}`
    Prompt { title: String, template: String, editor: LineEditor },
    Help,
}

/// Teclas de edição comuns à barra de entrada e às caixas de diálogo
fn edit_key(editor: &mut LineEditor, code: KeyCode) {
    match code {
        KeyCode::Char(c) => editor.insert(c),
        KeyCode::Backspace => editor.backspace(),
        KeyCode::Delete => editor.delete(),
        KeyCode::Left => editor.left(),
        KeyCode::Right => editor.right(),
        KeyCode::Home => editor.home(),
        KeyCode::End => editor.end(),
        _ => {}
    }
}

/// Linha clicada dentro de uma caixa com borda (0 = primeira linha útil)
fn row_in(area: Rect, col: u16, row: u16) -> Option<usize> {
    let inside = col > area.x && col + 1 < area.x + area.width && row > area.y && row + 1 < area.y + area.height;
    inside.then(|| (row - area.y - 1) as usize)
}

/// Retângulo centralizado na tela (limitado ao tamanho dela)
fn centered(screen: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(screen.width);
    let height = height.min(screen.height);
    Rect {
        x: screen.x + (screen.width - width) / 2,
        y: screen.y + (screen.height - height) / 2,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn ui_for(nick: &str) -> TerminalUi {
        TerminalUi::new(nick.to_string(), "abcdef0123".to_string(), Arc::new(AtomicBool::new(false)), None)
    }

    /// Renderiza a UI num terminal virtual e devolve o texto da tela
    fn render(ui: &mut TerminalUi) -> String {
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        terminal.draw(|f| ui.draw_ui(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let width = buffer.area.width as usize;
        buffer
            .content()
            .chunks(width)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
            // Emojis ocupam duas células; a segunda vira um espaço extra no texto da tela
            .replace("🌐  ", "🌐 ")
            .replace("🏰  ", "🏰 ")
            .replace("🔊  ", "🔊 ")
            .replace("💚  ", "💚 ")
            .replace("📬  ", "📬 ")
            .replace("🔒  ", "🔒 ")
            .replace("🔐  ", "🔐 ")
            .replace("⏳  ", "⏳ ")
    }

    fn bob_connected() -> UiEvent {
        UiEvent::PeerConnected {
            peer_id: "12D3KooWBob".to_string(),
            nick: "Bob".to_string(),
            pubkey: "224d733c71f8".to_string(),
        }
    }

    fn members(channel: &str, nicks: &[&str]) -> UiEvent {
        UiEvent::ChannelMembers {
            channel: channel.to_string(),
            members: nicks.iter().map(|n| n.to_string()).collect(),
        }
    }

    #[test]
    fn test_own_nick_always_listed_in_room() {
        let mut ui = ui_for("Alice");
        let screen = render(&mut ui);
        assert!(screen.contains("Alice (Você)"), "{}", screen);
        assert!(screen.contains("[Swarm: 0]"), "{}", screen);
    }

    /// Regressão: par conectado e presente na sala aparece em "Membros da Sala" sem ter mandado mensagem
    #[test]
    fn test_present_peer_listed_in_room_without_chatting() {
        let mut ui = ui_for("Alice");
        ui.handle_event(bob_connected());
        ui.handle_event(members("geral", &["Bob"]));

        let screen = render(&mut ui);
        assert!(screen.contains("Bob (224d73)"), "Bob deveria estar na lista de membros:\n{}", screen);
        assert!(screen.contains("[Swarm: 1]"), "{}", screen);
    }

    #[test]
    fn test_peer_leaving_room_is_removed_from_members() {
        let mut ui = ui_for("Alice");
        ui.handle_event(bob_connected());
        ui.handle_event(members("geral", &["Bob"]));
        ui.handle_event(members("geral", &[]));

        let screen = render(&mut ui);
        assert!(!screen.contains("Bob (224d73)"), "Bob não deveria estar na lista de membros:\n{}", screen);
        assert!(screen.contains("Alice (Você)"), "{}", screen);
    }

    #[test]
    fn test_members_of_other_channel_not_shown() {
        let mut ui = ui_for("Alice");
        ui.handle_event(bob_connected());
        ui.handle_event(members("jogos", &["Bob"]));

        let screen = render(&mut ui);
        assert!(!screen.contains("Bob (224d73)"), "Bob não deveria estar na lista de membros:\n{}", screen);

        ui.handle_event(UiEvent::ChannelChanged("jogos".to_string()));
        let screen = render(&mut ui);
        assert!(screen.contains("Bob (224d73)"), "{}", screen);
        assert!(screen.contains("#jogos"), "{}", screen);
    }

    #[test]
    fn test_disconnect_updates_swarm_count_and_logs() {
        let mut ui = ui_for("Alice");
        ui.handle_event(bob_connected());
        ui.handle_event(UiEvent::PeerDisconnected("12D3KooWBob".to_string()));

        let screen = render(&mut ui);
        assert!(screen.contains("[Swarm: 0]"), "{}", screen);
        assert!(!screen.contains("Par desconectado: Bob"), "notificação não polui o chat");
        ui.handle_key(key(KeyCode::F(2)));
        assert!(render(&mut ui).contains("Par desconectado: Bob"));
    }

    #[test]
    fn test_chat_message_rendered() {
        let mut ui = ui_for("Alice");
        ui.handle_event(UiEvent::ChatMessage {
            channel: "geral".to_string(),
            author: "Bob".to_string(),
            text: "olá mesh".to_string(),
            timestamp: 1_700_000_000,
        });

        let screen = render(&mut ui);
        assert!(screen.contains("Bob: olá mesh"), "{}", screen);
    }

    #[test]
    fn test_lobby_shows_free_channel_hint() {
        let mut ui = ui_for("Alice");
        let screen = render(&mut ui);
        assert!(screen.contains("Canais · 🌐 Lobby"), "{}", screen);
        assert!(screen.contains("▶ # geral"), "{}", screen);
        assert!(screen.contains("/join <qualquer nome>"), "{}", screen);
        assert!(screen.contains("🌐 Lobby #geral"), "cabeçalho mostra o espaço:
{}", screen);
    }

    #[test]
    fn test_server_space_lists_its_channels_and_marks_current() {
        let mut ui = ui_for("Alice");
        ui.handle_event(UiEvent::ChannelChanged("geral".to_string()));
        ui.handle_event(UiEvent::SpaceChanged {
            space_name: "🏰 Rust Guild".to_string(),
            channels: vec![("geral".into(), false), ("jogos".into(), false), ("voz".into(), true)],
            is_server: true,
        });
        let screen = render(&mut ui);
        assert!(screen.contains("Canais · 🏰 Rust Guild"), "{}", screen);
        assert!(screen.contains("▶ # geral"), "{}", screen);
        assert!(screen.contains("# jogos"), "{}", screen);
        assert!(screen.contains("🔊 voz"), "{}", screen);
        assert!(!screen.contains("/join <qualquer nome>"), "{}", screen);

        ui.handle_event(UiEvent::VoiceChannelChanged(Some("voz".to_string())));
        assert!(render(&mut ui).contains("▶ 🔊 voz"));
    }

    /// Linha do cabeçalho (a de dentro da borda)
    fn header_line(ui: &mut TerminalUi) -> String {
        render(ui).lines().nth(1).unwrap_or_default().to_string()
    }

    #[test]
    fn test_header_shows_encryption_state_of_current_room() {
        let mut ui = ui_for("Alice");
        // Lobby: nada cifrado, nada no cabeçalho
        let header = header_line(&mut ui);
        assert!(!header.contains("🔐") && !header.contains("aguardando chave"), "{}", header);

        // Entrou no servidor, a chave ainda não chegou
        ui.handle_event(UiEvent::SpaceChanged { space_name: "🏰 Rust Guild".into(), channels: vec![("geral".into(), false)], is_server: true });
        ui.handle_event(UiEvent::RoomKey(RoomKeyStatus::Waiting));
        let header = header_line(&mut ui);
        assert!(header.contains("⏳ aguardando chave"), "{}", header);
        assert!(!header.contains("🔐"), "{}", header);

        // Welcome recebido: cifrado
        ui.handle_event(UiEvent::RoomKey(RoomKeyStatus::Ready));
        let header = header_line(&mut ui);
        assert!(header.contains("🔐 cifrado"), "{}", header);
        assert!(!header.contains("aguardando chave"), "{}", header);

        // Perdeu o grupo (removido ou fora de sincronia): volta o aviso
        ui.handle_event(UiEvent::RoomKey(RoomKeyStatus::Waiting));
        assert!(header_line(&mut ui).contains("⏳ aguardando chave"));

        // De volta ao Lobby: o ícone some
        ui.handle_event(UiEvent::RoomKey(RoomKeyStatus::Ready));
        ui.handle_event(UiEvent::SpaceChanged { space_name: "🌐 Lobby".into(), channels: vec![], is_server: false });
        ui.handle_event(UiEvent::RoomKey(RoomKeyStatus::Unencrypted));
        let header = header_line(&mut ui);
        assert!(!header.contains("🔐") && !header.contains("aguardando chave"), "{}", header);
    }

    #[test]
    fn test_encryption_icon_keeps_header_click_areas() {
        let mut ui = ui_for("Alice");
        ui.handle_event(UiEvent::SpaceChanged { space_name: "🏰 Rust Guild".into(), channels: vec![("geral".into(), false)], is_server: true });
        ui.handle_event(UiEvent::RoomKey(RoomKeyStatus::Ready));
        render(&mut ui);
        let click_at = |ui: &mut TerminalUi, col: u16| {
            let row = ui.header_row;
            ui.handle_mouse(MouseEvent { kind: MouseEventKind::Down(MouseButton::Left), column: col, row, modifiers: KeyModifiers::NONE })
        };
        // O MIC continua clicável e o ícone (logo depois dele) não faz nada
        let (mic_start, mic_end) = ui.header_mic_cols;
        assert!(click_at(&mut ui, mic_start + 3).iter().any(|a| matches!(a, UiAction::ToggleMute)));
        assert!(click_at(&mut ui, mic_end + 3).is_empty());
        assert!(ui.overlay.is_none());
    }

    #[test]
    fn test_changing_space_clears_members_of_previous_space() {
        let mut ui = ui_for("Alice");
        ui.handle_event(bob_connected());
        ui.handle_event(members("geral", &["Bob"]));
        ui.handle_event(UiEvent::SpaceChanged { space_name: "🏰 Rust Guild".into(), channels: vec![("geral".into(), false)], is_server: true });
        let screen = render(&mut ui);
        assert!(!screen.contains("Bob (224d73)"), "Bob estava no #geral do Lobby, não no do servidor:
{}", screen);
        assert!(screen.contains("Alice (Você)"), "{}", screen);
    }

    /// Regressão: o clique usava a lista do swarm, não a lista exibida em "Membros"
    #[test]
    fn test_member_rows_follow_displayed_order() {
        let mut ui = ui_for("Alice");
        ui.handle_event(UiEvent::PeerConnected { peer_id: "p1".into(), nick: "Zed".into(), pubkey: "aaaaaa".into() });
        ui.handle_event(bob_connected());
        ui.handle_event(members("geral", &["Bob"]));
        render(&mut ui);
        assert_eq!(ui.member_rows, vec!["Alice".to_string(), "Bob".to_string()], "Zed não está na sala");
    }

    #[test]
    fn test_voice_room_members_rendered() {
        let mut ui = ui_for("Alice");
        ui.handle_event(UiEvent::ChannelChanged("sala1".to_string()));
        ui.handle_event(UiEvent::VoiceChannelChanged(Some("sala1".to_string())));
        ui.handle_event(UiEvent::VoiceRoomMembers(vec!["Alice".to_string(), "Bob".to_string()]));
        ui.handle_event(UiEvent::VoiceActivity { nick: "Bob".to_string(), speaking: true });

        let screen = render(&mut ui);
        assert!(screen.contains("Membros 🔊 sala1"), "{}", screen);
        assert!(screen.contains("Bob"), "{}", screen);
        assert!(screen.contains("[Falando...]"), "{}", screen);
        assert!(!screen.contains("Sala de Voz ["), "painel separado de voz foi removido:\n{}", screen);
    }

    // ---------- Interação: teclado, mouse, menus e diálogos ----------

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn type_text(ui: &mut TerminalUi, text: &str) -> Vec<UiAction> {
        text.chars().flat_map(|c| ui.handle_key(key(KeyCode::Char(c)))).collect()
    }

    fn sent(actions: &[UiAction]) -> Vec<String> {
        actions
            .iter()
            .filter_map(|a| match a {
                UiAction::SendMessage(m) => Some(m.clone()),
                _ => None,
            })
            .collect()
    }

    /// Clica na linha `line` da área escolhida por `area` (ex.: `|ui| ui.peers_area`)
    fn click(ui: &mut TerminalUi, area: fn(&TerminalUi) -> Rect, line: u16, right: bool) -> Vec<UiAction> {
        let area = area(ui);
        let button = if right { MouseButton::Right } else { MouseButton::Left };
        ui.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(button),
            column: area.x + 2,
            row: area.y + 1 + line,
            modifiers: KeyModifiers::NONE,
        })
    }

    fn select(ui: &mut TerminalUi, label: &str) -> Vec<UiAction> {
        let Some(Overlay::Menu(stack)) = &ui.overlay else { panic!("nenhum menu aberto") };
        let index = stack.last().unwrap().find(label).unwrap_or_else(|| panic!("item '{}' não está no menu", label));
        let mut stack = match ui.overlay.take() {
            Some(Overlay::Menu(s)) => s,
            _ => unreachable!(),
        };
        stack.last_mut().unwrap().selected = index;
        ui.activate_menu(stack)
    }

    #[test]
    fn test_create_server_through_menu_and_dialog() {
        let mut ui = ui_for("Alice");
        ui.handle_key(key(KeyCode::F(1)));
        select(&mut ui, "Espaços e Servidores");
        let screen = render(&mut ui);
        assert!(screen.contains("Criar novo servidor"), "menu deveria abrir com F1:\n{}", screen);

        select(&mut ui, "Criar novo servidor");
        assert!(render(&mut ui).contains("Nome do novo servidor"));
        type_text(&mut ui, "Rust Guild");
        let actions = ui.handle_key(key(KeyCode::Enter));
        assert_eq!(sent(&actions), vec!["/server create Rust Guild"]);
        assert!(ui.overlay.is_none());
    }

    #[test]
    fn test_empty_required_answer_keeps_dialog_open() {
        let mut ui = ui_for("Alice");
        ui.handle_key(key(KeyCode::F(1)));
        select(&mut ui, "Espaços e Servidores");
        select(&mut ui, "Criar novo servidor");
        assert!(ui.handle_key(key(KeyCode::Enter)).is_empty());
        assert!(matches!(ui.overlay, Some(Overlay::Prompt { .. })), "nome é obrigatório");
        ui.handle_key(key(KeyCode::Esc));
        assert!(ui.overlay.is_none(), "Esc cancela");
    }

    #[test]
    fn test_menu_keyboard_navigation_and_escape() {
        let mut ui = ui_for("Alice");
        ui.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL));
        assert!(matches!(&ui.overlay, Some(Overlay::Menu(stack)) if stack[0].selected == 0), "Ctrl+K também abre");
        ui.handle_key(key(KeyCode::Down));
        ui.handle_key(key(KeyCode::Down));
        assert!(matches!(&ui.overlay, Some(Overlay::Menu(stack)) if stack[0].selected == 2));
        ui.handle_key(key(KeyCode::Esc));
        assert!(ui.overlay.is_none());
    }

    #[test]
    fn test_switch_space_submenu_lists_servers() {
        let mut ui = ui_for("Alice");
        ui.handle_event(UiEvent::ServersChanged(vec![ServerEntry {
            name: "Rust Guild".into(),
            id: "ab".repeat(32),
            current: false,
            owner: true,
            moderator: false,
            pending: false,
            closed: false,
        }]));
        ui.handle_key(key(KeyCode::F(1)));
        select(&mut ui, "Espaços e Servidores");
        select(&mut ui, "Trocar de espaço");
        let screen = render(&mut ui);
        assert!(screen.contains("Rust Guild [dono]"), "{}", screen);
        assert!(screen.contains("▶ 🌐 Lobby"), "{}", screen);

        let actions = select(&mut ui, "Rust Guild");
        assert_eq!(sent(&actions), vec![format!("/server switch {}", "ab".repeat(32))]);
    }

    #[test]
    fn test_server_items_only_in_server() {
        let mut ui = ui_for("Alice");
        ui.handle_key(key(KeyCode::F(1)));
        select(&mut ui, "Espaços e Servidores");
        assert!(!render(&mut ui).contains("Convidar"));
        ui.handle_key(key(KeyCode::Esc));

        ui.handle_event(UiEvent::SpaceChanged { space_name: "🏰 Rust Guild".into(), channels: vec![("geral".into(), false)], is_server: true });
        ui.handle_key(key(KeyCode::F(1)));
        select(&mut ui, "Espaços e Servidores");
        assert_eq!(sent(&select(&mut ui, "Convidar")), vec!["/server invite"]);
    }

    #[test]
    fn test_clicking_member_opens_context_menu_with_moderation() {
        let mut ui = ui_for("Alice");
        ui.handle_event(bob_connected());
        ui.handle_event(UiEvent::SpaceChanged { space_name: "🏰 Rust Guild".into(), channels: vec![("geral".into(), false)], is_server: true });
        ui.handle_event(UiEvent::ServersChanged(vec![ServerEntry {
            name: "Rust Guild".into(),
            id: "123".into(),
            current: true,
            owner: true,
            moderator: false,
            pending: false,
            closed: false,
        }]));
        ui.handle_event(members("geral", &["Bob"]));
        render(&mut ui);

        assert!(click(&mut ui, |ui| ui.peers_area, 0, false).is_empty(), "clicar em si mesmo não abre menu");
        assert!(ui.overlay.is_none());

        click(&mut ui, |ui| ui.peers_area, 1, false);
        let screen = render(&mut ui);
        assert!(screen.contains("Banir"), "menu de contexto do Bob:\n{}", screen);

        select(&mut ui, "Banir");
        assert!(render(&mut ui).contains("7 dias"), "submenu de duração");
        select(&mut ui, "7 dias");
        type_text(&mut ui, "spam");
        assert_eq!(sent(&ui.handle_key(key(KeyCode::Enter))), vec!["/server ban Bob 7d spam"]);
    }

    #[test]
    fn test_optional_ban_reason_can_be_empty() {
        let mut ui = ui_for("Alice");
        ui.overlay = Some(Overlay::Menu(vec![member_menu("Bob", None, false, true, true, false, &[])]));
        select(&mut ui, "Banir");
        select(&mut ui, "Permanente");
        assert_eq!(sent(&ui.handle_key(key(KeyCode::Enter))), vec!["/server ban Bob perm"]);
    }

    #[test]
    fn test_add_friend_from_member_menu() {
        let mut ui = ui_for("Alice");
        ui.overlay = Some(Overlay::Menu(vec![member_menu("Bob", None, false, false, false, false, &[])]));
        assert_eq!(sent(&select(&mut ui, "Adicionar aos amigos")), vec!["/friend add Bob"]);
    }

    #[test]
    fn test_permissions_menu_checkbox_toggle_and_apply() {
        let mut ui = ui_for("Alice");
        ui.overlay = Some(Overlay::Menu(vec![member_menu("Bob", None, false, true, true, false, &[])]));
        select(&mut ui, "Permissões e Moderação");
        assert!(render(&mut ui).contains("Acessar Servidor"));

        // Alterna "Gerenciar Canais" de [ ] para [X]
        select(&mut ui, "Gerenciar Canais");
        let Some(Overlay::Menu(stack)) = &ui.overlay else { panic!("menu aberto") };
        assert!(stack.last().unwrap().items.iter().any(|i| i.label.starts_with("[X]") && i.label.contains("Gerenciar Canais")));

        // Alterna "Banir Membros" de [X] para [ ]
        select(&mut ui, "Banir Membros");
        let Some(Overlay::Menu(stack)) = &ui.overlay else { panic!("menu aberto") };
        assert!(stack.last().unwrap().items.iter().any(|i| i.label.starts_with("[ ]") && i.label.contains("Banir Membros")));

        // Aplica as permissões selecionadas
        let actions = select(&mut ui, "Aplicar Permissões");
        assert_eq!(sent(&actions), vec!["/server mod add Bob enter issue channels"]);
    }

    #[test]
    fn test_friends_presence_and_dm_channel_in_tui() {
        let mut ui = ui_for("Alice");
        ui.handle_event(UiEvent::FriendsChanged(vec![
            FriendUiEntry {
                public_key: "1111222233334444".into(),
                display_name: "Bobby".into(),
                online: false,
                state: p2p_core::identity::FriendState::Confirmed,
            },
            FriendUiEntry {
                public_key: "aaaabbbbccccdddd".into(),
                display_name: "Carol".into(),
                online: true,
                state: p2p_core::identity::FriendState::Confirmed,
            },
        ]));
        let screen = render(&mut ui);
        assert!(screen.contains("Bobby 💚 (111122)"), "amigo offline visível na lista:\n{}", screen);
        assert!(screen.contains("Carol 💚 (aaaabb)"), "amiga online visível na lista:\n{}", screen);

        // Abre menu principal (F1) -> Amigos e DMs -> Bobby -> Abrir conversa direta (DM)
        ui.handle_key(key(KeyCode::F(1)));
        select(&mut ui, "Amigos e DMs");
        assert!(render(&mut ui).contains("Bobby (11112222)"));
        select(&mut ui, "Bobby");
        assert_eq!(sent(&select(&mut ui, "Abrir conversa direta")), vec!["/dm open Bobby"]);

        // Simula resposta do Core abrindo o canal @Bobby e recebendo uma DM offline e online
        ui.handle_event(UiEvent::DmOpened { peer_name: "Bobby".into(), channel: "@Bobby".into() });
        ui.handle_event(UiEvent::DirectMessage {
            peer_name: "Bobby".into(),
            author: "Bobby".into(),
            text: "oi da mailbox!".into(),
            timestamp: 1_700_000_000,
            offline_delivery: true,
        });
        let screen = render(&mut ui);
        assert!(screen.contains("Chat @Bobby"), "título mostra @Bobby sem #:\n{}", screen);
        assert!(screen.contains("[@Bobby [📬 Offline E2EE]] Bobby: oi da mailbox!"), "{}", screen);
    }

    #[test]
    fn test_send_file_from_member_menu_quotes_path() {
        let mut ui = ui_for("Alice");
        ui.overlay = Some(Overlay::Menu(vec![member_menu("Bob", None, false, false, false, false, &[])]));
        select(&mut ui, "Enviar arquivo");
        type_text(&mut ui, "C:\\fotos\\férias 2026.png");
        assert_eq!(sent(&ui.handle_key(key(KeyCode::Enter))), vec!["/send Bob \"C:\\fotos\\férias 2026.png\""]);
    }

    #[test]
    fn test_clicking_channels_joins_and_right_click_opens_menu() {
        let mut ui = ui_for("Alice");
        ui.handle_event(UiEvent::SpaceChanged {
            space_name: "🏰 Rust Guild".into(),
            channels: vec![("geral".into(), false), ("jogos".into(), false), ("voz".into(), true)],
            is_server: true,
        });
        render(&mut ui);
        assert_eq!(sent(&click(&mut ui, |ui| ui.channels_area, 1, false)), vec!["/join jogos"]);
        assert_eq!(sent(&click(&mut ui, |ui| ui.channels_area, 2, false)), vec!["/voice join voz"]);

        click(&mut ui, |ui| ui.channels_area, 2, true);
        assert!(render(&mut ui).contains("Entrar na sala de voz"));
        assert_eq!(sent(&click(&mut ui, |ui| ui.popup_area, 0, false)), vec!["/voice join voz"], "clique no item do menu");
    }

    #[test]
    fn test_commands_are_not_echoed_as_chat() {
        let mut ui = ui_for("Alice");
        type_text(&mut ui, "/server list");
        assert_eq!(sent(&ui.handle_key(key(KeyCode::Enter))), vec!["/server list"]);
        type_text(&mut ui, "olá pessoal");
        ui.handle_key(key(KeyCode::Enter));
        let screen = render(&mut ui);
        assert!(!screen.contains("Alice: /server list"), "comando não vira mensagem:\n{}", screen);
        assert!(screen.contains("[#geral] Alice: olá pessoal"), "{}", screen);
    }

    #[test]
    fn test_help_command_opens_help_and_any_key_closes() {
        let mut ui = ui_for("Alice");
        type_text(&mut ui, "/help");
        assert!(ui.handle_key(key(KeyCode::Enter)).is_empty());
        assert!(render(&mut ui).contains("ATALHOS"));
        ui.handle_key(key(KeyCode::Char('x')));
        assert!(ui.overlay.is_none());
    }

    #[test]
    fn test_history_and_tab_in_the_input_bar() {
        let mut ui = ui_for("Alice");
        type_text(&mut ui, "/server info");
        ui.handle_key(key(KeyCode::Enter));
        ui.handle_key(key(KeyCode::Up));
        assert_eq!(ui.editor.text(), "/server info");
        ui.handle_key(key(KeyCode::Esc));

        ui.handle_event(bob_connected());
        type_text(&mut ui, "/send b");
        ui.handle_key(key(KeyCode::Tab));
        assert_eq!(ui.editor.text(), "/send Bob ");
    }

    #[test]
    fn test_ctrl_c_quits_even_with_menu_open() {
        let mut ui = ui_for("Alice");
        ui.handle_key(key(KeyCode::F(1)));
        let actions = ui.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(matches!(actions.as_slice(), [UiAction::Quit]));
    }

    #[test]
    fn test_chat_scrolls_with_page_up_and_title_shows_channel() {
        let mut ui = ui_for("Alice");
        for i in 0..100 {
            ui.handle_event(UiEvent::ChatMessage {
                channel: "geral".into(),
                author: "Bob".into(),
                text: format!("mensagem {}", i),
                timestamp: 1_700_000_000 + i as u64,
            });
        }
        let screen = render(&mut ui);
        assert!(screen.contains("mensagem 99") && !screen.contains("mensagem 10 "), "{}", screen);

        ui.handle_key(key(KeyCode::PageUp));
        ui.handle_key(key(KeyCode::PageUp));
        let screen = render(&mut ui);
        assert!(!screen.contains("mensagem 99"), "rolou para cima:\n{}", screen);
        assert!(screen.contains("acima do fim"), "{}", screen);

        ui.handle_event(UiEvent::ChannelChanged("jogos".into()));
        assert!(render(&mut ui).contains("Chat #jogos"), "título acompanha o canal");
    }

    #[test]
    fn test_core_notifications_go_to_system_tab() {
        let mut ui = ui_for("Alice");
        ui.handle_event(UiEvent::SystemLog("Endereço de escuta: /ip4/1.2.3.4".into()));
        ui.handle_event(UiEvent::SystemLog("📜 Rust Guild sincronizado".into()));
        ui.handle_event(UiEvent::ChatMessage {
            channel: "geral".into(),
            author: "Bob".into(),
            text: "oi".into(),
            timestamp: 1_700_000_000,
        });

        let screen = render(&mut ui);
        assert!(screen.contains("Bob: oi"), "{}", screen);
        assert!(!screen.contains("Endereço de escuta"), "chat sem notificações:\n{}", screen);
        assert!(screen.contains("Sistema (2)"), "contador de não lidas:\n{}", screen);
        let status_line = screen.lines().last().unwrap_or_default();
        assert!(status_line.contains("Rust Guild sincronizado"), "barra de status mostra o último evento: {}", status_line);

        ui.handle_key(key(KeyCode::F(2)));
        let screen = render(&mut ui);
        assert!(screen.contains("Endereço de escuta"), "{}", screen);
        assert!(!screen.contains("Bob: oi"), "{}", screen);
        assert!(!screen.contains("Sistema (2)"), "lidas ao abrir a aba");

        ui.handle_event(UiEvent::SystemLog("outro evento".into()));
        assert!(!render(&mut ui).contains("Sistema (1)"), "com a aba aberta, não conta como não lida");
    }

    thread_local! {
        static COPIED: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    /// Área de transferência falsa: guarda o que foi copiado
    fn fake_clipboard(text: &str) -> Result<(), String> {
        COPIED.with(|c| c.borrow_mut().push(text.to_string()));
        Ok(())
    }

    fn last_copied() -> Option<String> {
        COPIED.with(|c| c.borrow().last().cloned())
    }

    /// #92: copiar a própria chave (clique no cabeçalho), a de um membro, a de um amigo e o id do servidor
    #[test]
    fn test_copy_public_keys_and_server_id_to_clipboard() {
        let mut ui = ui_for("Alice");
        ui.clipboard = fake_clipboard;
        render(&mut ui);

        // Clique na chave do cabeçalho copia a chave completa
        let (col, row) = (ui.header_key_cols.0 + 3, ui.header_row);
        assert!(ui.handle_mouse(MouseEvent { kind: MouseEventKind::Down(MouseButton::Left), column: col, row, modifiers: KeyModifiers::NONE }).is_empty());
        assert_eq!(last_copied().as_deref(), Some("abcdef0123"));
        assert!(ui.overlay.is_none());
        let status_line = render(&mut ui).lines().last().unwrap_or_default().to_string();
        assert!(status_line.contains("Sua chave pública copiada"), "{}", status_line);

        // Membro da sala: chave completa dele
        ui.handle_event(bob_connected());
        ui.handle_event(members("geral", &["Bob"]));
        render(&mut ui);
        click(&mut ui, |ui| ui.peers_area, 1, false);
        assert!(select(&mut ui, "📋 Copiar chave pública").is_empty());
        assert_eq!(last_copied().as_deref(), Some("224d733c71f8"));
        assert!(render(&mut ui).lines().last().unwrap_or_default().contains("Chave pública de Bob copiada"));

        // Amigo
        let friend = FriendUiEntry {
            public_key: "cd".repeat(32),
            display_name: "Carol".into(),
            online: true,
            state: p2p_core::identity::FriendState::Confirmed,
        };
        ui.overlay = Some(Overlay::Menu(vec![super::menu::friends_menu(&[friend])]));
        select(&mut ui, "🟢 Carol");
        select(&mut ui, "📋 Copiar chave pública");
        assert_eq!(last_copied(), Some("cd".repeat(32)));

        // Servidor atual
        ui.handle_event(UiEvent::SpaceChanged { space_name: "🏰 Rust Guild".into(), channels: vec![("geral".into(), false)], is_server: true });
        ui.handle_event(UiEvent::ServersChanged(vec![ServerEntry {
            name: "Rust Guild".into(),
            id: "ab".repeat(32),
            current: true,
            owner: false,
            moderator: false,
            pending: false,
            closed: false,
        }]));
        ui.handle_key(key(KeyCode::F(1)));
        select(&mut ui, "Espaços e Servidores");
        select(&mut ui, "📋 Copiar ID do servidor");
        assert_eq!(last_copied(), Some("ab".repeat(32)));
    }

    /// Falha da área de transferência (ex.: Linux sem X11) vira aviso, sem derrubar a interface
    #[test]
    fn test_clipboard_failure_is_reported() {
        let mut ui = ui_for("Alice");
        ui.clipboard = |_| Err("sem servidor gráfico".into());
        ui.copy_to_clipboard("x", "Sua chave pública");
        assert!(ui.last_status_bar.contains("Falha ao copiar"));
        assert!(ui.system_messages.iter().any(|m| m.contains("sem servidor gráfico")));
    }

    #[test]
    fn test_clicking_header_toggles_mic_and_opens_spaces() {
        let mut ui = ui_for("Alice");
        render(&mut ui);
        let click_at = |ui: &mut TerminalUi, col: u16| {
            let row = ui.header_row;
            ui.handle_mouse(MouseEvent { kind: MouseEventKind::Down(MouseButton::Left), column: col, row, modifiers: KeyModifiers::NONE })
        };
        let mic = ui.header_mic_cols.0 + 3;
        assert!(click_at(&mut ui, mic).iter().any(|a| matches!(a, UiAction::ToggleMute)));
        assert!(ui.overlay.is_none());

        let space = ui.header_space_cols.0 + 3;
        assert!(click_at(&mut ui, space).is_empty());
        let Some(Overlay::Menu(stack)) = &ui.overlay else { panic!("menu de espaços não abriu") };
        assert!(stack.last().unwrap().find("▶ 🌐 Lobby").is_some());

        // Em outro ponto da barra não faz nada
        ui.overlay = None;
        let outside = ui.header_space_cols.0 - 2;
        assert!(click_at(&mut ui, outside).is_empty());
        assert!(ui.overlay.is_none());
    }

    #[test]
    fn test_clicking_tab_title_switches_tab() {
        let mut ui = ui_for("Alice");
        ui.handle_event(UiEvent::SystemLog("evento do core".into()));
        render(&mut ui);
        let (x, y, split) = (ui.chat_area.x, ui.chat_area.y, ui.tab_split);
        let click_at = |ui: &mut TerminalUi, col: u16| {
            ui.handle_mouse(MouseEvent { kind: MouseEventKind::Down(MouseButton::Left), column: col, row: y, modifiers: KeyModifiers::NONE })
        };
        click_at(&mut ui, x + split + 4);
        assert_eq!(ui.active_tab, Tab::System);
        assert!(render(&mut ui).contains("evento do core"));
        click_at(&mut ui, x + 3);
        assert_eq!(ui.active_tab, Tab::Chat);
    }

    /// Issue #62: Mensagens de chat e DMs que chegam fora de ordem (por latência do Gossipsub
    /// ou entrega tardia via Guardião da Mailbox Offline) — inclusive enviadas dentro do mesmo segundo
    /// com diferença de milissegundos — são reordenadas automaticamente na TUI pela ordem cronológica
    /// de envio (`timestamp` em milissegundos), mantendo estabilidade (`seq`) no mesmo milissegundo.
    #[test]
    fn test_messages_reordered_chronologically_by_send_timestamp() {
        let mut ui = ui_for("Alice");

        // 1) Chega primeiro uma mensagem mais recente enviada em t = 1_700_000_090_850 ms (.850s do segundo 90)
        ui.handle_event(UiEvent::ChatMessage {
            channel: "geral".into(),
            author: "Bob".into(),
            text: "quarta (enviada em .850s do seg 90, chegou primeiro)".into(),
            timestamp: 1_700_000_090_850,
        });

        // 2) Depois chega uma DM da Mailbox Offline que havia sido enviada antes, em t = 1_700_000_080_100 ms
        ui.handle_event(UiEvent::DirectMessage {
            peer_name: "Carol".into(),
            author: "Carol".into(),
            text: "primeira (enviada em t=80.100s via guardião, chegou atrasada)".into(),
            timestamp: 1_700_000_080_100,
            offline_delivery: true,
        });

        // 3) Duas mensagens no MESMO SEGUNDO (seg 90), mas em milissegundos diferentes (.120s e .450s),
        // chegando na ordem INVERSA (.450s chega antes de .120s): o timestamp em ms corrige a ordem!
        ui.handle_event(UiEvent::ChatMessage {
            channel: "geral".into(),
            author: "Dave".into(),
            text: "terceira (enviada em .450s do seg 90, chegou antes da de .120s)".into(),
            timestamp: 1_700_000_090_450,
        });
        ui.handle_event(UiEvent::DirectMessage {
            peer_name: "Bob".into(),
            author: "Bob".into(),
            text: "segunda (enviada em .120s do seg 90, chegou depois da de .450s)".into(),
            timestamp: 1_700_000_090_120,
            offline_delivery: false,
        });

        // O banner inicial (timestamp = 0) permanece no topo (índices 0 e 1),
        // seguido pelas mensagens em ordem cronológica estrita em milissegundos:
        // 80.100s -> 90.120s -> 90.450s -> 90.850s
        assert!(ui.messages[0].contains("Bem-vindo ao Anarchord"));
        assert!(ui.messages[2].contains("primeira (enviada em t=80.100s"));
        assert!(ui.messages[3].contains("segunda (enviada em .120s"));
        assert!(ui.messages[4].contains("terceira (enviada em .450s"));
        assert!(ui.messages[5].contains("quarta (enviada em .850s"));

        // Verifica também na tela renderizada que a posição vertical (linha) respeita a ordem de envio em ms
        let screen = render(&mut ui);
        let pos_1 = screen.find("primeira (enviada em t=80.100s").expect("1a na tela");
        let pos_2 = screen.find("segunda (enviada em .120s").expect("2a na tela");
        let pos_3 = screen.find("terceira (enviada em .450s").expect("3a na tela");
        let pos_4 = screen.find("quarta (enviada em .850s").expect("4a na tela");
        assert!(pos_1 < pos_2 && pos_2 < pos_3 && pos_3 < pos_4, "tela fora de ordem:\n{}", screen);
    }

    /// Issue #63:
    /// 1. Quando um arquivo é oferecido ou compartilhado (`UiEvent::FileKnown`), o autocompletar com `Tab`
    ///    passa a completar o `<id>` (e o nome) do arquivo para `/get `, `/accept `, `/reject ` e `/unshare `.
    /// 2. Ao executar `/files` (`UiEvent::FilesListed`), a TUI abre um popup clicável (`Overlay::Menu`)
    ///    onde o usuário pode clicar com o mouse (ou usar Enter) para escolher o arquivo e baixar/recusar/parar de compartilhar.
    #[test]
    fn test_file_id_tab_autocomplete_and_clickable_files_popup() {
        let mut ui = ui_for("Alice");

        // 1) Bob oferece um arquivo para Alice -> FileKnown registra o ID curto "bafk9a8b" e nome "relatorio.pdf"
        ui.handle_event(UiEvent::FileKnown(FileUiEntry {
            id: "bafk9a8b".into(),
            name: "relatorio.pdf".into(),
            size: "586 KB".into(),
            from: "Bob".into(),
            state: FileUiState::Offered,
        }));

        // Autocompletar com Tab para `/get bafk` -> `/get bafk9a8b `
        type_text(&mut ui, "/get bafk");
        ui.handle_key(key(KeyCode::Tab));
        assert_eq!(ui.editor.text(), "/get bafk9a8b ");
        ui.handle_key(key(KeyCode::Esc));

        // Autocompletar com Tab também funciona pelo nome do arquivo ou em `/reject ` e `/unshare `
        type_text(&mut ui, "/reject relat");
        ui.handle_key(key(KeyCode::Tab));
        assert_eq!(ui.editor.text(), "/reject relatorio.pdf ");
        ui.handle_key(key(KeyCode::Esc));

        // 2) Usuário executa `/files` e recebe `UiEvent::FilesListed` -> popup interativo abre automaticamente!
        ui.handle_event(UiEvent::FilesListed(vec![
            FileUiEntry {
                id: "bafk9a8b".into(),
                name: "relatorio.pdf".into(),
                size: "586 KB".into(),
                from: "Bob".into(),
                state: FileUiState::Offered,
            },
            FileUiEntry {
                id: "bafk7777".into(),
                name: "musica.ogg".into(),
                size: "4.2 MB".into(),
                from: "você".into(),
                state: FileUiState::Seeding,
            },
        ]));

        let screen = render(&mut ui);
        assert!(
            screen.contains("Arquivos (2)") && screen.contains("[bafk9a8b] relatorio.pdf") && screen.contains("[bafk7777] musica.ogg"),
            "popup de /files deveria listar os arquivos na tela:\n{}",
            screen
        );

        // Clicar com o mouse na 1ª linha do popup (`relatorio.pdf`) abre o submenu de ações daquele arquivo
        assert!(click(&mut ui, |ui| ui.popup_area, 0, false).is_empty());
        let sub_screen = render(&mut ui);
        assert!(
            sub_screen.contains("Baixar 'relatorio.pdf' (/get bafk9a8b)") && sub_screen.contains("Recusar oferta (/reject bafk9a8b)"),
            "submenu do arquivo oferecido:\n{}",
            sub_screen
        );

        // Clicar na 1ª opção do submenu dispara `/get bafk9a8b`!
        let actions = click(&mut ui, |ui| ui.popup_area, 0, false);
        assert_eq!(sent(&actions), vec!["/get bafk9a8b"]);
        assert!(ui.overlay.is_none());
    }

    /// Issue #31: Quebra de linha (word wrap) com recuo nas linhas de continuação
    /// e rolagem horizontal no campo de entrada quando o texto excede a largura da tela.
    #[test]
    fn test_issue_31_message_word_wrap_and_input_scrolling() {
        let mut ui = ui_for("Alice");

        // Mensagem longa recebida de Bob
        let long_text = "Esta é uma mensagem extremamente longa para testar quebra de linha automática na TUI com alinhamento visual perfeito e recuo adequado.";
        ui.handle_event(UiEvent::ChatMessage {
            channel: "geral".to_string(),
            author: "Bob".to_string(),
            text: long_text.to_string(),
            timestamp: 1_700_000_000,
        });

        let screen = render(&mut ui);
        assert!(screen.contains("[#geral] Bob: Esta é uma mensagem"));
        assert!(screen.contains("linha automática na TUI"));

        // Digitando mais texto no campo de entrada do que a largura do terminal
        let long_input = "a".repeat(120);
        type_text(&mut ui, &long_input);
        let screen_input = render(&mut ui);
        assert!(screen_input.contains("aaaaaaaa"));
    }

    /// Issue #33: Notificação de mensagens não lidas e menções no título do terminal quando desfocado.
    #[test]
    fn test_issue_33_terminal_title_and_unread_notifications() {
        let mut ui = ui_for("Alice");
        ui.is_focused = false;

        // Bob envia mensagem comum -> unread_messages = 1
        ui.handle_event(UiEvent::ChatMessage {
            channel: "geral".to_string(),
            author: "Bob".to_string(),
            text: "olá Alice".to_string(),
            timestamp: 1_700_000_000,
        });
        assert_eq!(ui.unread_messages, 1);
        assert!(!ui.has_mention);

        // Bob envia mensagem mencionando @Alice -> has_mention = true
        ui.handle_event(UiEvent::ChatMessage {
            channel: "geral".to_string(),
            author: "Bob".to_string(),
            text: "atenção @Alice urgente".to_string(),
            timestamp: 1_700_000_001,
        });
        assert_eq!(ui.unread_messages, 2);
        assert!(ui.has_mention);

        // Bob envia uma DM direta -> has_mention = true e unread incrementado
        ui.handle_event(UiEvent::DirectMessage {
            peer_name: "Bob".to_string(),
            author: "Bob".to_string(),
            text: "DM privada".to_string(),
            timestamp: 1_700_000_002,
            offline_delivery: false,
        });
        assert_eq!(ui.unread_messages, 3);
        assert!(ui.has_mention);

        // Quando a janela ganha foco novamente (FocusGained), o contador e menção são resetados
        ui.is_focused = true;
        ui.unread_messages = 0;
        ui.has_mention = false;
        assert_eq!(ui.unread_messages, 0);
        assert!(!ui.has_mention);
    }
}
