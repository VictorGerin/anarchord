//! Dois nós completos (`Core`) conversando em localhost só por comandos e eventos, como uma
//! interface faria: Lobby, servidor, convite, grupo cifrado, moderação e histórico.

use p2p_core::runtime::{
    Core, CoreCommand, CoreConfig, CoreError, CoreEvent, CoreHandle, RoomKeyStatus, ServerChange, ServerCommand, ServerNotice, SpaceInfo,
};
use p2p_core::UserIdentity;
use std::path::PathBuf;
use std::time::Duration;

/// Tempo máximo padrão de espera por um evento de rede/runtime nos testes de integração.
/// Pode ser sobrescrito pela variável de ambiente `ANARCHORD_TEST_TIMEOUT_SECS` (ex.: `ANARCHORD_TEST_TIMEOUT_SECS=90`).
/// Sob carga no Windows/debug, recomenda-se limitar a concorrência com `--test-threads=2` ou `RUST_TEST_THREADS=2`.
const DEFAULT_TIMEOUT_SECS: u64 = 40;

fn timeout() -> Duration {
    std::env::var("ANARCHORD_TEST_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&s| s > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_TIMEOUT_SECS))
}

struct Peer {
    handle: CoreHandle,
    /// Tudo o que o core já mandou
    seen: Vec<CoreEvent>,
}

impl Peer {
    fn send(&self, command: CoreCommand) {
        self.handle.send(command);
    }

    fn server(&self, command: ServerCommand) {
        self.send(CoreCommand::Server(command));
    }

    /// Lê eventos até algum (já recebido ou novo) satisfazer `pred`
    async fn wait(&mut self, what: &str, pred: impl Fn(&CoreEvent) -> bool) -> CoreEvent {
        if let Some(found) = self.seen.iter().find(|e| pred(e)) {
            return found.clone();
        }
        let result = tokio::time::timeout(timeout(), async {
            loop {
                let event = self.handle.next_event().await.expect("core encerrou");
                self.seen.push(event.clone());
                if pred(&event) {
                    return event;
                }
            }
        })
        .await;
        result.unwrap_or_else(|_| panic!("tempo esgotado esperando: {}. Eventos vistos:\n{:#?}", what, self.seen))
    }

    /// Como `wait`, mas só vale evento que chegou depois da posição `from` de `seen`
    async fn wait_after(&mut self, from: usize, what: &str, pred: impl Fn(&CoreEvent) -> bool) -> CoreEvent {
        if let Some(found) = self.seen.iter().skip(from).find(|e| pred(e)) {
            return found.clone();
        }
        let result = tokio::time::timeout(timeout(), async {
            loop {
                let event = self.handle.next_event().await.expect("core encerrou");
                self.seen.push(event.clone());
                if pred(&event) {
                    return event;
                }
            }
        })
        .await;
        result.unwrap_or_else(|_| panic!("tempo esgotado esperando: {}. Eventos vistos:\n{:#?}", what, &self.seen[from..]))
    }

    /// Estados da chave da sala enviados até agora, em ordem
    fn room_keys(&self) -> Vec<RoomKeyStatus> {
        self.seen.iter().filter_map(|e| match e { CoreEvent::RoomKey(s) => Some(*s), _ => None }).collect()
    }

    /// Lê o que chegar por `duration`
    async fn drain(&mut self, duration: Duration) {
        let _ = tokio::time::timeout(duration, async {
            while let Some(event) = self.handle.next_event().await {
                self.seen.push(event);
            }
        })
        .await;
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("anarchord_runtime_{}_{}_{}", tag, std::process::id(), rand_suffix()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64
}

fn start(nick: &str, connect_to: Option<u16>) -> (Peer, p2p_core::runtime::CoreTask) {
    let mut config = CoreConfig::new(UserIdentity::generate_with_nick(nick), temp_dir(&format!("{}_srv", nick)), temp_dir(&format!("{}_down", nick)));
    // Canal exclusivo do teste, para não misturar com nós Anarchord reais na LAN (mDNS)
    config.channel = format!("teste-{}", rand_suffix());
    config.connect = connect_to.map(|port| format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap());
    let (handle, task) = Core::start(config).expect("core deve iniciar");
    (Peer { handle, seen: Vec::new() }, task)
}

fn start_with_dirs(
    _nick: &str,
    identity: UserIdentity,
    srv_dir: PathBuf,
    down_dir: PathBuf,
    channel: String,
    connect_to: Option<u16>,
) -> (Peer, p2p_core::runtime::CoreTask) {
    let mut config = CoreConfig::new(identity, srv_dir, down_dir);
    config.channel = channel;
    config.connect = connect_to.map(|port| format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap());
    let (handle, task) = Core::start(config).expect("core deve iniciar");
    (Peer { handle, seen: Vec::new() }, task)
}

fn chat_text(event: &CoreEvent) -> Option<&str> {
    match event {
        CoreEvent::ChatMessage { text, .. } => Some(text),
        _ => None,
    }
}

#[tokio::test]
async fn test_two_cores_server_lifecycle() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut alice, alice_task) = start("Alice", None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut bob, bob_task) = start("Bob", Some(alice_port));
            tokio::task::spawn_local(bob_task.run());

            let CoreEvent::PeerIdentified { pubkey: bob_pk, .. } =
                alice.wait("Alice identificar Bob", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Bob")).await
            else {
                unreachable!()
            };
            let CoreEvent::PeerIdentified { pubkey: alice_pk, .. } =
                bob.wait("Bob identificar Alice", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Alice")).await
            else {
                unreachable!()
            };

            // Alice cria o servidor e entra nele
            alice.server(ServerCommand::Create("Rust Guild".into()));
            let CoreEvent::Server(ServerNotice::Created { id, .. }) =
                alice.wait("servidor criado", |e| matches!(e, CoreEvent::Server(ServerNotice::Created { .. }))).await
            else {
                unreachable!()
            };
            let in_server = |id: String| move |e: &CoreEvent| matches!(e, CoreEvent::ChannelEntered { space: SpaceInfo::Server { id: sid, .. }, .. } if *sid == id);
            alice.wait("Alice entrar no servidor", in_server(id.clone())).await;
            // Sozinha na sala, Alice cria o grupo cifrado: a interface recebe a chave pronta
            alice.wait("Alice com a chave da sala", |e| matches!(e, CoreEvent::RoomKey(RoomKeyStatus::Ready))).await;
            let ready_at = alice.seen.len();

            // Convite no Lobby #geral: os dois precisam estar lá (o canal de teste é outro)
            alice.send(CoreCommand::Server(ServerCommand::Switch("lobby".into())));
            alice.wait_after(ready_at, "Lobby sem cifra", |e| matches!(e, CoreEvent::RoomKey(RoomKeyStatus::Unencrypted))).await;
            bob.send(CoreCommand::JoinChannel("geral".into()));
            alice.send(CoreCommand::JoinChannel("geral".into()));
            bob.wait("Bob ver Alice em #geral", |e| matches!(e, CoreEvent::ChannelMembers { channel, members } if channel == "geral" && members.iter().any(|m| m == "Alice"))).await;
            alice.send(CoreCommand::Server(ServerCommand::Switch("Rust Guild".into())));
            // Repete até a malha do #geral se formar (sem ninguém lá, o convite não é publicado)
            for _ in 0..20 {
                alice.server(ServerCommand::Invite { target: None, server_id: None });
                alice.drain(Duration::from_millis(500)).await;
                if alice.seen.iter().any(|e| matches!(e, CoreEvent::Server(ServerNotice::InviteSent { .. }))) {
                    break;
                }
            }
            alice.wait("convite publicado", |e| matches!(e, CoreEvent::Server(ServerNotice::InviteSent { .. }))).await;
            let sid = id.clone();
            bob.wait("convite chegar", move |e| matches!(e, CoreEvent::InviteReceived { server_id, .. } if *server_id == sid)).await;

            // Bob aceita, recebe a cadeia, entra e ganha a chave do grupo cifrado
            bob.server(ServerCommand::Accept);
            bob.wait("Bob entrar no servidor", in_server(id.clone())).await;
            bob.wait("Bob receber a chave do grupo", |e| matches!(e, CoreEvent::Server(ServerNotice::KeyReceived { .. }))).await;
            // A interface viu o aviso de espera antes do Welcome e o 🔐 depois dele
            bob.wait("sala de Bob cifrada", |e| matches!(e, CoreEvent::RoomKey(RoomKeyStatus::Ready))).await;
            let keys = bob.room_keys();
            assert_eq!(keys.first(), Some(&RoomKeyStatus::Unencrypted), "{:?}", keys);
            let waiting = keys.iter().position(|k| *k == RoomKeyStatus::Waiting).expect("aviso de espera pela chave");
            assert!(keys[waiting..].contains(&RoomKeyStatus::Ready), "{:?}", keys);
            assert!(keys.windows(2).all(|w| w[0] != w[1]), "só emite quando muda: {:?}", keys);

            // Chat do servidor (cifrado de ponta a ponta); repete até a malha do tópico se formar
            let mut received = false;
            for _ in 0..20 {
                alice.send(CoreCommand::SendMessage("segredo do servidor".into()));
                bob.drain(Duration::from_millis(500)).await;
                if bob.seen.iter().any(|e| chat_text(e) == Some("segredo do servidor")) {
                    received = true;
                    break;
                }
            }
            assert!(received, "mensagem cifrada deveria chegar a Bob");

            // Passaporte de membro não dá permissão de moderar
            bob.server(ServerCommand::Ban { target: "Alice".into(), duration: None, reason: String::new() });
            bob.wait("ban recusado sem permissão", |e| matches!(e, CoreEvent::Error(CoreError::Server(m)) if m.contains("não dá essa permissão"))).await;

            // O líder determinístico atual (menor pubkey entre Alice e Bob) gira a chave MLS (/server rotate-key)
            if alice_pk < bob_pk {
                alice.server(ServerCommand::RotateKey);
                alice.wait("Alice rotacionar chave MLS", |e| matches!(e, CoreEvent::Server(ServerNotice::KeyRotated { .. }))).await;
            } else {
                bob.server(ServerCommand::RotateKey);
                bob.wait("Bob rotacionar chave MLS", |e| matches!(e, CoreEvent::Server(ServerNotice::KeyRotated { .. }))).await;
            }

            // Alice cria um canal de texto e um canal de voz (que também é canal de texto com o mesmo nome!)
            alice.server(ServerCommand::AddChannel { name: "jogos".into(), voice: false });
            alice.server(ServerCommand::AddChannel { name: "taverna".into(), voice: true });
            alice.wait("canal taverna adicionado", |e| {
                matches!(e, CoreEvent::Server(ServerNotice::Changed { change: ServerChange::ChannelAdded { name, voice: true }, .. }) if name == "taverna")
            }).await;

            // Entrar num canal de voz (JoinVoice) entra simultaneamente na voz E no chat de texto daquele canal ("taverna")
            alice.send(CoreCommand::JoinVoice("taverna".into()));
            alice.wait("Alice entrar na voz de taverna", |e| {
                matches!(e, CoreEvent::Voice(p2p_core::runtime::VoiceEvent::Joined(ch)) if ch == "taverna")
            }).await;
            alice.wait("Alice entrar no chat de texto de taverna junto com a voz", |e| {
                matches!(e, CoreEvent::ChannelEntered { channel, .. } if channel == "taverna")
            }).await;

            // Clicar/entrar num canal de texto (JoinChannel "geral") é uma ordem de saída do canal de voz:
            // Alice desconecta automaticamente da voz ("taverna") e fica somente no canal de texto "geral"!
            alice.send(CoreCommand::JoinChannel("geral".into()));
            alice.wait("Alice sair automaticamente da sala de voz ao clicar num canal de texto", |e| {
                matches!(e, CoreEvent::Voice(p2p_core::runtime::VoiceEvent::Left(ch)) if ch == "taverna")
            }).await;
            alice.wait("Alice voltar para o canal de texto #geral", |e| {
                matches!(e, CoreEvent::ChannelEntered { channel, .. } if channel == "geral")
            }).await;
            // Cada sala tem o próprio grupo cifrado: Alice voltou para o grupo de #geral (Bob a readmite)
            assert!(exchange(&mut alice, &mut bob, "de volta ao geral").await, "Alice e Bob no mesmo grupo de #geral");

            // Alice emite passaporte de moderador para Bob
            alice.server(ServerCommand::AddModerator { target: "Bob".into(), permissions: None });
            alice
                .wait("Bob certificado", |e| matches!(e, CoreEvent::Server(ServerNotice::Changed { change: ServerChange::ModeratorAdded { .. }, .. })))
                .await;
            bob.wait("Bob virar moderador", |e| matches!(e, CoreEvent::Server(ServerNotice::Role { moderator: true, .. }))).await;

            // Moderador não age sobre a dona
            bob.server(ServerCommand::Ban { target: "Alice".into(), duration: None, reason: String::new() });
            bob.wait("ban recusado: dono protegido", |e| matches!(e, CoreEvent::Error(CoreError::Server(m)) if m.contains("protegido"))).await;

            // Alice revoga o passaporte de moderador e bane Bob por 1 hora
            // Cada alteração só vale com o carimbo de tempo: a revogação é aplicada (e chega a Bob) antes do ban
            alice.server(ServerCommand::RemoveModerator("Bob".into()));
            alice.wait("revogação aplicada", |e| matches!(e, CoreEvent::Server(ServerNotice::Changed { change: ServerChange::ModeratorRemoved { .. }, .. }))).await;
            bob.wait("Bob deixar de ser moderador", |e| matches!(e, CoreEvent::Server(ServerNotice::Role { moderator: false, .. }))).await;
            let before_ban = alice.seen.len();
            alice.server(ServerCommand::Ban { target: "Bob".into(), duration: Some(3600), reason: "spam".into() });
            alice.wait("ban gravado", |e| matches!(e, CoreEvent::Server(ServerNotice::Moderated { .. }))).await;
            bob.wait("Bob ser avisado do ban", |e| matches!(e, CoreEvent::Server(ServerNotice::BanStatus { banned: true, .. }))).await;
            alice
                .wait_after(before_ban, "banido não aparece na lista do canal", |e| {
                    matches!(e, CoreEvent::ChannelMembers { members, .. } if !members.iter().any(|m| m == "Bob"))
                })
                .await;

            // A manutenção da dona tira Bob do grupo cifrado; depois disso ele não lê mais nada
            bob.wait("Bob sair do grupo cifrado", |e| matches!(e, CoreEvent::Server(ServerNotice::RemovedFromGroup { .. }))).await;
            let removed_at = bob.seen.iter().position(|e| matches!(e, CoreEvent::Server(ServerNotice::RemovedFromGroup { .. }))).unwrap();
            bob.wait_after(removed_at, "Bob perder o 🔐", |e| matches!(e, CoreEvent::RoomKey(RoomKeyStatus::Waiting))).await;
            for _ in 0..4 {
                alice.send(CoreCommand::SendMessage("depois do ban".into()));
                bob.drain(Duration::from_millis(500)).await;
            }
            assert!(!bob.seen.iter().any(|e| chat_text(e) == Some("depois do ban")), "banido não lê mais o servidor");
            assert!(
                bob.seen.iter().any(|e| matches!(e, CoreEvent::EncryptedMessage { channel, size, .. } if channel == "geral" && *size > 0)),
                "o banido vê que as mensagens chegam, mas só cifradas"
            );

            // O histórico (a cadeia) registra tudo
            bob.server(ServerCommand::History);
            let CoreEvent::Server(ServerNotice::History(history)) =
                bob.wait("histórico", |e| matches!(e, CoreEvent::Server(ServerNotice::History(_)))).await
            else {
                unreachable!()
            };
            let text: Vec<&str> = history.iter().map(|h| h.description.as_str()).collect();
            let joined = text.join("\n");
            assert!(joined.contains("criado 'Rust Guild'"), "{}", joined);
            let alice_errors: Vec<&CoreEvent> = alice.seen.iter().filter(|e| matches!(e, CoreEvent::Error(_))).collect();
            assert!(joined.contains("revogou o passaporte"), "{}\nerros de Alice: {:?}", joined, alice_errors);
            assert!(joined.contains(" baniu "), "{}", joined);

            alice.send(CoreCommand::Shutdown);
            alice.wait("Alice encerrar", |e| matches!(e, CoreEvent::Stopped)).await;
        })
        .await;
}

/// Arquivo compartilhado na sala chega a quem pede, tudo pelo core
#[tokio::test]
async fn test_two_cores_share_file_in_room() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut alice, alice_task) = start("Carol", None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut bob, bob_task) = start("Dave", Some(alice_port));
            tokio::task::spawn_local(bob_task.run());
            let room = format!("arquivos-{}", rand_suffix());
            for peer in [&alice, &bob] {
                peer.send(CoreCommand::JoinChannel(room.clone()));
            }
            let r = room.clone();
            alice.wait("Alice ver Bob na sala", move |e| matches!(e, CoreEvent::ChannelMembers { channel, members } if channel == &r && members.iter().any(|m| m == "Dave"))).await;

            let dir = temp_dir("arquivo");
            let path = dir.join("notas.txt");
            let data: Vec<u8> = (0..700_000).map(|i| (i % 251) as u8).collect();
            std::fs::write(&path, &data).unwrap();
            alice.send(CoreCommand::ShareFile(path));

            let CoreEvent::File(p2p_core::files::FileEvent::Offered { cid, .. }) =
                bob.wait("oferta chegar", |e| matches!(e, CoreEvent::File(p2p_core::files::FileEvent::Offered { .. }))).await
            else {
                unreachable!()
            };
            bob.send(CoreCommand::GetFile(cid.short()));
            let CoreEvent::File(p2p_core::files::FileEvent::Completed { path, .. }) =
                bob.wait("download terminar", |e| matches!(e, CoreEvent::File(p2p_core::files::FileEvent::Completed { .. }))).await
            else {
                unreachable!()
            };
            assert_eq!(std::fs::read(path).unwrap(), data);
        })
        .await;
}

/// Issue #68 & #66: Download interrompido retoma automaticamente ao iniciar o app,
/// reconecta aos seeders via tópico de enxame `anarchord/file/<cid>`, emite o progresso
/// inicial herdado (> 0.0) e conclui os pedaços restantes com sucesso
#[tokio::test]
async fn test_two_cores_resume_file_after_restart() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let alice_ident = UserIdentity::generate_with_nick("Alice");
            let alice_srv = temp_dir("alice_srv");
            let alice_down = temp_dir("alice_down");
            let room = format!("resume-room-{}", rand_suffix());

            let (mut alice, alice_task) = start_with_dirs("Alice", alice_ident.clone(), alice_srv, alice_down, room.clone(), None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());

            let bob_ident = UserIdentity::generate_with_nick("Bob");
            let bob_srv = temp_dir("bob_srv");
            let bob_down = temp_dir("bob_down");

            // Alice entra na sala e compartilha o arquivo
            let dir = temp_dir("orig_arquivo");
            let path = dir.join("grande.bin");
            let data: Vec<u8> = (0..800_000).map(|i| (i * 17 % 255) as u8).collect();
            std::fs::write(&path, &data).unwrap();

            alice.send(CoreCommand::JoinChannel(room.clone()));
            alice.send(CoreCommand::ShareFile(path.clone()));
            let CoreEvent::File(p2p_core::files::FileEvent::Shared { cid, .. }) =
                alice.wait("Alice concluir compartilhamento e semear", |e| {
                    matches!(e, CoreEvent::File(p2p_core::files::FileEvent::Shared { .. }))
                }).await
            else {
                unreachable!()
            };

            // Encontra o manifesto exato com o mesmo timestamp gerado por Alice
            let t_now = p2p_core::runtime::now_secs();
            let manifest = (t_now.saturating_sub(2)..=t_now + 2)
                .find_map(|t| {
                    p2p_core::files::Manifest::from_file(&path, &alice_ident, None, t)
                        .ok()
                        .filter(|m| m.cid() == cid)
                })
                .expect("manifesto correspondente ao CID da Alice");

            // Simula um download parcial interrompido em Bob: grava 2 de 4 pedaços no disco de Bob
            let partial_dir = bob_down.join(".parcial").join(&bob_ident.public_key_hex()[..8]);
            let alice_store = p2p_core::files::PieceStore::seed(manifest.clone(), path.clone(), None);
            let p0 = alice_store.serve_piece(0).unwrap();
            let p1 = alice_store.serve_piece(1).unwrap();
            {
                let mut bob_store = p2p_core::files::PieceStore::create(
                    &partial_dir,
                    manifest.clone(),
                    None,
                    Some(p2p_core::files::Origin::Topic(room.clone())),
                )
                .unwrap();
                bob_store.accept_piece(0, &p0).unwrap();
                bob_store.accept_piece(1, &p1).unwrap();
            }

            // Bob inicia pela primeira vez com o download já pendente na pasta .parcial
            let (mut bob, bob_task) = start_with_dirs("Bob", bob_ident, bob_srv, bob_down, room.clone(), Some(alice_port));
            tokio::task::spawn_local(bob_task.run());
            bob.send(CoreCommand::JoinChannel(room.clone()));

            // Issue #68: Bob emite imediatamente o progresso inicial herdado (50% = 0.5)
            bob.wait("Bob emitir progresso inicial herdado", |e| {
                matches!(e, CoreEvent::File(p2p_core::files::FileEvent::Progress { progress, .. }) if *progress >= 0.5)
            })
            .await;

            // Issue #66: Bob se conecta ao tópico anarchord/file/<cid> e conclui os 50% restantes
            let CoreEvent::File(p2p_core::files::FileEvent::Completed { path: downloaded_path, .. }) =
                bob.wait("Bob concluir download retomado", |e| {
                    matches!(e, CoreEvent::File(p2p_core::files::FileEvent::Completed { .. }))
                })
                .await
            else {
                unreachable!()
            };

            // Validação estrita de integridade via SHA-512 do arquivo antes e depois da transferência
            let original_sha512 = {
                use sha2::{Digest, Sha512};
                Sha512::digest(&data)
            };
            let downloaded_bytes = std::fs::read(downloaded_path).unwrap();
            let downloaded_sha512 = {
                use sha2::{Digest, Sha512};
                Sha512::digest(&downloaded_bytes)
            };
            assert_eq!(original_sha512, downloaded_sha512, "SHA-512 do arquivo retomado deve ser idêntico ao original");
            assert_eq!(downloaded_bytes, data);
        })
        .await;
}


/// Issue #74: Nós que iniciam no mesmo canal devem se ver mutuamente em ChannelMembers
/// ao se conectarem, sem precisar de JoinChannel manual nem de mensagem de chat.
#[tokio::test]
async fn test_two_cores_see_each_other_in_same_channel_on_connect() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let room = format!("geral-{}", rand_suffix());
            let (mut alice, alice_task) = start_with_dirs(
                "Alice",
                UserIdentity::generate_with_nick("Alice"),
                temp_dir("alice_srv"),
                temp_dir("alice_down"),
                room.clone(),
                None,
            );
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());

            let (mut bob, bob_task) = start_with_dirs(
                "Bob",
                UserIdentity::generate_with_nick("Bob"),
                temp_dir("bob_srv"),
                temp_dir("bob_down"),
                room.clone(),
                Some(alice_port),
            );
            tokio::task::spawn_local(bob_task.run());

            let r = room.clone();
            let r2 = room.clone();
            let alice_sees_bob = alice.wait("Alice ver Bob em ChannelMembers", move |e| {
                matches!(e, CoreEvent::ChannelMembers { channel, members } if channel == &r && members.iter().any(|m| m == "Bob"))
            });
            let bob_sees_alice = bob.wait("Bob ver Alice em ChannelMembers", move |e| {
                matches!(e, CoreEvent::ChannelMembers { channel, members } if channel == &r2 && members.iter().any(|m| m == "Alice"))
            });

            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(alice_sees_bob, bob_sees_alice);
            })
            .await
            .expect("Ambos os nós devem se ver em ChannelMembers após conexão direta");
        })
        .await;
}


/// Testa o fluxo completo de Passaportes do Servidor (ServerPassport):
/// 1. Alice cria servidor e gera passaporte de dono automático;
/// 2. Alice e Bob se conectam;
/// 3. Alice emite passaporte de moderador para Bob;
/// 4. Bob recebe e armazena o passaporte com sucesso;
/// 5. Bob consulta seu passaporte via ShowPassport e obtém PassportInfo.
#[tokio::test]
async fn test_server_passport_issuance_acceptance_and_flattening() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let room = format!("geral-{}", rand_suffix());
            let alice_id = UserIdentity::generate_with_nick("Alice");
            let bob_id = UserIdentity::generate_with_nick("Bob");
            let bob_pubkey = bob_id.public_key_hex();

            let (mut alice, alice_task) = start_with_dirs(
                "Alice",
                alice_id,
                temp_dir("alice_passport_srv"),
                temp_dir("alice_passport_down"),
                room.clone(),
                None,
            );
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());

            let (mut bob, bob_task) = start_with_dirs(
                "Bob",
                bob_id,
                temp_dir("bob_passport_srv"),
                temp_dir("bob_passport_down"),
                room.clone(),
                Some(alice_port),
            );
            tokio::task::spawn_local(bob_task.run());

            // Alice e Bob se conectam no Swarm
            alice
                .wait("Alice identificar Bob", |e| {
                    matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Bob")
                })
                .await;
            bob
                .wait("Bob identificar Alice", |e| {
                    matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Alice")
                })
                .await;

            // 1. Alice cria o servidor
            alice.server(ServerCommand::Create("Fortaleza".to_string()));
            let created = alice
                .wait("Alice criar servidor Fortaleza", |e| {
                    matches!(e, CoreEvent::Server(ServerNotice::Created { .. }))
                })
                .await;
            let server_id = match created {
                CoreEvent::Server(ServerNotice::Created { id, .. }) => id,
                _ => unreachable!(),
            };

            // Bob passa a acompanhar o servidor aberto (recebe Welcome + passaporte automático de membro)
            bob.server(ServerCommand::Join(server_id.clone()));

            // Bob recebe passaporte automático inicial de membro (nível 255) e entra no servidor
            bob
                .wait("Bob receber passaporte inicial de membro", |e| {
                    matches!(e, CoreEvent::Server(ServerNotice::PassportUpdated { .. }))
                })
                .await;
            let sid = server_id.clone();
            bob.wait("Bob entrar no servidor", move |e| {
                matches!(e, CoreEvent::ChannelEntered { space: SpaceInfo::Server { id, .. }, .. } if *id == sid)
            })
            .await;

            bob.server(ServerCommand::ShowPassport);
            let initial_info = bob
                .wait("Bob receber PassportInfo inicial", |e| {
                    matches!(e, CoreEvent::Server(ServerNotice::PassportInfo { .. }))
                })
                .await;
            assert!(matches!(initial_info, CoreEvent::Server(ServerNotice::PassportInfo { ref permissions, .. }) if !permissions.contains(&"Ban".to_string())));

            // 2. Alice promove Bob emitindo passaporte de moderador
            let before_promote = bob.seen.len();
            alice.server(ServerCommand::IssuePassport {
                target: "Bob".to_string(),
                moderator: true,
                duration: Some(7 * 86_400),
            });

            // 3. Bob recebe a oferta do novo passaporte e consulta a promoção para nível 2
            bob.wait_after(before_promote, "Bob receber passaporte de moderador", |e| {
                matches!(e, CoreEvent::Server(ServerNotice::PassportUpdated { .. }))
            })
            .await;
            bob.server(ServerCommand::ShowPassport);
            let promoted_info = bob
                .wait("Bob receber PassportInfo de moderador", |e| {
                    matches!(e, CoreEvent::Server(ServerNotice::PassportInfo { permissions, .. }) if permissions.contains(&"Ban".to_string()))
                })
                .await;

            match promoted_info {
                CoreEvent::Server(ServerNotice::PassportInfo {
                    holder,
                    chain_depth,
                    permissions,
                    ..
                }) => {
                    assert_eq!(holder, bob_pubkey);
                    assert_eq!(chain_depth, 1);
                    assert!(permissions.contains(&"EnterServer".to_string()));
                    assert!(permissions.contains(&"Ban".to_string()));
                }
                _ => unreachable!(),
            }
        })
        .await;
}

/// Dona e membro saem e voltam: o servidor continua funcionando com os dados salvos em disco
#[tokio::test]
async fn test_server_chat_survives_restart_of_owner_and_member() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (alice_ident, bob_ident) = (UserIdentity::generate_with_nick("Alice"), UserIdentity::generate_with_nick("Bob"));
            let (alice_srv, alice_down, bob_srv, bob_down) = (temp_dir("ra_srv"), temp_dir("ra_down"), temp_dir("rb_srv"), temp_dir("rb_down"));
            let room = format!("teste-{}", rand_suffix());
            let in_server = |id: String| move |e: &CoreEvent| matches!(e, CoreEvent::ChannelEntered { space: SpaceInfo::Server { id: sid, .. }, .. } if *sid == id);

            // 1ª sessão: Alice cria, Bob entra e recebe passaporte automático
            let (mut alice, alice_task) = start_with_dirs("Alice", alice_ident.clone(), alice_srv.clone(), alice_down.clone(), room.clone(), None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut bob, bob_task) = start_with_dirs("Bob", bob_ident.clone(), bob_srv.clone(), bob_down.clone(), room.clone(), Some(alice_port));
            tokio::task::spawn_local(bob_task.run());
            alice.wait("Alice identificar Bob", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Bob")).await;
            alice.server(ServerCommand::Create("Guilda".into()));
            let CoreEvent::Server(ServerNotice::Created { id, .. }) =
                alice.wait("servidor criado", |e| matches!(e, CoreEvent::Server(ServerNotice::Created { .. }))).await
            else {
                unreachable!()
            };
            bob.server(ServerCommand::Join(id.clone()));
            bob.wait("Bob receber a chave", |e| matches!(e, CoreEvent::Server(ServerNotice::KeyReceived { .. }))).await;
            alice.send(CoreCommand::Shutdown);
            bob.send(CoreCommand::Shutdown);
            alice.wait("Alice encerrar", |e| matches!(e, CoreEvent::Stopped)).await;
            bob.wait("Bob encerrar", |e| matches!(e, CoreEvent::Stopped)).await;

            // 2ª sessão: os dois voltam e conversam no servidor
            let (mut alice, alice_task) = start_with_dirs("Alice", alice_ident, alice_srv, alice_down, room.clone(), None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut bob, bob_task) = start_with_dirs("Bob", bob_ident, bob_srv, bob_down, room, Some(alice_port));
            tokio::task::spawn_local(bob_task.run());
            alice.wait("Alice identificar Bob de novo", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Bob")).await;
            alice.server(ServerCommand::Switch(id.clone()));
            bob.server(ServerCommand::Switch(id.clone()));
            alice.wait("Alice voltar ao servidor", in_server(id.clone())).await;
            bob.wait("Bob voltar ao servidor", in_server(id.clone())).await;

            let mut received = false;
            for _ in 0..30 {
                alice.send(CoreCommand::SendMessage("de volta".into()));
                bob.drain(Duration::from_millis(500)).await;
                if bob.seen.iter().any(|e| chat_text(e) == Some("de volta")) {
                    received = true;
                    break;
                }
            }
            alice.drain(Duration::from_millis(100)).await;
            assert!(received, "Bob deveria receber a mensagem depois de voltar.\nBob: {:#?}\nAlice: {:#?}",
                bob.seen.iter().filter(|e| !matches!(e, CoreEvent::Network(_))).collect::<Vec<_>>(),
                alice.seen.iter().filter(|e| matches!(e, CoreEvent::Server(_) | CoreEvent::Error(_))).collect::<Vec<_>>());
        })
        .await;
}

#[tokio::test]
async fn test_private_server_direct_invite_with_passport() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (alice_ident, bob_ident) = (UserIdentity::generate_with_nick("Alice"), UserIdentity::generate_with_nick("Bob"));
            let (alice_srv, alice_down, bob_srv, bob_down) = (temp_dir("priv_srv_a"), temp_dir("priv_down_a"), temp_dir("priv_srv_b"), temp_dir("priv_down_b"));
            let room = format!("priv-{}", rand_suffix());
            let in_server = |id: String| move |e: &CoreEvent| matches!(e, CoreEvent::ChannelEntered { space: SpaceInfo::Server { id: sid, .. }, .. } if *sid == id);

            let (mut alice, alice_task) = start_with_dirs("Alice", alice_ident, alice_srv, alice_down, room.clone(), None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut bob, bob_task) = start_with_dirs("Bob", bob_ident, bob_srv, bob_down, room, Some(alice_port));
            tokio::task::spawn_local(bob_task.run());

            alice.wait("Alice identificar Bob", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Bob")).await;
            bob.wait("Bob identificar Alice", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Alice")).await;

            // 1. Alice cria um servidor e torna privado (fechado)
            alice.server(ServerCommand::Create("Clube Privado".into()));
            let CoreEvent::Server(ServerNotice::Created { id, .. }) =
                alice.wait("servidor criado", |e| matches!(e, CoreEvent::Server(ServerNotice::Created { .. }))).await
            else {
                unreachable!()
            };

            alice.server(ServerCommand::Close);
            alice.wait("servidor fechado", |e| matches!(e, CoreEvent::Server(ServerNotice::Changed { change: ServerChange::Closed, .. }))).await;

            // 2. Alice convida Bob diretamente para o servidor privado
            alice.server(ServerCommand::Invite { target: Some("Bob".into()), server_id: Some(id.clone()) });
            alice.wait("convite enviado", |e| matches!(e, CoreEvent::Server(ServerNotice::InviteSent { .. }))).await;

            // 3. Bob recebe o convite contendo o passaporte embutido
            let sid = id.clone();
            bob.wait("Bob receber convite com passaporte", move |e| matches!(e, CoreEvent::InviteReceived { server_id, .. } if *server_id == sid)).await;

            // 4. Bob aceita o convite e entra diretamente no servidor privado
            bob.server(ServerCommand::Accept);
            bob.wait("Bob entrar no servidor privado", in_server(id.clone())).await;
            bob.wait("Bob receber chave do grupo MLS", |e| matches!(e, CoreEvent::Server(ServerNotice::KeyReceived { .. }))).await;
        })
        .await;
}

/// O líder do grupo cifrado cai e volta (como num Ctrl+C) enquanto o outro membro continua com o
/// grupo antigo: ao voltar, ele é readmitido com chave nova e os dois voltam a conversar
#[tokio::test]
async fn test_leader_restart_is_readmitted_with_new_key() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (alice_ident, bob_ident) = (UserIdentity::generate_with_nick("Alice"), UserIdentity::generate_with_nick("Bob"));
            let (alice_srv, alice_down, bob_srv, bob_down) = (temp_dir("la_srv"), temp_dir("la_down"), temp_dir("lb_srv"), temp_dir("lb_down"));
            let room = format!("teste-{}", rand_suffix());
            let in_server = |id: String| move |e: &CoreEvent| matches!(e, CoreEvent::ChannelEntered { space: SpaceInfo::Server { id: sid, .. }, .. } if *sid == id);

            let (mut alice, alice_task) = start_with_dirs("Alice", alice_ident.clone(), alice_srv.clone(), alice_down.clone(), room.clone(), None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut bob, bob_task) = start_with_dirs("Bob", bob_ident.clone(), bob_srv.clone(), bob_down.clone(), room.clone(), Some(alice_port));
            let bob_port = bob_task.listen_port();
            tokio::task::spawn_local(bob_task.run());
            alice.wait("Alice identificar Bob", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Bob")).await;
            alice.server(ServerCommand::Create("Guilda".into()));
            let CoreEvent::Server(ServerNotice::Created { id, .. }) =
                alice.wait("servidor criado", |e| matches!(e, CoreEvent::Server(ServerNotice::Created { .. }))).await
            else {
                unreachable!()
            };
            bob.server(ServerCommand::Join(id.clone()));
            bob.wait("Bob receber a chave", |e| matches!(e, CoreEvent::Server(ServerNotice::KeyReceived { .. }))).await;
            bob.wait("Bob ver quem lidera", |e| matches!(e, CoreEvent::Server(ServerNotice::LeaderChanged { leader: Some(_), .. }))).await;

            // Reinicia só quem for o líder (menor pubkey); o outro fica com o grupo antigo
            let alice_leads = alice_ident.public_key_hex() < bob_ident.public_key_hex();
            let (leader, member) = if alice_leads { (&mut alice, &mut bob) } else { (&mut bob, &mut alice) };
            leader.send(CoreCommand::Shutdown);
            leader.wait("líder cair", |e| matches!(e, CoreEvent::Stopped)).await;
            let (mut leader, leader_task) = if alice_leads {
                start_with_dirs("Alice", alice_ident, alice_srv, alice_down, room.clone(), Some(bob_port))
            } else {
                start_with_dirs("Bob", bob_ident, bob_srv, bob_down, room.clone(), Some(alice_port))
            };
            tokio::task::spawn_local(leader_task.run());
            leader.server(ServerCommand::Switch(id.clone()));
            leader.wait("líder voltar ao servidor", in_server(id.clone())).await;

            assert!(exchange(&mut leader, member, "de volta").await, "o líder que voltou deveria ser lido");
            assert!(exchange(member, &mut leader, "bem-vindo").await, "o líder que voltou deveria ler");
        })
        .await;
}

/// Repete o envio até a mensagem chegar (a malha do tópico leva um tempo para se formar)
async fn exchange(from: &mut Peer, to: &mut Peer, text: &str) -> bool {
    for _ in 0..30 {
        from.send(CoreCommand::SendMessage(text.into()));
        to.drain(Duration::from_millis(500)).await;
        if to.seen.iter().any(|e| chat_text(e) == Some(text)) {
            return true;
        }
    }
    false
}

/// Só participa (e pode liderar) o grupo cifrado quem está no servidor: Bob ir para o Lobby o tira do
/// grupo, e Alice passa a liderar mesmo que a pubkey de Bob seja menor
#[tokio::test]
async fn test_member_in_lobby_is_not_in_group_nor_leader() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut alice, alice_task) = start("Alice", None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut bob, bob_task) = start("Bob", Some(alice_port));
            tokio::task::spawn_local(bob_task.run());
            alice.wait("Alice identificar Bob", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Bob")).await;
            alice.server(ServerCommand::Create("Guilda".into()));
            let CoreEvent::Server(ServerNotice::Created { id, .. }) =
                alice.wait("servidor criado", |e| matches!(e, CoreEvent::Server(ServerNotice::Created { .. }))).await
            else {
                unreachable!()
            };
            bob.server(ServerCommand::Join(id.clone()));
            bob.wait("Bob receber a chave", |e| matches!(e, CoreEvent::Server(ServerNotice::KeyReceived { .. }))).await;

            bob.send(CoreCommand::Server(ServerCommand::Switch("lobby".into())));
            let mut alone = false;
            for _ in 0..30 {
                alice.seen.clear();
                alice.server(ServerCommand::Info);
                let CoreEvent::Server(ServerNotice::Info(info)) =
                    alice.wait("info", |e| matches!(e, CoreEvent::Server(ServerNotice::Info(_)))).await
                else {
                    unreachable!()
                };
                if info.mls_leader.as_deref() == Some("Alice") {
                    alone = true;
                    break;
                }
                alice.drain(Duration::from_millis(500)).await;
            }
            assert!(alone, "com Bob no Lobby, Alice lidera o grupo do servidor");
        })
        .await;
}

/// O grupo cifrado é por sala: trocar de canal dentro do servidor sai do grupo da sala anterior
/// (Alice passa a liderar #geral) e forma o grupo da nova sala
#[tokio::test]
async fn test_changing_channel_leaves_room_group() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut alice, alice_task) = start("Alice", None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut bob, bob_task) = start("Bob", Some(alice_port));
            tokio::task::spawn_local(bob_task.run());
            alice.wait("Alice identificar Bob", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Bob")).await;
            alice.server(ServerCommand::Create("Guilda".into()));
            let CoreEvent::Server(ServerNotice::Created { id, .. }) =
                alice.wait("servidor criado", |e| matches!(e, CoreEvent::Server(ServerNotice::Created { .. }))).await
            else {
                unreachable!()
            };
            alice.server(ServerCommand::AddChannel { name: "jogos".into(), voice: false });
            alice.wait("canal criado", |e| matches!(e, CoreEvent::Server(ServerNotice::Changed { change: ServerChange::ChannelAdded { .. }, .. }))).await;
            bob.server(ServerCommand::Join(id.clone()));
            bob.wait("Bob receber a chave de #geral", |e| matches!(e, CoreEvent::Server(ServerNotice::KeyReceived { .. }))).await;
            assert!(exchange(&mut alice, &mut bob, "oi no geral").await);

            bob.send(CoreCommand::JoinChannel("jogos".into()));
            bob.wait("Bob entrar em #jogos", |e| matches!(e, CoreEvent::ChannelEntered { channel, .. } if channel == "jogos")).await;
            let mut alice_alone = false;
            for _ in 0..30 {
                alice.seen.clear();
                alice.server(ServerCommand::Info);
                let CoreEvent::Server(ServerNotice::Info(info)) =
                    alice.wait("info", |e| matches!(e, CoreEvent::Server(ServerNotice::Info(_)))).await
                else {
                    unreachable!()
                };
                if info.mls_leader.as_deref() == Some("Alice") {
                    alice_alone = true;
                    break;
                }
                alice.drain(Duration::from_millis(500)).await;
            }
            assert!(alice_alone, "com Bob em #jogos, Alice lidera o grupo de #geral");

            // Alice vai para #jogos também: entra no grupo dessa sala e os dois voltam a conversar
            alice.send(CoreCommand::JoinChannel("jogos".into()));
            assert!(exchange(&mut bob, &mut alice, "oi nos jogos").await, "grupo de #jogos formado com os dois");
        })
        .await;
}

/// Quem sai do servidor renuncia ao passaporte: com o servidor já privado, voltar com
/// `/server join` não devolve o passaporte antigo (#89)
#[tokio::test]
async fn test_leaving_private_server_needs_new_passport_to_return() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut alice, alice_task) = start("Alice", None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut carol, carol_task) = start("Carol", Some(alice_port));
            tokio::task::spawn_local(carol_task.run());
            alice.wait("Alice identificar Carol", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Carol")).await;
            alice.server(ServerCommand::Create("Clube".into()));
            let CoreEvent::Server(ServerNotice::Created { id, .. }) =
                alice.wait("servidor criado", |e| matches!(e, CoreEvent::Server(ServerNotice::Created { .. }))).await
            else {
                unreachable!()
            };
            carol.server(ServerCommand::Join(id.clone()));
            carol.wait("Carol receber passaporte", |e| matches!(e, CoreEvent::Server(ServerNotice::PassportUpdated { .. }))).await;
            carol.wait("Carol receber a chave", |e| matches!(e, CoreEvent::Server(ServerNotice::KeyReceived { .. }))).await;

            alice.server(ServerCommand::Close);
            alice.wait("servidor privado", |e| matches!(e, CoreEvent::Server(ServerNotice::Changed { change: ServerChange::Closed, .. }))).await;
            carol.server(ServerCommand::Leave);
            carol.wait("Carol sair", |e| matches!(e, CoreEvent::Server(ServerNotice::Left { .. }))).await;
            alice
                .wait("Alice ver a renúncia", |e| {
                    matches!(e, CoreEvent::Server(ServerNotice::ModerationReceived { kind: p2p_core::community::ModKind::Renounce { .. }, .. }))
                })
                .await;

            carol.seen.clear();
            carol.server(ServerCommand::Join(id.clone()));
            carol.drain(Duration::from_secs(8)).await;
            assert!(
                !carol.seen.iter().any(|e| matches!(e, CoreEvent::Server(ServerNotice::PassportUpdated { .. }))),
                "servidor privado: quem saiu não recebe o passaporte antigo de volta"
            );
        })
        .await;
}

/// Pedido de acesso a servidor privado (#91): um aviso só, lista de pendentes e emissão pela lista
#[tokio::test]
async fn test_private_server_access_request_is_listed_once() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut alice, alice_task) = start("Alice", None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut carol, carol_task) = start("Carol", Some(alice_port));
            tokio::task::spawn_local(carol_task.run());
            let CoreEvent::PeerIdentified { pubkey: carol_pk, .. } =
                alice.wait("Alice identificar Carol", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Carol")).await
            else {
                unreachable!()
            };
            alice.server(ServerCommand::Create("Clube".into()));
            let CoreEvent::Server(ServerNotice::Created { id, .. }) =
                alice.wait("servidor criado", |e| matches!(e, CoreEvent::Server(ServerNotice::Created { .. }))).await
            else {
                unreachable!()
            };
            alice.server(ServerCommand::Close);
            alice.wait("servidor privado", |e| matches!(e, CoreEvent::Server(ServerNotice::Changed { change: ServerChange::Closed, .. }))).await;

            carol.server(ServerCommand::Join(id.clone()));
            let pk = carol_pk.clone();
            alice
                .wait("Alice ver Carol na lista", move |e| {
                    matches!(e, CoreEvent::Server(ServerNotice::AccessRequests { requests, .. }) if requests.iter().any(|r| r.pubkey == pk))
                })
                .await;
            // Vários ciclos de sincronização depois, continua sendo um aviso só
            alice.drain(Duration::from_secs(12)).await;
            let warnings = alice.seen.iter().filter(|e| matches!(e, CoreEvent::Server(ServerNotice::AccessRequested { .. }))).count();
            assert_eq!(warnings, 1, "um aviso por pessoa, sem repetir a cada ciclo");
            assert!(
                !carol.seen.iter().any(|e| matches!(e, CoreEvent::Server(ServerNotice::PassportUpdated { .. }))),
                "servidor privado: sem passaporte automático"
            );

            // Emissão pela lista (o que o menu "Pedidos de acesso" executa)
            alice.server(ServerCommand::IssuePassport { target: carol_pk.clone(), moderator: false, duration: None });
            carol.wait("Carol receber passaporte", |e| matches!(e, CoreEvent::Server(ServerNotice::PassportUpdated { .. }))).await;
            alice.seen.clear();
            let mut emptied = false;
            for _ in 0..20 {
                alice.server(ServerCommand::Requests);
                if let CoreEvent::Server(ServerNotice::AccessRequests { requests, .. }) =
                    alice.wait("lista", |e| matches!(e, CoreEvent::Server(ServerNotice::AccessRequests { explicit: true, .. }))).await
                {
                    if requests.is_empty() {
                        emptied = true;
                        break;
                    }
                }
                alice.seen.clear();
                alice.drain(Duration::from_millis(500)).await;
            }
            assert!(emptied, "quem recebeu passaporte sai da lista de pendentes");
        })
        .await;
}

/// Ban desfeito: quem continuou inscrito no tópico de pedidos volta à lista sem pedir de novo
#[tokio::test]
async fn test_unbanned_request_is_listed_again() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut alice, alice_task) = start("Alice", None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut carol, carol_task) = start("Carol", Some(alice_port));
            tokio::task::spawn_local(carol_task.run());
            let CoreEvent::PeerIdentified { pubkey: carol_pk, .. } =
                alice.wait("Alice identificar Carol", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Carol")).await
            else {
                unreachable!()
            };
            alice.server(ServerCommand::Create("Clube".into()));
            let CoreEvent::Server(ServerNotice::Created { id, .. }) =
                alice.wait("servidor criado", |e| matches!(e, CoreEvent::Server(ServerNotice::Created { .. }))).await
            else {
                unreachable!()
            };
            alice.server(ServerCommand::Close);
            alice.wait("servidor privado", |e| matches!(e, CoreEvent::Server(ServerNotice::Changed { change: ServerChange::Closed, .. }))).await;

            carol.server(ServerCommand::Join(id.clone()));
            let pk = carol_pk.clone();
            alice
                .wait("Alice ver Carol na lista", move |e| {
                    matches!(e, CoreEvent::Server(ServerNotice::AccessRequests { requests, .. }) if requests.iter().any(|r| r.pubkey == pk))
                })
                .await;

            alice.server(ServerCommand::Ban { target: carol_pk.clone(), duration: None, reason: String::new() });
            alice.wait("ban gravado", |e| matches!(e, CoreEvent::Server(ServerNotice::Moderated { .. }))).await;
            alice
                .wait("ban aplicado", |e| {
                    matches!(e, CoreEvent::Server(ServerNotice::ModerationReceived { kind: p2p_core::community::ModKind::Ban { .. }, .. }))
                })
                .await;
            let pk = carol_pk.clone();
            alice
                .wait("banida sai da lista", move |e| {
                    matches!(e, CoreEvent::Server(ServerNotice::AccessRequests { requests, .. }) if !requests.iter().any(|r| r.pubkey == pk))
                })
                .await;

            alice.seen.clear();
            alice.server(ServerCommand::Unban(carol_pk.clone()));
            let pk = carol_pk.clone();
            alice
                .wait("Carol volta à lista depois do unban", move |e| {
                    matches!(e, CoreEvent::Server(ServerNotice::AccessRequests { requests, .. }) if requests.iter().any(|r| r.pubkey == pk))
                })
                .await;
        })
        .await;
}

/// Moderador que fica online depois vê quem está esperando (#91)
#[tokio::test]
async fn test_moderator_online_later_sees_pending_request() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let alice_ident = UserIdentity::generate_with_nick("Alice");
            let (alice_srv, alice_down) = (temp_dir("pend_a_srv"), temp_dir("pend_a_down"));
            let room = format!("teste-{}", rand_suffix());
            let (mut alice, alice_task) = start_with_dirs("Alice", alice_ident.clone(), alice_srv.clone(), alice_down.clone(), room.clone(), None);
            tokio::task::spawn_local(alice_task.run());
            alice.server(ServerCommand::Create("Clube".into()));
            let CoreEvent::Server(ServerNotice::Created { id, .. }) =
                alice.wait("servidor criado", |e| matches!(e, CoreEvent::Server(ServerNotice::Created { .. }))).await
            else {
                unreachable!()
            };
            alice.server(ServerCommand::Close);
            alice.wait("servidor privado", |e| matches!(e, CoreEvent::Server(ServerNotice::Changed { change: ServerChange::Closed, .. }))).await;
            alice.send(CoreCommand::Shutdown);
            alice.wait("Alice sair", |e| matches!(e, CoreEvent::Stopped)).await;

            // Carol pede acesso sem ninguém online
            let (mut carol, carol_task) = start("Carol", None);
            tokio::task::spawn_local(carol_task.run());
            let CoreEvent::Started { pubkey: carol_pk, .. } = carol.wait("Carol iniciar", |e| matches!(e, CoreEvent::Started { .. })).await else {
                unreachable!()
            };
            carol.server(ServerCommand::Join(id.clone()));
            carol.wait("Carol procurando o servidor", |e| matches!(e, CoreEvent::Server(ServerNotice::Searching { .. }))).await;

            // Alice volta e se conecta a Carol
            let (mut alice, alice_task) = start_with_dirs("Alice", alice_ident, alice_srv, alice_down, room, None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            carol.send(CoreCommand::Dial(format!("/ip4/127.0.0.1/tcp/{}", alice_port)));
            // No Lobby, o aviso chega; no servidor, a lista de pendentes também
            alice.wait("Alice ser avisada do pedido", |e| matches!(e, CoreEvent::Server(ServerNotice::AccessRequested { .. }))).await;
            alice.server(ServerCommand::Switch(id.clone()));
            let pk = carol_pk.clone();
            alice
                .wait("Alice ver Carol na lista", move |e| {
                    matches!(e, CoreEvent::Server(ServerNotice::AccessRequests { requests, .. }) if requests.iter().any(|r| r.pubkey == pk))
                })
                .await;
        })
        .await;
}

/// Pedido de acesso com prova de trabalho (#91): o servidor exige prova e não tem TSA na política,
/// então a semente é carimbada por uma testemunha da rede (a configuração usa a FreeTSA)
#[tokio::test]
async fn test_access_request_with_proof_of_work_via_witness() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let (mut alice, alice_task) = start("Alice", None);
            let alice_port = alice_task.listen_port();
            tokio::task::spawn_local(alice_task.run());
            let (mut carol, carol_task) = start("Carol", Some(alice_port));
            tokio::task::spawn_local(carol_task.run());
            alice.wait("Alice identificar Carol", |e| matches!(e, CoreEvent::PeerIdentified { nick, .. } if nick == "Carol")).await;
            alice.server(ServerCommand::Create("Forte".into()));
            let CoreEvent::Server(ServerNotice::Created { id, .. }) =
                alice.wait("servidor criado", |e| matches!(e, CoreEvent::Server(ServerNotice::Created { .. }))).await
            else {
                unreachable!()
            };
            // Toda alteração precisa de carimbo: com Alice sozinha, só a TSA carimba. A política de
            // prova vem antes, e a remoção da TSA (carimbada por ela mesma) por último.
            alice.server(ServerCommand::AccessPow(8));
            alice.wait("prova exigida", |e| matches!(e, CoreEvent::Server(ServerNotice::Changed { change: ServerChange::AccessPow(8), .. }))).await;
            alice.server(ServerCommand::RemoveTsa("FreeTSA".into()));
            alice.wait("sem TSA", |e| matches!(e, CoreEvent::Server(ServerNotice::Changed { change: ServerChange::TsaRemoved(_), .. }))).await;

            carol.server(ServerCommand::Join(id.clone()));
            carol.wait("Carol calcular a prova", |e| matches!(e, CoreEvent::Server(ServerNotice::AccessProofComputing { .. }))).await;
            carol.wait("Carol receber passaporte", |e| matches!(e, CoreEvent::Server(ServerNotice::PassportUpdated { .. }))).await;
        })
        .await;
}
