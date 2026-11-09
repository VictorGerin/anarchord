//! `anarchord-agent`: um nó Anarchord sem interface, controlado por JSON.
//!
//! Protocolo (uma mensagem por linha, UTF-8):
//! - **stdin**: um [`CoreCommand`] em JSON por linha (ex.: `{"JoinChannel":"geral"}`,
//!   `{"Server":{"Create":"Guilda"}}`, `"ListPeers"`). Fim do stdin encerra o nó.
//! - **stdout**: um [`CoreEvent`] em JSON por linha, na ordem em que o core emitiu.
//! - **stderr**: logs de diagnóstico (tracing) e erros de comando ilegível.
//!
//! É o que o laboratório de testes (`lab/`) usa para dirigir cada nó, e serve para bots.

use clap::Parser;
use p2p_core::runtime::{Core, CoreCommand, CoreConfig, CoreEvent};
use p2p_core::UserIdentity;
use std::io::Write;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Parser, Debug)]
#[command(name = "anarchord-agent", version, about = "Nó Anarchord controlado por JSON no stdin/stdout")]
struct Args {
    /// Apelido
    #[arg(long, default_value = "agent")]
    nick: String,

    /// Pasta de dados: identidade, servidores, downloads
    #[arg(long, default_value = "agent-data")]
    data_dir: PathBuf,

    /// Porta TCP + QUIC (0 = escolhe uma livre)
    #[arg(long, default_value_t = 0)]
    port: u16,

    /// Canal de texto inicial no Lobby
    #[arg(long, default_value = "geral")]
    channel: String,

    /// Bootstrap da DHT (multiaddr com /p2p/<id>), pode repetir
    #[arg(long)]
    bootstrap: Vec<String>,

    /// Tracker BitTorrent UDP (host:porta), pode repetir
    #[arg(long)]
    tracker: Vec<String>,

    /// Disca este endereço ao iniciar
    #[arg(long)]
    connect: Option<String>,

    /// Rede isolada: não usa os nós de bootstrap do IPFS nem os trackers públicos embutidos,
    /// só o que vier em --bootstrap, --tracker e --connect
    #[arg(long)]
    isolated: bool,

    /// Desliga a descoberta automática (DHT e trackers)
    #[arg(long)]
    no_discovery: bool,

    /// Desliga a descoberta na rede local (mDNS)
    #[arg(long)]
    no_mdns: bool,

    /// Não pede ao roteador (UPnP) que encaminhe a porta de escuta
    #[arg(long)]
    no_upnp: bool,

    /// Atende como servidor de relay (nó público)
    #[arg(long)]
    relay_server: bool,

    /// Rede de laboratório: IPs privados valem como públicos e o AutoNAT é rápido
    #[arg(long)]
    lab: bool,

    /// Abre microfone e alto-falante do sistema
    #[arg(long)]
    audio: bool,

    /// Melodia sintética na sala de voz
    #[arg(long)]
    synth_audio: bool,

    /// Vídeo sintético no Lobby
    #[arg(long)]
    synth_video: bool,

    /// Entra nesta sala de voz do Lobby ao iniciar
    #[arg(long)]
    auto_voice: Option<String>,

    /// Baixa todo arquivo oferecido e assiste toda tela anunciada
    #[arg(long)]
    auto_accept: bool,

    /// Grava pacotes brutos de aplicação (sniffer JSONL) no caminho indicado
    #[arg(long)]
    sniff_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    // Logs vão para o stderr: o stdout é só do protocolo
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into());
    tracing_subscriber::fmt().with_writer(std::io::stderr).with_env_filter(filter).init();

    std::fs::create_dir_all(&args.data_dir)?;
    let identity_file = args.data_dir.join("identity.json");
    let mut identity = UserIdentity::load_or_create(&identity_file)?;
    if identity.profile.display_name != args.nick {
        identity.set_nick(&args.nick);
        identity.save_to(&identity_file)?;
    }

    let bootstrap = args.bootstrap.iter().map(|a| a.parse()).collect::<Result<Vec<_>, _>>()?;
    let config = CoreConfig {
        identity_path: Some(identity_file.clone()),
        config_path: Some(args.data_dir.join("config.json")),
        identity,
        port: args.port,
        listen_ip: None,
        servers_dir: args.data_dir.join("servers"),
        download_dir: args.data_dir.join("downloads"),
        channel: args.channel,
        connect: args.connect.as_deref().map(str::parse).transpose()?,
        auto_voice: args.auto_voice,
        audio: args.audio,
        synth_audio: args.synth_audio,
        synth_video: args.synth_video,
        discovery: !args.no_discovery,
        test_mode: args.auto_accept,
        bootstrap,
        trackers: args.tracker,
        public_defaults: !args.isolated,
        mdns: !args.no_mdns,
        upnp: !args.no_upnp,
        relay_server: args.relay_server,
        lab: args.lab,
        sniff_file: args.sniff_file.or_else(|| Some(args.data_dir.join("packets.jsonl"))),
        protocol_capabilities: None,
    };
    let (core, task) = Core::start(config)?;
    let (commands, mut events) = core.split();

    // Eventos -> stdout, uma linha JSON cada (flush a cada linha: quem lê espera em tempo real)
    tokio::spawn(async move {
        let mut stdout = std::io::stdout();
        while let Some(event) = events.recv().await {
            let stopped = matches!(event, CoreEvent::Stopped);
            match serde_json::to_string(&event) {
                Ok(line) => {
                    let _ = writeln!(stdout, "{}", line);
                    let _ = stdout.flush();
                }
                Err(e) => eprintln!("evento não serializável: {}", e),
            }
            if stopped {
                break;
            }
        }
    });

    // stdin -> comandos
    let to_core = commands.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) if line.trim().is_empty() => continue,
                Ok(Some(line)) => match serde_json::from_str::<CoreCommand>(&line) {
                    Ok(command) => {
                        let _ = to_core.send(command);
                    }
                    Err(e) => eprintln!("comando ilegível ({}): {}", e, line),
                },
                // Fim do stdin (o controlador saiu): encerra o nó
                Ok(None) | Err(_) => {
                    let _ = to_core.send(CoreCommand::Shutdown);
                    break;
                }
            }
        }
    });

    task.run().await;
    // Dá tempo de o último evento (Stopped) sair
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    Ok(())
}
