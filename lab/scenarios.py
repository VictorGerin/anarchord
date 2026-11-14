"""Cenários do laboratório: testes de ponta a ponta com vários nós, cada um atrás do seu NAT.

Cada cenário recebe um `Lab` vazio, monta a topologia, sobe os contêineres (`await lab.up()`),
dirige os nós com comandos e valida com `wait`.

Os argumentos de cada nó ficam explícitos no `start`. Só os fixos de todo nó (rede isolada,
sem mDNS, porta 4001) vêm de `anarlab.node.BASE_ARGS`. Como o nó acha os outros é sempre do
cenário: `*relay.bootstrap_args` (DHT pelo relay), `*root.bootstrap_args` (DHT pelo nó raiz),
`--tracker` ou `--connect`. Um passo que não acontece no tempo levanta
StepFailed, e o cenário falha com o log completo em lab/results/<cenário>/events.log.
"""

from anarlab import scenario
from anarlab.node import StepFailed

MB = 1024 * 1024


@scenario("Hole punching entre dois NATs cone")
async def hole_punching_cone(lab):
    a, b = lab.nat("a", "cone"), lab.nat("b", "cone")
    alice, bob = lab.peer("alice", a), lab.peer("bob", b)
    lab.relay()
    await lab.up()
    relay = await lab.start_relay()
    await alice.start(*relay.bootstrap_args)
    await bob.start(*relay.bootstrap_args)

    lab.step("os dois detectam o NAT e reservam um endereço no relay")
    await lab.relay_address(alice)
    await lab.relay_address(bob)

    lab.step("Bob conecta em Alice pelo relay")
    await lab.connect(bob, alice)

    lab.step("DCUtR promove a conexão para direta")
    direct = lambda c: not c["relayed"]
    await bob.wait("Network.Connected", where=lambda c: c["peer_id"] == alice.peer_id and direct(c), desc="conexão direta com Alice")

    lab.step("chat funciona pela conexão")
    await lab.join_room("sala", alice, bob)
    alice.send({"SendMessage": "olá pelo buraco no NAT"})
    await bob.wait("ChatMessage", where=lambda m: m["text"] == "olá pelo buraco no NAT")


@scenario("NAT simétrico: tudo passa pelo relay")
async def symmetric_nat_relay(lab):
    a, b = lab.nat("a", "symmetric"), lab.nat("b", "symmetric")
    alice, bob = lab.peer("alice", a), lab.peer("bob", b)
    lab.relay()
    await lab.up()
    relay = await lab.start_relay()
    await alice.start(*relay.bootstrap_args)
    await bob.start(*relay.bootstrap_args)

    lab.step("conexão pelo relay")
    await lab.connect(bob, alice)
    await bob.wait("Network.Connected", where=lambda c: c["peer_id"] == alice.peer_id and c["relayed"], desc="conexão relayada")

    lab.step("chat e arquivo pelo relay")
    await lab.join_room("sala", alice, bob)
    alice.send({"SendMessage": "via relay"})
    await bob.wait("ChatMessage", where=lambda m: m["text"] == "via relay")
    digest = await alice.make_file("/data/relatorio.bin", 2 * MB)
    alice.send({"ShareFile": "/data/relatorio.bin"})
    offer = await bob.wait("File.Offered", where=lambda o: o["name"] == "relatorio.bin")
    bob.send({"GetFile": offer["cid"][8:16]})
    await bob.wait("File.Completed", where=lambda c: c["name"] == "relatorio.bin", timeout=120)
    await lab.same_file({bob: f"{bob.downloads}/relatorio.bin"}, digest)

    lab.step("sem conexão direta (o NAT simétrico impede o hole punching)")
    if bob.find("Network.Connected", where=lambda c: c["peer_id"] == alice.peer_id and not c["relayed"]):
        raise StepFailed("conexão direta não era esperada atrás de NAT simétrico")


@scenario("Chat entre três LANs")
async def chat_three_lans(lab):
    nodes = [lab.peer(name, lab.nat(name)) for name in ("alice", "bob", "carol")]
    alice, bob, carol = nodes
    lab.relay()
    await lab.up()
    relay = await lab.start_relay()
    for node in nodes:
        await node.start(*relay.bootstrap_args)

    lab.step("malha completa: Bob e Carol conectam em Alice, Carol em Bob")
    await lab.connect(bob, alice)
    await lab.connect(carol, alice)
    await lab.connect(carol, bob)
    await lab.join_room("geral3", *nodes)

    lab.step("cada um fala; todos recebem de todos, com o autor certo")
    for node in nodes:
        node.send({"SendMessage": f"oi de {node.nick}"})
    for node in nodes:
        for other in nodes:
            if other is not node:
                await node.wait(
                    "ChatMessage",
                    where=lambda m, o=other: m["text"] == f"oi de {o.nick}" and m["author"] == o.nick and m["author_pubkey"],
                    desc=f"mensagem de {other.nick}",
                )


@scenario("Enxame: quem baixou distribui depois que o publicador sai")
async def file_swarm(lab):
    alice, bob, carol = (lab.peer(n, lab.nat(n)) for n in ("alice", "bob", "carol"))
    lab.relay()
    await lab.up()
    relay = await lab.start_relay()
    for node in (alice, bob, carol):
        await node.start(*relay.bootstrap_args)
    await lab.connect(bob, alice)
    await lab.connect(carol, alice)
    await lab.connect(carol, bob)
    await lab.join_room("arquivos", alice, bob, carol)

    lab.step("Alice compartilha 6 MB; todos veem a oferta")
    digest = await alice.make_file("/data/filme.bin", 6 * MB)
    alice.send({"ShareFile": "/data/filme.bin"})
    offer = await bob.wait("File.Offered", where=lambda o: o["name"] == "filme.bin")
    await carol.wait("File.Offered", where=lambda o: o["name"] == "filme.bin")
    file_id = offer["cid"][8:16]

    lab.step("Bob baixa tudo")
    bob.send({"GetFile": file_id})
    await bob.wait("File.Completed", where=lambda c: c["name"] == "filme.bin", timeout=180)

    lab.step("Alice cai; Carol baixa de Bob")
    await alice.kill()
    carol.send({"GetFile": file_id})
    await carol.wait("File.Completed", where=lambda c: c["name"] == "filme.bin", timeout=180)
    await lab.same_file({bob: f"{bob.downloads}/filme.bin", carol: f"{carol.downloads}/filme.bin"}, digest)


@scenario("Download interrompido retoma depois de reiniciar")
async def resume_download(lab):
    # Banda de conexão doméstica: o download leva tempo suficiente para ser interrompido no meio
    # (netem age na saída da interface: quem envia os dados é a Alice)
    alice, bob = lab.peer("alice", lab.nat("a"), netem="rate 8mbit"), lab.peer("bob", lab.nat("b"))
    lab.relay()
    await lab.up()
    relay = await lab.start_relay()
    await alice.start(*relay.bootstrap_args)
    await bob.start(*relay.bootstrap_args)
    await lab.connect(bob, alice)
    await lab.join_room("arquivos", alice, bob)

    digest = await alice.make_file("/data/grande.bin", 24 * MB)
    alice.send({"ShareFile": "/data/grande.bin"})
    offer = await bob.wait("File.Offered", where=lambda o: o["name"] == "grande.bin")

    lab.step("Bob começa a baixar e cai no meio")
    bob.send({"GetFile": offer["cid"][8:16]})
    await bob.wait("File.Progress", where=lambda p: p["progress"] > 0.05, timeout=120, desc="algum progresso")
    mark_alice = alice.mark()
    await bob.kill()
    # Espera a Alice perceber a queda (a conexão antiga expira por inatividade). Se o Bob voltasse
    # antes, o gossipsub dela não reenviaria as inscrições na conexão nova (limitação do libp2p)
    await alice.wait("PeerLeft", where=lambda p: p["peer_id"] == bob.peer_id, since=mark_alice, timeout=90, desc="perceber a queda de Bob")
    partial = await bob.sh("ls /data/agent/downloads/.parcial/*/ | wc -l")
    if int(partial) == 0:
        raise StepFailed("o download parcial deveria ficar em disco")

    lab.step("Bob volta, reconecta e o download continua de onde parou")
    mark = bob.mark()
    await bob.start(*relay.bootstrap_args)
    await bob.wait("File.Started", where=lambda s: s["name"] == "grande.bin", since=mark, desc="download retomado")
    await lab.connect(bob, alice)
    await bob.wait("File.Completed", where=lambda c: c["name"] == "grande.bin", since=mark, timeout=240)
    await lab.same_file({bob: f"{bob.downloads}/grande.bin"}, digest)


@scenario("Servidor entre NATs: convite, grupo cifrado, moderação e ban")
async def server_lifecycle(lab):
    alice, bob = lab.peer("alice", lab.nat("a")), lab.peer("bob", lab.nat("b"))
    lab.relay()
    await lab.up()
    relay = await lab.start_relay()
    await alice.start(*relay.bootstrap_args)
    await bob.start(*relay.bootstrap_args)
    await lab.connect(bob, alice)
    await lab.join_room("geral", alice, bob)

    lab.step("Alice cria o servidor e convida no Lobby #geral")
    alice.server({"Create": "Guilda"})
    created = await alice.wait("Server.Created")
    server_id = created["id"]
    alice.server({"Invite": {"target": None, "server_id": None}})
    await alice.wait("Server.InviteSent")
    await bob.wait("InviteReceived", where=lambda i: i["server_id"] == server_id)

    lab.step("Bob aceita, recebe a configuração e a chave do grupo cifrado")
    bob.server("Accept")
    in_server = lambda c: isinstance(c["space"], dict) and c["space"].get("Server", {}).get("id") == server_id
    await bob.wait("ChannelEntered", where=in_server, timeout=60)
    await bob.wait("Server.KeyReceived", timeout=60)

    lab.step("chat cifrado do servidor chega")
    for _ in range(20):
        alice.send({"SendMessage": "segredo"})
        try:
            await bob.wait("ChatMessage", where=lambda m: m["text"] == "segredo", timeout=1)
            break
        except StepFailed:
            continue
    await bob.wait("ChatMessage", where=lambda m: m["text"] == "segredo")

    lab.step("rotação de chave MLS (/server rotate-key) pelo líder atual avança a época sem interromper o chat")
    leader = alice if alice.pubkey < bob.pubkey else bob
    follower = bob if leader is alice else alice
    leader.server("RotateKey")
    await leader.wait("Server.KeyRotated", timeout=30)
    leader.send({"SendMessage": "nova epoca mls"})
    await follower.wait("ChatMessage", where=lambda m: m["text"] == "nova epoca mls", timeout=20)

    lab.step("moderação por níveis")
    alice.server({"AddModerator": {"target": "Bob", "permissions": None}})
    await bob.wait("Server.Role", where=lambda r: r["moderator"] is True)
    bob.server({"Ban": {"target": "Alice", "duration": None, "reason": ""}})
    # Alice é a raiz/criadora do servidor: a cadeia recusa com Rejected(ProtectedTarget)
    # ("o alvo é protegido (ou é a chave do servidor)"), antes da regra de ancestralidade.
    await bob.wait("Error.Server", where=lambda m: "protegido" in m)

    lab.step("Alice bane Bob: ele sai do grupo cifrado e não lê mais nada")
    alice.server({"Ban": {"target": "Bob", "duration": 3600, "reason": "teste"}})
    await bob.wait("Server.BanStatus", where=lambda b: b["banned"])
    await bob.wait("Server.RemovedFromGroup", timeout=60)
    mark = bob.mark()
    for _ in range(3):
        alice.send({"SendMessage": "depois do ban"})
    await bob.expect_none("ChatMessage", where=lambda m: m["text"] == "depois do ban", since=mark, during=4)


@scenario("Voz e tela entre NATs")
async def voice_and_screen(lab):
    alice, bob = lab.peer("alice", lab.nat("a")), lab.peer("bob", lab.nat("b"))
    lab.relay()
    await lab.up()
    relay = await lab.start_relay()
    await alice.start(*relay.bootstrap_args, "--synth-audio", "--synth-video", "--auto-voice", "sala")
    await bob.start(*relay.bootstrap_args, "--auto-voice", "sala")
    await lab.connect(bob, alice)

    lab.step("Bob ouve Alice na sala de voz")
    await bob.wait("Voice.Speaking", where=lambda s: s["nick"] == "Alice" and s["speaking"], desc="Alice falando")

    lab.step("Bob vê a tela anunciada e assiste")
    await bob.wait("Screen.StreamAvailable", where=lambda s: s["nick"] == "Alice")
    bob.send({"WatchScreen": {"query": "Alice"}})
    await bob.wait("Screen.Watching")
    frames = await bob.wait("Screen.FrameReceived", where=lambda f: f["seq"] >= 120 and f["bytes"] > 0, timeout=60)
    if (frames["width"], frames["height"]) != (640, 360):
        raise StepFailed(f"resolução inesperada: {frames}")


@scenario("Rede ruim: perda e latência no enxame e no chat")
async def lossy_network(lab):
    alice = lab.peer("alice", lab.nat("a"), netem="delay 60ms 20ms loss 3%")
    bob = lab.peer("bob", lab.nat("b"), netem="delay 40ms loss 3%")
    lab.relay()
    await lab.up()
    relay = await lab.start_relay()
    await alice.start(*relay.bootstrap_args)
    await bob.start(*relay.bootstrap_args)
    await lab.connect(bob, alice, timeout=90)
    await lab.join_room("sala", alice, bob, timeout=90)

    lab.step("chat chega mesmo com perda")
    for i in range(5):
        alice.send({"SendMessage": f"msg {i}"})
    for i in range(5):
        await bob.wait("ChatMessage", where=lambda m, i=i: m["text"] == f"msg {i}", timeout=60)

    lab.step("arquivo de 3 MB chega íntegro")
    digest = await alice.make_file("/data/ruim.bin", 3 * MB)
    alice.send({"ShareFile": "/data/ruim.bin"})
    offer = await bob.wait("File.Offered", where=lambda o: o["name"] == "ruim.bin", timeout=60)
    bob.send({"GetFile": offer["cid"][8:16]})
    await bob.wait("File.Completed", where=lambda c: c["name"] == "ruim.bin", timeout=240)
    await lab.same_file({bob: f"{bob.downloads}/ruim.bin"}, digest)


# ---------------------------------------------------------------------- bootstrap e --connect
# Tudo em rede isolada: nenhum nó conhece os bootstraps do IPFS nem os trackers públicos, e o
# mDNS fica desligado. Se os pares se acham, foi pelo mecanismo que o cenário está testando.


@scenario("--connect direto entre dois nós públicos")
async def connect_direct(lab):
    alice, bob = lab.public("alice"), lab.public("bob")
    await lab.up()
    await alice.start("--no-discovery")
    await bob.start("--no-discovery", "--connect", alice.address)
    await bob.wait("PeerIdentified", where=lambda p: p["nick"] == "Alice", desc="identificar Alice")
    await alice.wait("PeerIdentified", where=lambda p: p["nick"] == "Bob", desc="identificar Bob")
    await bob.wait("Network.Connected", where=lambda c: c["peer_id"] == alice.peer_id and not c["relayed"])


@scenario("--connect de dentro de um NAT para um nó público")
async def connect_from_behind_nat(lab):
    alice = lab.public("alice")
    bob = lab.peer("bob", lab.nat("b"))
    await lab.up()
    await alice.start("--no-discovery")
    await bob.start("--no-discovery", "--connect", alice.address)
    await alice.wait("PeerIdentified", where=lambda p: p["nick"] == "Bob", desc="Alice ver Bob (conexão de saída pelo NAT)")

    lab.step("chat pela conexão que Bob abriu")
    await lab.join_room("sala", alice, bob)
    bob.send({"SendMessage": "saindo pelo NAT"})
    await alice.wait("ChatMessage", where=lambda m: m["text"] == "saindo pelo NAT")


@scenario("Bootstrap só pelo tracker BitTorrent do laboratório")
async def tracker_bootstrap(lab):
    tracker = lab.tracker()
    alice, bob = lab.public("alice"), lab.public("bob")
    await lab.up()
    await alice.start("--tracker", tracker)
    await bob.start("--tracker", tracker)

    lab.step("o tracker apresenta um ao outro")
    await bob.wait("Network.TrackerPeer", where=lambda p: p.startswith(alice.ip + ":"), desc="Alice no tracker")
    await bob.wait("PeerIdentified", where=lambda p: p["nick"] == "Alice", desc="identificar Alice")
    await alice.wait("PeerIdentified", where=lambda p: p["nick"] == "Bob", desc="identificar Bob")
    if alice.find("Network.DhtBootstrap", where=lambda b: b["nodes"] > 0):
        raise StepFailed("sem --bootstrap, a DHT não deveria ter nós de bootstrap")


@scenario("Bootstrap só pela DHT de um nó raiz")
async def dht_root_bootstrap(lab):
    alice, bob = lab.public("alice"), lab.public("bob")
    lab.root()
    await lab.up()
    root = await lab.start_root()
    await alice.start(*root.bootstrap_args)
    await bob.start(*root.bootstrap_args)

    lab.step("os dois entram na DHT pelo nó raiz e se acham pelo registro de provedor")
    await alice.wait("Network.DhtBootstrap", where=lambda b: b["nodes"] >= 1)
    await bob.wait("PeerIdentified", where=lambda p: p["nick"] == "Alice", timeout=90, desc="achar Alice pela DHT")
    await alice.wait("PeerIdentified", where=lambda p: p["nick"] == "Bob", timeout=90, desc="achar Bob pela DHT")
    if bob.find("Network.TrackerPeer"):
        raise StepFailed("nenhum tracker foi configurado")
    await lab.join_room("sala", alice, bob)
    alice.send({"SendMessage": "achei você pela DHT"})
    await bob.wait("ChatMessage", where=lambda m: m["text"] == "achei você pela DHT")


@scenario("Troca de pares: quem conhece apresenta, inclusive atrás de NAT")
async def peer_exchange(lab):
    alice = lab.public("alice")
    bob, carol = lab.peer("bob", lab.nat("b")), lab.peer("carol", lab.nat("c"))
    await lab.up()
    # Sem DHT, tracker nem mDNS: Bob e Carol só conhecem Alice, que é relay público
    await alice.start("--no-discovery", "--relay-server")
    await bob.start("--no-discovery", "--connect", alice.address)
    await carol.start("--no-discovery", "--connect", alice.address)

    lab.step("Bob e Carol reservam um circuito em Alice")
    await lab.relay_address(bob)
    await lab.relay_address(carol)

    lab.step("Alice conta a cada um como alcançar o outro (pelo circuito); eles se conectam")
    await bob.wait("PeerIdentified", where=lambda p: p["nick"] == "Carol", timeout=90, desc="Bob achar Carol pela troca de pares")
    await carol.wait("PeerIdentified", where=lambda p: p["nick"] == "Bob", timeout=90, desc="Carol achar Bob pela troca de pares")
    if not (bob.find("Network.PeerExchange") or carol.find("Network.PeerExchange")):
        raise StepFailed("a conexão deveria ter vindo da troca de pares")
    await lab.join_room("sala", alice, bob, carol)
    bob.send({"SendMessage": "achei você pela Alice"})
    await carol.wait("ChatMessage", where=lambda m: m["text"] == "achei você pela Alice")


# ---------------------------------------------------------------------- DMs 1:1 E2EE, Mailbox Offline, Firewall Assimétrico e Sniffer


@scenario("DMs 1:1 E2EE, Mailbox Offline via Guardião (sem duplicata após restart) e Sniffer")
async def dm_mailbox_and_sniffer(lab):
    alice = lab.public("alice")
    bob = lab.public("bob")
    carol = lab.public("carol")
    await lab.up()

    await alice.start("--no-discovery")
    await bob.start("--no-discovery", "--connect", alice.address)
    await carol.start("--no-discovery", "--connect", alice.address)

    await alice.wait("PeerIdentified", where=lambda p: p["nick"] == "Bob", desc="Alice ver Bob")
    await alice.wait("PeerIdentified", where=lambda p: p["nick"] == "Carol", desc="Alice ver Carol")

    lab.step("Alice ↔ Bob são amigos; Alice ↔ Carol são amigos; Bob e Carol NÃO são amigos")
    alice.send({"AddFriend": {"pubkey": bob.pubkey, "alias": "Bob"}})
    bob.send({"AddFriend": {"pubkey": alice.pubkey, "alias": "Alice"}})
    alice.send({"AddFriend": {"pubkey": carol.pubkey, "alias": "Carol"}})
    carol.send({"AddFriend": {"pubkey": alice.pubkey, "alias": "Alice"}})

    await alice.wait("FriendUpdated", where=lambda f: f["pubkey"] == carol.pubkey and not f["removed"])
    await carol.wait("FriendUpdated", where=lambda f: f["pubkey"] == alice.pubkey and not f["removed"])

    lab.step("DM 1:1 E2EE online entre Alice e Carol + validação crua no Sniffer")
    secret_online = "segredo_online_e2ee_alice_para_carol_778899"
    since_carol = carol.mark()
    alice.send({"SendDm": {"target": "Carol", "text": secret_online, "suggested_ttl": None}})
    await carol.wait(
        "DirectMessage",
        where=lambda m: m["author"] == "Alice" and m["text"] == secret_online and not m["offline_delivery"],
        since=since_carol,
        desc="Carol receber DM online de Alice",
    )

    # Valida no sniffer de pacotes que houve KeyOffer X25519 e DirectMessage.Message cifrada e assinada
    key_offer_pkt = await alice.wait_packet(
        kind="DirectMessage.KeyOffer",
        direction="TX",
        where=lambda p: p["crypto"].get("recipient_pubkey") == carol.pubkey,
        desc="KeyOffer X25519 de Alice para Carol",
    )
    if key_offer_pkt["crypto"].get("signature_valid") is not True:
        raise StepFailed(f"Assinatura Ed25519 inválida no KeyOffer: {key_offer_pkt}")
    if len(key_offer_pkt["crypto"].get("ephemeral_x25519_pubkey") or "") != 64:
        raise StepFailed("Chave efêmera X25519 deveria ter 32 bytes (64 hex chars)")

    dm_pkt = await carol.wait_packet(
        kind="DirectMessage.Message",
        direction="RX",
        where=lambda p: p["crypto"].get("sender_pubkey") == alice.pubkey,
        desc="Pacote bruto DirectMessage.Message recebido por Carol",
    )
    if dm_pkt["crypto"].get("signature_valid") is not True:
        raise StepFailed(f"Assinatura Ed25519 externa inválida no DirectMessage: {dm_pkt}")
    secret_online_hex = secret_online.encode("utf-8").hex()
    if secret_online_hex in dm_pkt["raw_hex"] or secret_online in dm_pkt["raw_hex"]:
        raise StepFailed("VAZAMENTO DE TEXTO CLARO: o segredo da DM apareceu no quadro bruto do fio!")

    lab.step("Carol e Bob ficam offline; Alice envia DM para Carol quando NINGUÉM está online")
    await carol.stop()
    await bob.stop()
    await alice.wait("PeerLeft", where=lambda p: p["nick"] == "Carol", desc="Alice notar saída de Carol")
    await alice.wait("PeerLeft", where=lambda p: p["nick"] == "Bob", desc="Alice notar saída de Bob")

    secret_offline = "mensagem_offline_exclusiva_alice_carol_112233"
    alice.send({"SendDm": {"target": "Carol", "text": secret_offline, "suggested_ttl": 7200}})
    queued = await alice.wait("MailboxQueued", where=lambda q: q["recipient_pubkey"] == carol.pubkey)
    envelope_id = queued["envelope_id"]

    lab.step("Bob (amigo guardião de Alice) fica online DEPOIS do envio e assume a guarda do envelope")
    since_bob = bob.mark()
    await bob.start("--no-discovery", "--connect", alice.address)
    await bob.wait(
        "MailboxStoredForFriend",
        where=lambda s: s["envelope_id"] == envelope_id,
        since=since_bob,
        desc="Bob virar guardião do envelope offline que Alice enviou quando ninguém estava online",
    )

    # Valida no sniffer de Bob que Bob recebeu o Mailbox.Store assinado por Alice, mas sem vazamento do texto claro
    store_pkt = await bob.wait_packet(
        kind="Mailbox.Store",
        direction="RX",
        where=lambda p: p["crypto"].get("envelope_id") == envelope_id,
        desc="Pacote bruto Mailbox.Store no sniffer de Bob",
    )
    if store_pkt["crypto"].get("signature_valid") is not True:
        raise StepFailed("Assinatura externa de Mailbox.Store inválida no sniffer de Bob")
    secret_offline_hex = secret_offline.encode("utf-8").hex()
    if secret_offline_hex in store_pkt["raw_hex"]:
        raise StepFailed("VAZAMENTO: o guardião Bob conseguiu ver o texto claro no pacote Mailbox.Store!")

    lab.step("Alice fica offline; Carol volta online conectando APENAS a Bob (que não é amigo de Carol)")
    await alice.stop()
    await carol.start("--no-discovery", "--connect", bob.address)
    await carol.wait(
        "DirectMessage",
        where=lambda m: m["author"] == "Alice" and m["text"] == secret_offline and m["offline_delivery"],
        desc="Carol receber DM offline de Alice entregue pelo guardião Bob",
    )

    # Confere no sniffer que Bob enviou Mailbox.Deliver e Carol emitiu Mailbox.Ack assinado
    await bob.wait_packet(
        kind="Mailbox.Deliver",
        direction="TX",
        where=lambda p: p["crypto"].get("envelope_id") == envelope_id and p["crypto"].get("signature_valid") is True,
        desc="Mailbox.Deliver enviado por Bob",
    )
    await carol.wait_packet(
        kind="Mailbox.Ack",
        direction="TX",
        where=lambda p: p["crypto"].get("envelope_id") == envelope_id and p["crypto"].get("signature_valid") is True,
        desc="Mailbox.Ack assinado por Carol",
    )

    lab.step("Carol fecha e reabre o programa, Bob fica offline e Alice volta online: Carol NÃO recebe duplicata")
    await carol.stop()
    await bob.stop()
    await alice.start("--no-discovery")
    await carol.start("--no-discovery", "--connect", alice.address)
    await carol.wait("PeerIdentified", where=lambda p: p["nick"] == "Alice", desc="Carol reconectar com Alice")
    since_reconnect = carol.mark()
    await carol.expect_none(
        "DirectMessage",
        where=lambda m: m["text"] == secret_offline,
        during=5,
        since=since_reconnect,
        desc="mensagem offline duplicada após reiniciar Carol e reconectar à Alice",
    )


@scenario("Firewall Assimétrico de DMs: Amigos vs Desconhecidos, Bloqueio Progressivo e Aviso de Cortesia")
async def dm_asymmetric_firewall(lab):
    alice = lab.public("alice")
    carol = lab.public("carol")
    await lab.up()

    await carol.start("--no-discovery")
    await alice.start("--no-discovery", "--connect", carol.address)
    await carol.wait("PeerIdentified", where=lambda p: p["nick"] == "Alice", desc="Carol ver Alice")
    await alice.wait("PeerIdentified", where=lambda p: p["nick"] == "Carol", desc="Alice ver Carol")
    # Barreira de mesh: só envia DMs depois que os dois se veem em #geral, senão a
    # primeira mensagem se perde antes do mesh Gossipsub se formar.
    await lab.join_room("geral", alice, carol)

    lab.step("Assimetria: Alice adiciona Carol como amiga, mas Carol NÃO tem Alice na lista de amigos")
    alice.send({"AddFriend": {"pubkey": carol.pubkey, "alias": "Carol"}})
    await alice.wait("FriendUpdated", where=lambda f: f["pubkey"] == carol.pubkey and not f["removed"])

    lab.step("Alice envia 4 DMs seguidas para Carol (limite de desconhecidos de Carol = 3 msg/min)")
    since_carol = carol.mark()
    since_alice = alice.mark()
    for i in range(1, 5):
        alice.send({"SendDm": {"target": "Carol", "text": f"oi carol {i}", "suggested_ttl": None}})

    # O Gossipsub entrega a rajada em qualquer ordem (no run 43598295395 chegaram 4, 3 e 2),
    # ent�o exigimos 3 DMs distintas das 4 enviadas, sem presumir quais textos passam primeiro.
    recebidas = set()
    for n in range(1, 4):
        msg = await carol.wait(
            "DirectMessage",
            where=lambda m: m["author"] == "Alice"
            and m["text"].startswith("oi carol ")
            and m["text"] not in recebidas,
            since=since_carol,
            desc=f"Carol receber a {n}� das 3 DMs de desconhecida antes do limite",
        )
        recebidas.add(msg["text"])
    if len(recebidas) != 3:
        raise StepFailed(f"Carol deveria receber 3 DMs de Alice antes do limite: {sorted(recebidas)}")

    blocked = await carol.wait(
        "PeerBlocked",
        where=lambda b: b["pubkey"] == alice.pubkey and not b["is_friend"] and b["offense_level"] == 1,
        since=since_carol,
        desc="Firewall de Carol bloquear Alice na 4ª mensagem",
    )
    if blocked["duration_secs"] != 60 or not blocked["courtesy_sent"]:
        raise StepFailed(f"Bloqueio de nível 1 deveria ser de 60s com aviso de cortesia: {blocked}")

    lab.step("Alice recebe o aviso automático de cortesia (E2EE) do Firewall de Carol")
    await alice.wait(
        "DirectMessage",
        where=lambda m: m["author"] == "Carol" and "Aviso Automático do Firewall de Carol" in m["text"],
        since=since_alice,
        desc="Alice receber aviso de cortesia E2EE de Carol",
    )

    lab.step("Enquanto bloqueada, novas mensagens de Alice são descartadas silenciosamente por Carol")
    since_blocked = carol.mark()
    alice.send({"SendDm": {"target": "Carol", "text": "tentando furar bloqueio", "suggested_ttl": None}})
    await carol.expect_none(
        "DirectMessage",
        where=lambda m: m["text"] == "tentando furar bloqueio",
        during=3,
        since=since_blocked,
        desc="DM de par bloqueado",
    )

    lab.step("Carol adiciona Alice como amiga: Alice é desbloqueada na hora e passa a ter cota de amiga (30 msg/min)")
    carol.send({"AddFriend": {"pubkey": alice.pubkey, "alias": "Alice"}})
    await carol.wait("FriendUpdated", where=lambda f: f["pubkey"] == alice.pubkey and not f["removed"])

    since_friend = carol.mark()
    for i in range(1, 6):
        alice.send({"SendDm": {"target": "Carol", "text": f"agora somos amigas {i}", "suggested_ttl": None}})
    for i in range(1, 6):
        await carol.wait(
            "DirectMessage",
            where=lambda m, i=i: m["author"] == "Alice" and m["text"] == f"agora somos amigas {i}",
            since=since_friend,
            desc=f"Carol receber DM {i}/5 da amiga Alice sem bloqueio",
        )


@scenario("NodeFirewall no Lobby: Flood de Chat Bloqueado sem Degradar Nós Honestos")
async def lobby_firewall_flood(lab):
    alice = lab.public("alice")
    bob = lab.public("bob")
    mallory = lab.public("mallory")
    await lab.up()

    await bob.start("--no-discovery")
    await alice.start("--no-discovery", "--connect", bob.address)
    await mallory.start("--no-discovery", "--connect", bob.address)

    await bob.wait("PeerIdentified", where=lambda p: p["nick"] == "Alice", desc="Bob ver Alice")
    await bob.wait("PeerIdentified", where=lambda p: p["nick"] == "Mallory", desc="Bob ver Mallory")
    # Barreira de mesh: o flood só começa quando os três se veem em #geral; antes
    # disso o Gossipsub ainda não tem mesh e nenhuma mensagem chega a Bob.
    await lab.join_room("geral", alice, bob, mallory)

    lab.step("Bob configura firewall.stranger_chat_per_10s = 4")
    bob.send({"SetConfig": {"key": "firewall.stranger_chat_per_10s", "value": "4"}})
    await bob.wait("ConfigUpdated", where=lambda c: c["key"] == "firewall.stranger_chat_per_10s")

    lab.step("Mallory inunda o Lobby com 7 mensagens seguidas; Bob aceita 4 e bloqueia Mallory na 5ª")
    since_flood = bob.mark()
    for i in range(1, 8):
        mallory.send({"SendMessage": f"spam lobby {i}"})

    # O Gossipsub entrega a rajada em qualquer ordem (no run 43587786146 chegaram 7, 6, 5 e 4),
    # então exigimos 4 mensagens distintas de Mallory, sem presumir a ordem dos textos.
    recebidas = set()
    for n in range(1, 5):
        msg = await bob.wait(
            "ChatMessage",
            where=lambda m: m["author"] == "Mallory"
            and m["text"].startswith("spam lobby ")
            and m["text"] not in recebidas,
            since=since_flood,
            desc=f"Bob receber a {n}ª das 4 mensagens de Mallory antes do limite",
        )
        recebidas.add(msg["text"])
    if len(recebidas) != 4:
        raise StepFailed(f"Bob deveria receber 4 mensagens de Mallory antes do limite: {sorted(recebidas)}")

    blocked = await bob.wait(
        "PeerBlocked",
        where=lambda b: b["pubkey"] == mallory.pubkey and b["offense_level"] == 1,
        since=since_flood,
        desc="NodeFirewall de Bob bloquear Mallory no flood de chat",
    )
    if blocked["duration_secs"] != 60:
        raise StepFailed(f"Duração do bloqueio nível 1 deveria ser 60s: {blocked}")

    lab.step("Enquanto Mallory está bloqueado, Alice conversa normalmente com Bob no Lobby sem degradação")
    since_after_block = bob.mark()
    mallory.send({"SendMessage": "spam bloqueado invisivel"})
    alice.send({"SendMessage": "mensagem honesta da Alice"})

    await bob.wait(
        "ChatMessage",
        where=lambda m: m["author"] == "Alice" and m["text"] == "mensagem honesta da Alice",
        since=since_after_block,
        desc="Bob receber mensagem de Alice normalmente durante ataque de Mallory",
    )
    await bob.expect_none(
        "ChatMessage",
        where=lambda m: m["text"] == "spam bloqueado invisivel",
        during=2,
        since=since_after_block,
        desc="mensagem de Mallory bloqueado",
    )

    lab.step("Bob desbloqueia Mallory manualmente (/firewall unblock) e Mallory volta a falar")
    bob.send({"UnblockPeer": {"target": "Mallory"}})
    await bob.wait("PeerUnblocked", where=lambda u: u["pubkey"] == mallory.pubkey, desc="Mallory desbloqueado")

    since_unblocked = bob.mark()
    mallory.send({"SendMessage": "desculpa pessoal"})
    await bob.wait(
        "ChatMessage",
        where=lambda m: m["author"] == "Mallory" and m["text"] == "desculpa pessoal",
        since=since_unblocked,
        desc="Bob voltar a receber mensagem de Mallory após desbloqueio",
    )


