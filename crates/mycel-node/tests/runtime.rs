//! Runtime end-to-end: real storage, real QUIC, the full messaging API.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use mycel_node::api::{Delivery, Event, NetworkMode};
use mycel_node::{Runtime, RuntimeOptions};

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("mycel-rt-{name}-{}", mycel_node::crypto::random_u64()))
}

async fn open(dir: &std::path::Path, name: &str, port: u16, keeper: bool) -> Arc<Runtime> {
    Runtime::open_with(RuntimeOptions {
        data_dir: dir.to_path_buf(),
        mode: NetworkMode::Local,
        name: Some(name.into()),
        keeper,
        port,
    })
    .await
    .unwrap()
}

fn connect_all(rts: &[&Arc<Runtime>]) {
    for a in rts {
        for b in rts {
            if a.profile().id != b.profile().id {
                a.node().add_peer_addr(b.node().addr());
            }
        }
    }
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..300 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread")]
async fn messaging_end_to_end() {
    let (da, db) = (tmp("alice"), tmp("bob"));
    let (pa, pb) = (free_port(), free_port());
    let alice = open(&da, "Alice", pa, false).await;
    let mut bob = open(&db, "Bob", pb, false).await;
    connect_all(&[&alice, &bob]);
    let mut bob_events = bob.subscribe();

    // exchange contact codes
    let bob_contact = alice.add_contact(bob.profile().contact_code).unwrap();
    assert_eq!(bob_contact.name, "Bob");
    assert!(alice.add_contact("garbage".into()).is_err());

    // DM
    let conv = alice.create_conversation(None, vec![bob_contact.id.clone()]).unwrap();
    assert!(conv.direct);
    assert_eq!(conv.title, "Bob");
    let m1 = alice.send_message(conv.id.clone(), "hi bob 👋".into(), None, vec![]).await.unwrap();
    assert!(m1.is_mine);

    eventually("bob gets the conversation", || bob.conversations().len() == 1).await;
    let added = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(Event::ConversationAdded { conversation }) = bob_events.recv().await {
                return conversation;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(added, conv.id);
    eventually("bob sees message", || {
        bob.messages(conv.id.clone(), None, None).unwrap().iter().any(|m| m.body == "hi bob 👋")
    })
    .await;
    // Alice isn't Bob's contact: it arrives as a message request.
    let bconv = bob.conversation(conv.id.clone()).unwrap();
    assert!(bconv.request);
    assert_eq!(bconv.invited_by.as_deref(), Some(alice.profile().id.as_str()));
    assert!(bob.contacts().is_empty(), "strangers are not auto-added");
    assert!(bob.send_message(conv.id.clone(), "x".into(), None, vec![]).await.is_err());
    let bconv = bob.accept_request(conv.id.clone()).unwrap();
    assert!(!bconv.request);
    assert_eq!(bconv.title, "Alice", "bob learns alice's name via Profile");
    assert_eq!(bconv.unread, 1);
    assert!(bob.contacts().iter().any(|c| c.name == "Alice"), "accepted → contact");

    // delivery → read
    eventually("delivered", || {
        alice.messages(conv.id.clone(), None, None).unwrap().last().unwrap().delivery >= Delivery::Delivered
    })
    .await;
    bob.mark_read(conv.id.clone()).unwrap();
    assert_eq!(bob.conversation(conv.id.clone()).unwrap().unread, 0);
    eventually("read", || {
        let msgs = alice.messages(conv.id.clone(), None, None).unwrap();
        msgs.iter().find(|m| m.id == m1.id).unwrap().delivery == Delivery::Read
    })
    .await;

    // reply, react, edit, delete
    let r = bob
        .send_message(conv.id.clone(), "hey alice".into(), Some(m1.id.clone()), vec![])
        .await
        .unwrap();
    assert_eq!(r.reply_to.as_deref(), Some(m1.id.as_str()));
    bob.toggle_reaction(conv.id.clone(), m1.id.clone(), "❤️".into()).unwrap();
    alice.edit_message(conv.id.clone(), m1.id.clone(), "hi bob! (edited)".into()).unwrap();
    assert!(bob.edit_message(conv.id.clone(), m1.id.clone(), "nope".into()).is_err());
    eventually("alice sees reply + reaction; bob sees edit", || {
        let am = alice.messages(conv.id.clone(), None, None).unwrap();
        let bm = bob.messages(conv.id.clone(), None, None).unwrap();
        am.len() == 2
            && am[0].reactions.iter().any(|r| r.emoji == "❤️")
            && bm[0].body == "hi bob! (edited)"
            && bm[0].edited
    })
    .await;
    bob.delete_message(conv.id.clone(), r.id.clone()).unwrap();
    eventually("delete propagates", || {
        alice.messages(conv.id.clone(), None, None).unwrap()[1].deleted
    })
    .await;

    // attachment
    let file = tmp("photo").with_extension("png");
    let content: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 256) as u8).collect();
    std::fs::write(&file, &content).unwrap();
    let sent = alice
        .send_message(conv.id.clone(), "pic".into(), None, vec![file.to_string_lossy().into()])
        .await
        .unwrap();
    assert_eq!(sent.attachments[0].mime, "image/png");
    assert!(sent.attachments[0].local_path.is_some());
    let blob = sent.attachments[0].blob.clone();
    eventually("bob sees attachment msg", || {
        bob.messages(conv.id.clone(), None, None).unwrap().iter().any(|m| m.body == "pic")
    })
    .await;
    let path = bob.fetch_attachment(blob).await.unwrap();
    assert_eq!(std::fs::read(path).unwrap(), content);

    // restart bob: everything persists
    let bob_id = bob.profile().id.clone();
    bob.shutdown().await.unwrap();
    drop(bob);
    tokio::time::sleep(Duration::from_millis(300)).await;
    bob = open(&db, "Bob", pb, false).await;
    assert_eq!(bob.profile().id, bob_id, "same identity after restart");
    connect_all(&[&alice, &bob]);
    let msgs = bob.messages(conv.id.clone(), None, None).unwrap();
    assert_eq!(msgs.len(), 3);
    assert!(msgs[0].body.contains("edited"));
    assert!(bob.contacts().iter().any(|c| c.name == "Alice"));
    bob.send_message(conv.id.clone(), "back after restart".into(), None, vec![]).await.unwrap();
    eventually("alice gets post-restart message", || {
        alice.messages(conv.id.clone(), None, None).unwrap().iter().any(|m| m.body == "back after restart")
    })
    .await;

    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn keeper_delivers_while_sender_is_offline() {
    let (da, db, dk) = (tmp("alice"), tmp("bob"), tmp("keeper"));
    let (pa, pb, pk) = (free_port(), free_port(), free_port());
    let alice = open(&da, "Alice", pa, false).await;
    let bob = open(&db, "Bob", pb, false).await;
    let keeper = open(&dk, "Keeper", pk, true).await;
    connect_all(&[&alice, &bob, &keeper]);

    let b = alice.add_contact(bob.profile().contact_code).unwrap();
    let k = alice.add_contact(keeper.profile().contact_code).unwrap();
    let conv = alice.create_conversation(Some("Team".into()), vec![b.id.clone()]).unwrap();
    alice.add_keeper(conv.id.clone(), k.id.clone()).unwrap();
    eventually("bob joined", || bob.conversations().len() == 1).await;
    bob.accept_request(conv.id.clone()).unwrap();
    eventually("keeper joined", || keeper.node().space_ids().len() == 1).await;
    assert!(keeper.conversations().is_empty(), "keeper never shows conversations");

    // Bob goes offline. Alice writes, syncs to the keeper, then goes offline too.
    bob.shutdown().await.unwrap();
    drop(bob);
    alice.send_message(conv.id.clone(), "sent while you were away".into(), None, vec![]).await.unwrap();
    let space = keeper.node().space_ids()[0];
    eventually("keeper holds it (but can't read it)", || {
        keeper.node().with_space(&space, |r| r.opaque_count()).unwrap() >= 3
    })
    .await;
    alice.shutdown().await.unwrap();
    drop(alice);

    // Bob comes back: only the keeper is online.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let bob = open(&db, "Bob", pb, false).await;
    connect_all(&[&bob, &keeper]);
    eventually("bob gets the message from the keeper", || {
        bob.messages(conv.id.clone(), None, None)
            .unwrap()
            .iter()
            .any(|m| m.body == "sent while you were away")
    })
    .await;
    bob.shutdown().await.unwrap();
    keeper.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn group_admin_removes_member() {
    let dirs: Vec<PathBuf> = ["a", "b", "c"].iter().map(|n| tmp(n)).collect();
    let alice = open(&dirs[0], "Alice", free_port(), false).await;
    let bob = open(&dirs[1], "Bob", free_port(), false).await;
    let carol = open(&dirs[2], "Carol", free_port(), false).await;
    connect_all(&[&alice, &bob, &carol]);
    let b = alice.add_contact(bob.profile().contact_code).unwrap();
    let c = alice.add_contact(carol.profile().contact_code).unwrap();
    let conv = alice.create_conversation(Some("Trio".into()), vec![b.id.clone(), c.id.clone()]).unwrap();
    eventually("all joined", || bob.conversations().len() == 1 && carol.conversations().len() == 1).await;
    bob.accept_request(conv.id.clone()).unwrap();
    carol.accept_request(conv.id.clone()).unwrap();
    assert!(bob.rename_conversation(conv.id.clone(), "mine".into()).is_err(), "not admin");

    // L4: Bob (not admin) bypasses the API and appends a forged Meta op.
    // Every peer's WASM chat rules reject it; the title is unchanged.
    let space = alice.node().space_ids()[0];
    let forged = mycel_node::chat::ChatOp::Meta { title: Some("pwned".into()), direct: false };
    bob.node()
        .with_space(&space, |r| r.append(mycel_node::chat::messages_feed(), forged.encode()))
        .unwrap()
        .unwrap();
    bob.node().changed(space);
    eventually("alice's rules reject bob's forged op", || {
        alice.node().with_space(&space, |r| r.rule_rejected()).unwrap() == 1
    })
    .await;
    assert_eq!(alice.conversation(conv.id.clone()).unwrap().title, "Trio");
    assert_eq!(bob.node().with_space(&space, |r| r.rule_rejected()).unwrap(), 1);

    alice.remove_member(conv.id.clone(), c.id.clone()).unwrap();
    eventually("carol learns she was removed", || {
        !carol.conversation(conv.id.clone()).unwrap().active
    })
    .await;
    alice.send_message(conv.id.clone(), "carol can't see this".into(), None, vec![]).await.unwrap();
    eventually("bob sees it", || {
        bob.messages(conv.id.clone(), None, None).unwrap().iter().any(|m| m.body == "carol can't see this")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!carol
        .messages(conv.id.clone(), None, None)
        .unwrap()
        .iter()
        .any(|m| m.body == "carol can't see this"));
    assert!(carol.send_message(conv.id.clone(), "hello?".into(), None, vec![]).await.is_err());
    for r in [alice, bob, carol] {
        r.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn declined_and_blocked_strangers_stay_out() {
    let (dm, dv) = (tmp("mallory"), tmp("victim"));
    let mallory = open(&dm, "Mallory", free_port(), false).await;
    let victim = open(&dv, "Victim", free_port(), false).await;
    connect_all(&[&mallory, &victim]);
    // Mallory only needs the victim's public card (e.g. from the LAN).
    let v = mallory.add_contact(victim.profile().contact_code).unwrap();
    let c1 = mallory.create_conversation(None, vec![v.id.clone()]).unwrap();
    mallory.send_message(c1.id.clone(), "click my file".into(), None, vec![]).await.unwrap();
    eventually("request arrives", || victim.conversations().iter().any(|c| c.request)).await;
    assert!(victim.contacts().is_empty());
    victim.decline_request(c1.id.clone(), true).unwrap();
    assert!(victim.conversations().is_empty(), "declined conversations are hidden");
    // A new attempt from the blocked key is refused at the network layer.
    let c2 = mallory.create_conversation(Some("again".into()), vec![v.id.clone()]).unwrap();
    let _ = mallory.node().sync_with(
        mycel_node::crypto::SignPk(<[u8; 32]>::try_from(hex_decode(&v.id)).unwrap()),
        hash_of(&c2.id),
        false,
    ).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(victim.conversations().is_empty());
    assert!(!victim.node().space_ids().contains(&hash_of(&c2.id)));
    mallory.shutdown().await.unwrap();
    victim.shutdown().await.unwrap();
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hash_of(s: &str) -> mycel_node::crypto::Hash32 {
    mycel_node::crypto::Hash32(<[u8; 32]>::try_from(hex_decode(s)).unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn contact_code_address_hints_connect_without_discovery() {
    // Local mode: no mDNS, and we deliberately don't call connect_all.
    let alice = open(&tmp("ha"), "Alice", free_port(), false).await;
    let bob = open(&tmp("hb"), "Bob", free_port(), false).await;
    let code = bob.profile().contact_code;
    assert!(code.contains('@'), "code carries address hints: {code}");
    let b = alice.add_contact(code).unwrap();
    let conv = alice.create_conversation(None, vec![b.id.clone()]).unwrap();
    alice.send_message(conv.id.clone(), "found you by code".into(), None, vec![]).await.unwrap();
    eventually("bob reached via hints only", || {
        bob.conversations().iter().any(|c| c.id == conv.id)
    })
    .await;
    alice.shutdown().await.unwrap();
    bob.shutdown().await.unwrap();
}

// ───────────────────────────── attachments ─────────────────────────────

/// Alice and Bob in an accepted DM.
async fn dm_pair(tag: &str) -> (Arc<Runtime>, Arc<Runtime>, String) {
    let alice = open(&tmp(tag), "Alice", free_port(), false).await;
    let bob = open(&tmp(tag), "Bob", free_port(), false).await;
    connect_all(&[&alice, &bob]);
    let b = alice.add_contact(bob.profile().contact_code).unwrap();
    let conv = alice.create_conversation(None, vec![b.id]).unwrap();
    eventually("bob joined", || bob.conversations().len() == 1).await;
    bob.accept_request(conv.id.clone()).unwrap();
    (alice, bob, conv.id)
}

/// Write `len` pseudo-random bytes to `path` a megabyte at a time.
fn write_pseudo_random(path: &std::path::Path, len: usize) {
    use std::io::Write;
    let mut f = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut buf = vec![0u8; 1 << 20];
    let mut left = len;
    while left > 0 {
        for c in buf.chunks_mut(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            c.copy_from_slice(&x.to_le_bytes()[..c.len()]);
        }
        let n = left.min(buf.len());
        f.write_all(&buf[..n]).unwrap();
        left -= n;
    }
}

/// Compare two files a chunk at a time (they may be big).
fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    use std::io::Read;
    let (mut fa, mut fb) = (std::fs::File::open(a).unwrap(), std::fs::File::open(b).unwrap());
    if fa.metadata().unwrap().len() != fb.metadata().unwrap().len() {
        return false;
    }
    let (mut ba, mut bb) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    loop {
        let n = fa.read(&mut ba).unwrap();
        if n == 0 {
            return true;
        }
        fb.read_exact(&mut bb[..n]).unwrap();
        if ba[..n] != bb[..n] {
            return false;
        }
    }
}

async fn wait_for_message(rt: &Runtime, conv: &str, body: &str) -> mycel_node::api::MessageView {
    let mut found = None;
    eventually(&format!("message {body:?} arrives"), || {
        found = rt.messages(conv.into(), None, None).unwrap().into_iter().find(|m| m.body == body);
        found.is_some()
    })
    .await;
    found.unwrap()
}

fn progress_events(rx: &mut tokio::sync::broadcast::Receiver<Event>, id: &str) -> Vec<(u64, u64)> {
    let mut out = vec![];
    while let Ok(ev) = rx.try_recv() {
        if let Event::TransferProgress { id: i, done, total, .. } = ev
            && i == id
        {
            out.push((done, total));
        }
    }
    out
}

/// Way past the old 50 MiB cap: streamed, chunk-encrypted, fetched on demand
/// (too big for an eager push), byte-exact, with progress both ways.
#[tokio::test(flavor = "multi_thread")]
async fn large_attachment_streams_between_nodes() {
    let (alice, bob, conv) = dm_pair("big").await;
    let file = tmp("big").with_extension("mov");
    let len = 120 * 1024 * 1024;
    write_pseudo_random(&file, len);
    let path = file.to_string_lossy().into_owned();

    let mut a_events = alice.subscribe();
    let t = std::time::Instant::now();
    let sent = alice.send_message(conv.clone(), "video".into(), None, vec![path.clone()]).await.unwrap();
    let encrypt_time = t.elapsed();
    let att = &sent.attachments[0];
    assert_eq!(att.size, len as u64);
    assert_eq!(att.mime, "video/quicktime");
    assert_eq!(att.name, file.file_name().unwrap().to_str().unwrap());
    assert!(same_file(&file, std::path::Path::new(att.local_path.as_ref().unwrap())), "sender keeps a plaintext copy");
    let up = progress_events(&mut a_events, &path);
    assert_eq!(up.last(), Some(&(len as u64, len as u64)), "upload progress ends at 100%");

    wait_for_message(&bob, &conv, "video").await;
    let space = bob.node().space_ids()[0];
    let hash = hash_of(&att.blob);
    assert!(bob.node().blob_path(&space, &hash).is_none(), "not pushed eagerly");

    let mut b_events = bob.subscribe();
    let t = std::time::Instant::now();
    let got = bob.fetch_attachment(att.blob.clone()).await.unwrap();
    let fetch_time = t.elapsed();
    assert!(same_file(&file, std::path::Path::new(&got)), "byte-exact after the round trip");
    let down = progress_events(&mut b_events, &att.blob);
    assert!(down.len() >= 2, "download progress events: {down:?}");
    let (done, total) = *down.last().unwrap();
    assert_eq!(done, total);
    assert!(total > len as u64, "progress counts sealed bytes");
    eprintln!(
        "120 MiB: encrypt+store {encrypt_time:?}, fetch+decrypt {fetch_time:?}, {} download progress events",
        down.len()
    );
    let view = bob.messages(conv.clone(), None, None).unwrap();
    assert_eq!(view.last().unwrap().attachments[0].local_path.as_deref(), Some(got.as_str()));

    for rt in [alice, bob] {
        rt.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(rt.data_dir()); // ~0.5 GB of test data
    }
    let _ = std::fs::remove_file(&file);
}

/// Attachments sent before streaming (one-shot sealed) still open; folders
/// and packages go as .zip; file:// URLs work; unreadable files say why.
#[tokio::test(flavor = "multi_thread")]
async fn legacy_attachments_folders_and_read_errors() {
    use mycel_node::chat::{AttachmentRef, ChatOp, messages_feed};
    use mycel_node::crypto::SymKey;
    let (alice, bob, conv) = dm_pair("legacy").await;
    let space = alice.node().space_ids()[0];

    // the one-shot format older builds sent
    let plain: Vec<u8> = (0..300_000u32).map(|i| (i * 13 % 251) as u8).collect();
    let (key, nonce) = (SymKey::generate(), mycel_node::crypto::random());
    let ct = key.seal(&nonce, b"mycel/v0/attachment", &plain).unwrap();
    let blob = alice.node().put_blob(space, ct).await.unwrap();
    let a = AttachmentRef {
        blob,
        key: key.0,
        nonce,
        name: "old.pdf".into(),
        mime: "application/pdf".into(),
        size: plain.len() as u64,
    };
    let op = ChatOp::Text { body: "legacy".into(), reply_to: None, attachments: vec![a] };
    alice.node().with_space(&space, |r| r.append(messages_feed(), op.encode())).unwrap().unwrap();
    alice.node().changed(space);
    let m = wait_for_message(&bob, &conv, "legacy").await;
    let got = bob.fetch_attachment(m.attachments[0].blob.clone()).await.unwrap();
    assert_eq!(std::fs::read(got).unwrap(), plain);

    // a folder (like a macOS package), passed as a file:// URL with a space in its name
    let root = tmp("pkg");
    let pkg = root.join("My Report.pages");
    std::fs::create_dir_all(pkg.join("Data")).unwrap();
    std::fs::write(pkg.join("Index.xml"), b"<doc/>").unwrap();
    std::fs::write(pkg.join("Data").join("img.bin"), vec![7u8; 100_000]).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("Index.xml", pkg.join("link.xml")).unwrap();
    let url = format!("file://{}", pkg.to_string_lossy().replace(' ', "%20"));
    let sent = alice.send_message(conv.clone(), "pkg".into(), None, vec![url]).await.unwrap();
    assert_eq!(sent.attachments[0].name, "My Report.pages.zip");
    assert_eq!(sent.attachments[0].mime, "application/zip");
    let m = wait_for_message(&bob, &conv, "pkg").await;
    let got = bob.fetch_attachment(m.attachments[0].blob.clone()).await.unwrap();
    let mut z = zip::ZipArchive::new(std::fs::File::open(got).unwrap()).unwrap();
    let names: Vec<String> = z.file_names().map(str::to_string).collect();
    assert!(names.contains(&"My Report.pages/Index.xml".to_string()), "{names:?}");
    assert!(names.contains(&"My Report.pages/Data/img.bin".to_string()), "{names:?}");
    let mut img = vec![];
    std::io::Read::read_to_end(&mut z.by_name("My Report.pages/Data/img.bin").unwrap(), &mut img).unwrap();
    assert_eq!(img, vec![7u8; 100_000]);

    // errors carry the reason
    let missing = root.join("nope.txt").to_string_lossy().into_owned();
    let e = alice.send_message(conv.clone(), "x".into(), None, vec![missing]).await.unwrap_err();
    assert!(format!("{e:#}").contains("can't find"), "{e:#}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let locked = root.join("locked.txt");
        std::fs::write(&locked, b"secret").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&locked).is_err() {
            // (not running as root)
            let e = alice
                .send_message(conv.clone(), "x".into(), None, vec![locked.to_string_lossy().into()])
                .await
                .unwrap_err();
            let msg = format!("{e:#}");
            assert!(msg.contains("locked.txt") && msg.contains("denied"), "{msg}");
            #[cfg(target_os = "macos")]
            assert!(msg.contains("Privacy & Security"), "{msg}");
        }
    }
    for rt in [alice, bob] {
        rt.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(rt.data_dir());
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Live voice call between two runtimes (test audio in place of devices):
/// refused while the conversation is still a message request, then rings,
/// answers, carries audio, mutes and hangs up through the JSON command table.
#[tokio::test(flavor = "multi_thread")]
async fn voice_call_between_runtimes() {
    use mycel_node::api::{CallEndReason, CallPhase};
    use mycel_node::call::audio::{AudioIo, TestAudio, TestSource};
    use mycel_node::call::level::estimate_frequency;
    use mycel_node::dispatch::dispatch;
    use serde_json::json;

    let (da, db) = (tmp("call-alice"), tmp("call-bob"));
    let alice = open(&da, "Alice", free_port(), false).await;
    let bob = open(&db, "Bob", free_port(), false).await;
    connect_all(&[&alice, &bob]);
    let bob_audio = Arc::new(TestAudio::new(TestSource::Sine { hz: 330.0, amp: 0.5 }));
    alice.calls().set_audio(Arc::new(TestAudio::new(TestSource::Sine { hz: 440.0, amp: 0.5 })));
    bob.calls().set_audio(bob_audio.clone() as Arc<dyn AudioIo>);
    let mut bob_events = bob.subscribe();

    // Alice has Bob's code, Bob doesn't have hers: on Bob's side this is a
    // message request, so her call is refused and nothing rings.
    let bob_contact = alice.add_contact(bob.profile().contact_code).unwrap();
    let conv = alice.create_conversation(None, vec![bob_contact.id.clone()]).unwrap();
    eventually("bob gets the request", || bob.conversations().iter().any(|c| c.id == conv.id && c.request)).await;
    assert!(bob.start_call(conv.id.clone()).await.is_err(), "can't call from an unaccepted request");
    let c = alice.start_call(conv.id.clone()).await.unwrap();
    eventually("refused", || {
        alice.call_status().iter().any(|x| x.id == c.id && x.end_reason == Some(CallEndReason::Failed))
    })
    .await;
    assert!(bob.call_status().is_empty(), "nothing rang on bob's side");

    // Bob accepts the request: now it rings.
    bob.accept_request(conv.id.clone()).unwrap();
    let out = dispatch(&alice, "start_call", json!({ "conversation": conv.id })).await.unwrap();
    assert_eq!(out["state"], "connecting");
    assert_eq!(out["direction"], "outgoing");
    assert_eq!(out["peerName"], "Bob");
    let id = out["id"].as_str().unwrap().to_string();
    let incoming = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(Event::CallIncoming { call }) = bob_events.recv().await {
                return call;
            }
        }
    })
    .await
    .expect("callIncoming event");
    assert_eq!(incoming.id, id);
    assert_eq!(incoming.conversation, conv.id);
    assert_eq!(incoming.peer_name, "Alice");
    let json_event = serde_json::to_value(Event::CallIncoming { call: incoming.clone() }).unwrap();
    assert_eq!(json_event["type"], "callIncoming");
    assert_eq!(json_event["call"]["state"], "ringing");

    let accepted = dispatch(&bob, "accept_call", json!({ "call": id })).await.unwrap();
    assert!(accepted["state"] == "connecting" || accepted["state"] == "active");
    eventually("both active", || {
        let a = alice.call_status();
        let b = bob.call_status();
        a.first().is_some_and(|c| c.state == CallPhase::Active) && b.first().is_some_and(|c| c.state == CallPhase::Active)
    })
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    {
        let rec = bob_audio.recording();
        let rec = rec.lock();
        let f = estimate_frequency(&rec.samples[rec.samples.len() - 48_000..], 48_000).unwrap();
        assert!((f - 440.0).abs() < 8.0, "bob hears alice's 440 Hz, got {f}");
    }
    let st = dispatch(&bob, "call_status", json!({})).await.unwrap();
    assert_eq!(st[0]["state"], "active");
    assert_eq!(st[0]["path"], "network");
    assert!(st[0]["durationMs"].as_u64().unwrap() >= 1_500);
    assert!(st[0]["stats"]["framesReceived"].as_u64().unwrap() > 50);
    // the Network panel learns the call's path too
    let net = alice.network_status();
    assert!(net.peers.iter().any(|p| p.id == bob_contact.id && p.online));

    let muted = dispatch(&bob, "set_muted", json!({ "call": id, "muted": true })).await.unwrap();
    assert_eq!(muted["muted"], true);
    eventually("alice sees bob muted", || alice.call_status().first().is_some_and(|c| c.remote_muted)).await;

    dispatch(&alice, "end_call", json!({ "call": id })).await.unwrap();
    eventually("bob sees the hang-up", || {
        bob.call_status().first().is_some_and(|c| c.end_reason == Some(CallEndReason::RemoteHungUp))
    })
    .await;
    assert!(dispatch(&bob, "accept_call", json!({ "call": id })).await.is_err(), "can't answer an ended call");

    for rt in [alice, bob] {
        rt.shutdown().await.unwrap();
        let _ = std::fs::remove_dir_all(rt.data_dir());
    }
}
