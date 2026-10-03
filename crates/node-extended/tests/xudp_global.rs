mod support;
use node_extended::{Config, mux::serve_xudp};
use node_session::Host;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::watch,
};

async fn packet(client: &mut tokio::io::DuplexStream, id: u16, global: [u8; 8], payload: &[u8]) {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&id.to_be_bytes());
    metadata.extend_from_slice(&[1, 1, 2, 0, 80, 1, 127, 0, 0, 1]);
    metadata.extend_from_slice(&global);
    client.write_u16(metadata.len() as u16).await.unwrap();
    client.write_all(&metadata).await.unwrap();
    client.write_u16(payload.len() as u16).await.unwrap();
    client.write_all(payload).await.unwrap();
}
async fn response(client: &mut tokio::io::DuplexStream) -> (u16, u8, Vec<u8>) {
    let len = client.read_u16().await.unwrap();
    let mut metadata = vec![0; len as usize];
    client.read_exact(&mut metadata).await.unwrap();
    let payload = if metadata[3] & 1 != 0 {
        let len = client.read_u16().await.unwrap();
        let mut bytes = vec![0; len as usize];
        client.read_exact(&mut bytes).await.unwrap();
        bytes
    } else {
        vec![]
    };
    (
        u16::from_be_bytes([metadata[0], metadata[1]]),
        metadata[2],
        payload,
    )
}
#[tokio::test]
async fn global_id_rebinds_after_eof_and_cancel_returns_listener_permits() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let host = TestHost::new();
        let config = Config::default();
        let user = host.users()[0].clone();
        let (mut client, server) = tokio::io::duplex(65536);
        let first = tokio::spawn(serve_xudp(
            Box::new(server),
            user.clone(),
            peer(),
            host.clone(),
            config.clone(),
            None,
        ));
        packet(&mut client, 1, [1; 8], b"first").await;
        assert_eq!(response(&mut client).await, (1, 2, b"first".to_vec()));
        drop(client);
        first.await.unwrap().unwrap();
        assert_eq!(host.active.load(Ordering::SeqCst), 1);
        assert_eq!(config.xudp_sessions.cached_sessions(), 1);
        let (mut client, server) = tokio::io::duplex(65536);
        let (stop, rx) = watch::channel(false);
        let mut other_peer = peer();
        other_peer.set_port(other_peer.port() + 1);
        let second = tokio::spawn(serve_xudp(
            Box::new(server),
            user,
            other_peer,
            host.clone(),
            config.clone(),
            Some(rx),
        ));
        packet(&mut client, 8, [1; 8], b"second").await;
        assert_eq!(response(&mut client).await, (8, 2, b"second".to_vec()));
        assert_eq!(
            host.active.load(Ordering::SeqCst),
            1,
            "GlobalID must reuse the Host channel across TCP source ports"
        );
        stop.send(true).unwrap();
        second.await.unwrap().unwrap();
        assert_eq!(host.active.load(Ordering::SeqCst), 0);
        assert_eq!(config.xudp_sessions.cached_sessions(), 0);
        assert_eq!(
            config.shared_budget.available_bytes(),
            Some(8 * 1024 * 1024)
        );
        assert_eq!(config.shared_budget.available_sessions(), Some(1024));
        assert_eq!(host.totals(), (11, 11));
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn active_rebind_joins_old_reader_and_same_id_cannot_cross_identities() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let host = TestHost::new();
        let config = Config::default();
        let user = host.users()[0].clone();
        let second_user = node_session::User {
            name: Arc::from("second"),
            uuid: Some([2; 16]),
            password: Some("different".into()),
        };
        *host.users.write().unwrap() = Arc::from([user.clone(), second_user.clone()]);
        let (stop, rx) = watch::channel(false);
        let (mut first, server) = tokio::io::duplex(65536);
        let job1 = tokio::spawn(serve_xudp(
            Box::new(server),
            user.clone(),
            peer(),
            host.clone(),
            config.clone(),
            Some(rx.clone()),
        ));
        packet(&mut first, 1, [4; 8], b"one").await;
        let _ = response(&mut first).await;
        let (mut second, server) = tokio::io::duplex(65536);
        let job2 = tokio::spawn(serve_xudp(
            Box::new(server),
            user,
            peer(),
            host.clone(),
            config.clone(),
            Some(rx.clone()),
        ));
        packet(&mut second, 2, [4; 8], b"two").await;
        assert_eq!(response(&mut second).await, (2, 2, b"two".to_vec()));
        assert_eq!(response(&mut first).await, (1, 3, vec![]));
        assert_eq!(host.active.load(Ordering::SeqCst), 1);
        let (mut third, server) = tokio::io::duplex(65536);
        let job3 = tokio::spawn(serve_xudp(
            Box::new(server),
            second_user,
            peer(),
            host.clone(),
            config.clone(),
            Some(rx),
        ));
        packet(&mut third, 3, [4; 8], b"three").await;
        assert_eq!(response(&mut third).await, (3, 2, b"three".to_vec()));
        assert_eq!(host.active.load(Ordering::SeqCst), 2);
        stop.send(true).unwrap();
        job1.await.unwrap().unwrap();
        job2.await.unwrap().unwrap();
        job3.await.unwrap().unwrap();
        assert_eq!(host.active.load(Ordering::SeqCst), 0);
        assert_eq!(config.xudp_sessions.cached_sessions(), 0);
        assert_eq!(config.shared_budget.available_sessions(), Some(1024));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn failed_host_channel_is_removed_before_same_global_id_readmission() {
    use node_session::{BoxStream, Datagram, Destination, User};
    use std::{io, net::SocketAddr, sync::atomic::AtomicBool};
    struct FaultHost {
        inner: Arc<TestHost>,
        fail: Arc<AtomicBool>,
    }
    struct FaultChannel {
        inner: Arc<dyn Datagram>,
        fail: Arc<AtomicBool>,
    }
    #[async_trait::async_trait]
    impl Host for FaultHost {
        fn users(&self) -> Arc<[User]> {
            self.inner.users()
        }
        async fn connect(
            &self,
            user: &User,
            peer: SocketAddr,
            target: &Destination,
        ) -> io::Result<BoxStream> {
            self.inner.connect(user, peer, target).await
        }
        async fn datagram(&self, user: &User, peer: SocketAddr) -> io::Result<Arc<dyn Datagram>> {
            Ok(Arc::new(FaultChannel {
                inner: self.inner.datagram(user, peer).await?,
                fail: self.fail.clone(),
            }))
        }
    }
    #[async_trait::async_trait]
    impl Datagram for FaultChannel {
        async fn send(&self, payload: &[u8], target: &Destination) -> io::Result<usize> {
            if self.fail.swap(false, Ordering::SeqCst) {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "fixture revocation",
                ))
            } else {
                self.inner.send(payload, target).await
            }
        }
        async fn receive(&self, bytes: &mut [u8]) -> io::Result<(usize, Destination)> {
            self.inner.receive(bytes).await
        }
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        let inner = TestHost::new();
        let host = Arc::new(FaultHost {
            inner: inner.clone(),
            fail: Arc::new(AtomicBool::new(true)),
        });
        let config = Config::default();
        let user = host.users()[0].clone();
        let (stop, rx) = watch::channel(false);
        let (mut client, server) = tokio::io::duplex(65536);
        let server = tokio::spawn(serve_xudp(
            Box::new(server),
            user,
            peer(),
            host,
            config.clone(),
            Some(rx),
        ));
        packet(&mut client, 1, [9; 8], b"rejected").await;
        assert_eq!(response(&mut client).await, (1, 3, vec![]));
        assert_eq!(config.xudp_sessions.cached_sessions(), 0);
        assert_eq!(inner.active.load(Ordering::SeqCst), 0);
        packet(&mut client, 2, [9; 8], b"fresh").await;
        assert_eq!(response(&mut client).await, (2, 2, b"fresh".to_vec()));
        assert_eq!(inner.active.load(Ordering::SeqCst), 1);
        assert_eq!(inner.totals(), (5, 5));
        stop.send(true).unwrap();
        server.await.unwrap().unwrap();
        assert_eq!(inner.active.load(Ordering::SeqCst), 0);
        assert_eq!(config.shared_budget.available_sessions(), Some(1024));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn publishing_new_users_releases_paused_changed_profiles_and_preserves_current_ones() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let host = TestHost::new();
        let config = Config::default();
        let original = host.users()[0].clone();
        let stable = node_session::User {
            name: Arc::from("stable"),
            uuid: Some([6; 16]),
            password: Some("unchanged".into()),
        };
        *host.users.write().unwrap() = Arc::from([original.clone(), stable.clone()]);
        for (id, user) in [(1, original.clone()), (2, stable.clone())] {
            let (mut client, server) = tokio::io::duplex(65536);
            let job = tokio::spawn(serve_xudp(
                Box::new(server),
                user,
                peer(),
                host.clone(),
                config.clone(),
                None,
            ));
            packet(&mut client, id, [12; 8], b"cached").await;
            let _ = response(&mut client).await;
            drop(client);
            job.await.unwrap().unwrap();
        }
        assert_eq!(host.active.load(Ordering::SeqCst), 2);
        assert_eq!(config.xudp_sessions.cached_sessions(), 2);
        config.xudp_sessions.prune_users(&host.users());
        assert_eq!(config.xudp_sessions.cached_sessions(), 2);
        let changed = node_session::User {
            password: Some("replaced credential".into()),
            ..original
        };
        *host.users.write().unwrap() = Arc::from([changed, stable]);
        config.xudp_sessions.prune_users(&host.users());
        assert_eq!(host.active.load(Ordering::SeqCst), 1);
        assert_eq!(config.xudp_sessions.cached_sessions(), 1);
        assert_eq!(config.shared_budget.available_sessions(), Some(1023));
        config.xudp_sessions.clear_idle();
        assert_eq!(host.active.load(Ordering::SeqCst), 0);
        assert_eq!(config.xudp_sessions.cached_sessions(), 0);
        assert_eq!(config.shared_budget.available_sessions(), Some(1024));
        assert_eq!(
            config.shared_budget.available_bytes(),
            Some(8 * 1024 * 1024)
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn old_pending_admission_cannot_repopulate_cache_after_authentication_prune() {
    use node_session::{BoxStream, Datagram, Destination, User};
    use std::{io, net::SocketAddr};
    struct PendingHost {
        inner: Arc<TestHost>,
        started: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    #[async_trait::async_trait]
    impl Host for PendingHost {
        fn users(&self) -> Arc<[User]> {
            self.inner.users()
        }
        async fn connect(
            &self,
            user: &User,
            peer: SocketAddr,
            target: &Destination,
        ) -> io::Result<BoxStream> {
            self.inner.connect(user, peer, target).await
        }
        async fn datagram(&self, user: &User, peer: SocketAddr) -> io::Result<Arc<dyn Datagram>> {
            let channel = self.inner.datagram(user, peer).await?;
            self.started.notify_one();
            self.release.notified().await;
            Ok(channel)
        }
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        let inner = TestHost::new();
        let host = Arc::new(PendingHost {
            inner: inner.clone(),
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let config = Config::default();
        let user = host.users()[0].clone();
        let (mut client, server) = tokio::io::duplex(65536);
        let job = tokio::spawn(serve_xudp(
            Box::new(server),
            user.clone(),
            peer(),
            host.clone(),
            config.clone(),
            None,
        ));
        packet(&mut client, 1, [13; 8], b"old profile").await;
        host.started.notified().await;
        *inner.users.write().unwrap() = Arc::from([User {
            password: Some("rotated".into()),
            ..user
        }]);
        config.xudp_sessions.prune_users(&host.users());
        host.release.notify_one();
        assert_eq!(
            job.await.unwrap().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(inner.totals(), (0, 0));
        assert_eq!(inner.active.load(Ordering::SeqCst), 0);
        assert_eq!(config.xudp_sessions.cached_sessions(), 0);
        assert_eq!(config.shared_budget.available_sessions(), Some(1024));
    })
    .await
    .unwrap();
}
