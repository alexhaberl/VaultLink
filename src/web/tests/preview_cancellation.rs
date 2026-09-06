static TEXT_PREVIEW_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone, Copy)]
enum PreviewTestRoute {
    Web,
    Api,
    Admin,
}

impl PreviewTestRoute {
    fn uri(self) -> &'static str {
        match self {
            Self::Web => "/v/preview-cancel/preview?path=preview.txt",
            Self::Api => "/api/v2/public/shares/preview-cancel/preview?path=preview.txt",
            Self::Admin => "/admin/preview?path=docs/preview.txt",
        }
    }

    fn request(self) -> Request {
        let mut request = request(Method::GET, self.uri(), "");
        request.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_static("vaultlink_session=preview-admin-session"),
        );
        request
    }
}

struct PreviewRequestFinished(Arc<std::sync::atomic::AtomicBool>);

impl Drop for PreviewRequestFinished {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

async fn wait_for_preview_resources(state: &AppState, share_id: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if state.try_acquire_preview_render(64).is_ok()
                && state.db().active_transfer_reservations(share_id).unwrap() == 0
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("finished detached read should release all resources");
}

async fn disconnect_preview_request(
    app: &Router,
    state: &AppState,
    hook: &TextPreviewReadTestHook,
    route: PreviewTestRoute,
) -> (
    axum_server::Handle<std::net::SocketAddr>,
    tokio::task::JoinHandle<()>,
) {
    let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let finished_marker = finished.clone();
    let server_app = app.clone().layer(middleware::from_fn(
        move |request: Request, next: axum::middleware::Next| {
            let marker = PreviewRequestFinished(finished_marker.clone());
            async move {
                let _marker = marker;
                next.run(request).await
            }
        },
    ));
    let handle = axum_server::Handle::<std::net::SocketAddr>::new();
    let server_handle = handle.clone();
    let server = tokio::spawn(async move {
        axum_server::bind("127.0.0.1:0".parse().unwrap())
            .http1_only()
            .handle(server_handle)
            .serve(server_app.into_make_service())
            .await
            .unwrap();
    });
    let address = handle.listening().await.unwrap();
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(
        &mut client,
        format!(
            "GET {} HTTP/1.1\r\nHost: localhost\r\nCookie: vaultlink_session=preview-admin-session\r\n\r\n",
            route.uri()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while hook.entered.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("preview should reach the blocking read");
    assert!(state.try_acquire_preview_render(64).is_err());
    drop(client);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !finished.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("HTTP disconnect should drop the request future");
    (handle, server)
}

async fn preview_tcp_cancellation(route: PreviewTestRoute) {
    let _serial = TEXT_PREVIEW_TEST_SERIAL.lock().await;
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let (state, share_id) = preview_test_state(root.path(), data.path());
    let hook = Arc::new(TextPreviewReadTestHook {
        panic_after_release: false,
        path: if matches!(route, PreviewTestRoute::Admin) {
            "docs/preview.txt"
        } else {
            "preview.txt"
        }
        .into(),
        entered: std::sync::atomic::AtomicUsize::new(0),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    let slot = TEXT_PREVIEW_READ_TEST_HOOK.get_or_init(|| std::sync::Mutex::new(None));
    assert!(slot.lock().unwrap().replace(hook.clone()).is_none());
    let hook_guard = TextPreviewReadTestGuard(hook.clone());
    let app = router(state.clone());
    let (handle, server) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        disconnect_preview_request(&app, &state, &hook, route),
    )
    .await
    .expect("TCP preview test timed out");
    let budget_held = state.try_acquire_preview_render(64).is_err();
    // Clean up before asserting so a failing regression cannot strand a reader.
    if !budget_held {
        hook.release();
        handle.shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        panic!("HTTP disconnect released the memory budget before its blocking read finished");
    }
    assert_eq!(
        app.clone().oneshot(route.request()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(hook.entered.load(Ordering::Acquire), 1);
    if !matches!(route, PreviewTestRoute::Admin) {
        assert_eq!(
            state.db().active_transfer_reservations(share_id).unwrap(),
            1
        );
    }
    hook.release();
    wait_for_preview_resources(&state, share_id).await;
    assert_eq!(
        state
            .db()
            .share_by_token("preview-cancel")
            .unwrap()
            .unwrap()
            .download_count,
        0
    );
    let response = app.oneshot(route.request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(state.try_acquire_preview_render(64).is_err());
    drop(response);
    assert!(state.try_acquire_preview_render(64).is_ok());
    drop(hook_guard);
    handle.shutdown();
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnected_web_preview_retains_its_read_resources() {
    preview_tcp_cancellation(PreviewTestRoute::Web).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnected_api_preview_retains_its_read_resources() {
    preview_tcp_cancellation(PreviewTestRoute::Api).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnected_admin_preview_retains_its_read_resources() {
    preview_tcp_cancellation(PreviewTestRoute::Admin).await;
}

fn preview_test_state(root: &Path, data: &Path) -> (AppState, i64) {
    std::fs::create_dir(root.join("docs")).unwrap();
    std::fs::write(root.join("docs/preview.txt"), b"preview content").unwrap();
    let state = test_state(root, data);
    state.mutate_runtime_for_test(|runtime| runtime.max_preview_size = MAX_TEXT_PREVIEW_SIZE);
    state.db().create_admin("admin", "hash", "secret").unwrap();
    state
        .db()
        .create_session(
            "preview-admin-session",
            1,
            "csrf",
            Utc::now() + Duration::hours(1),
        )
        .unwrap();
    state.db().verify_mfa("preview-admin-session").unwrap();
    let share_id = state
        .db()
        .create_share(
            "preview-cancel",
            None,
            "docs",
            true,
            &Permission::DownloadOnly,
            None,
            None,
            None,
            1,
            None,
            &UploadConflictStrategy::Reject,
        )
        .unwrap();
    (state, share_id)
}

#[tokio::test]
async fn preview_read_errors_panics_oversize_and_response_cancellation_release_resources() {
    let _serial = TEXT_PREVIEW_TEST_SERIAL.lock().await;
    for route in [
        PreviewTestRoute::Web,
        PreviewTestRoute::Api,
        PreviewTestRoute::Admin,
    ] {
        let root = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let (state, share_id) = preview_test_state(root.path(), data.path());
        let app = router(state.clone());
        std::fs::write(root.path().join("docs/preview.txt"), b"invalid\0text").unwrap();
        assert_eq!(
            app.clone().oneshot(route.request()).await.unwrap().status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        wait_for_preview_resources(&state, share_id).await;
        std::fs::write(root.path().join("docs/preview.txt"), b"valid preview").unwrap();
        let hook = Arc::new(TextPreviewReadTestHook {
            panic_after_release: true,
            path: if matches!(route, PreviewTestRoute::Admin) {
                "docs/preview.txt"
            } else {
                "preview.txt"
            }
            .into(),
            entered: std::sync::atomic::AtomicUsize::new(0),
            released: std::sync::Mutex::new(true),
            wake: std::sync::Condvar::new(),
        });
        let slot = TEXT_PREVIEW_READ_TEST_HOOK.get_or_init(|| std::sync::Mutex::new(None));
        assert!(slot.lock().unwrap().replace(hook.clone()).is_none());
        let guard = TextPreviewReadTestGuard(hook);
        assert_eq!(
            app.clone().oneshot(route.request()).await.unwrap().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        drop(guard);
        wait_for_preview_resources(&state, share_id).await;
        state.mutate_runtime_for_test(|runtime| runtime.max_preview_size = 1);
        let response = app.clone().oneshot(route.request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        drop(response);
        wait_for_preview_resources(&state, share_id).await;
        state.mutate_runtime_for_test(|runtime| runtime.max_preview_size = MAX_TEXT_PREVIEW_SIZE);
        let response = app.oneshot(route.request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.try_acquire_preview_render(64).is_err());
        drop(response);
        wait_for_preview_resources(&state, share_id).await;
        assert_eq!(
            state
                .db()
                .share_by_token("preview-cancel")
                .unwrap()
                .unwrap()
                .download_count,
            0
        );
    }
}
