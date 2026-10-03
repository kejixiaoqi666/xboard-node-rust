//! Dropping a controller future must not detach its network workers.
pub struct Task<T>(tokio::task::JoinHandle<T>);
impl<T> Task<T> {
    pub fn new(task: tokio::task::JoinHandle<T>) -> Self {
        Self(task)
    }
    pub fn abort(&self) {
        self.0.abort();
    }
    pub fn is_finished(&self) -> bool {
        self.0.is_finished()
    }
}
impl<T> std::future::Future for Task<T> {
    type Output = Result<T, tokio::task::JoinError>;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.get_mut().0).poll(cx)
    }
}
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
