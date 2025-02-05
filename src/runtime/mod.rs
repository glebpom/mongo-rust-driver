mod async_read_ext;
mod async_write_ext;
mod http;
#[cfg(feature = "async-std-runtime")]
mod interval;
mod join_handle;
mod resolver;
mod stream;

use std::{future::Future, net::SocketAddr, time::Duration};

pub(crate) use self::{
    async_read_ext::AsyncLittleEndianRead,
    async_write_ext::AsyncLittleEndianWrite,
    join_handle::AsyncJoinHandle,
    resolver::AsyncResolver,
    stream::AsyncStream,
};
use crate::{
    error::{ErrorKind, Result},
    options::StreamAddress,
};
pub(crate) use http::HttpClient;
#[cfg(feature = "async-std-runtime")]
use interval::Interval;
#[cfg(feature = "tokio-runtime")]
use tokio::time::Interval;

/// An abstract handle to the async runtime.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AsyncRuntime {
    /// Represents the `tokio` runtime.
    #[cfg(feature = "tokio-runtime")]
    Tokio,

    /// Represents the `async-std` runtime.
    #[cfg(feature = "async-std-runtime")]
    AsyncStd,
}

impl AsyncRuntime {
    /// Spawn a task in the background to run a future.
    ///
    /// If the runtime is still running, this will return a handle to the background task.
    /// Otherwise, it will return `None`. As a result, this must be called from an async block
    /// or function running on a runtime.
    pub(crate) fn spawn<F, O>(self, fut: F) -> Option<AsyncJoinHandle<O>>
    where
        F: Future<Output = O> + Send + 'static,
        O: Send + 'static,
    {
        match self {
            #[cfg(feature = "tokio-runtime")]
            Self::Tokio => Some(AsyncJoinHandle::Tokio(tokio::task::spawn(fut))),

            #[cfg(feature = "async-std-runtime")]
            Self::AsyncStd => Some(AsyncJoinHandle::AsyncStd(async_std::task::spawn(fut))),
        }
    }

    /// Spawn a task in the background to run a future.
    ///
    /// Note: this must only be called from an async block or function running on a runtime.
    pub(crate) fn execute<F, O>(self, fut: F)
    where
        F: Future<Output = O> + Send + 'static,
        O: Send + 'static,
    {
        self.spawn(fut);
    }

    /// Run a future in the foreground, blocking on it completing.
    ///
    /// This will panic if called from a sychronous context when tokio is being used.
    #[cfg(any(feature = "sync", test))]
    pub(crate) fn block_on<F, T>(self, fut: F) -> T
    where
        F: Future<Output = T> + Send,
        T: Send,
    {
        #[cfg(all(feature = "tokio-runtime", not(feature = "async-std-runtime")))]
        {
            tokio::task::block_in_place(|| futures::executor::block_on(fut))
        }

        #[cfg(feature = "async-std-runtime")]
        {
            async_std::task::block_on(fut)
        }
    }

    /// Delay for the specified duration.
    pub(crate) async fn delay_for(self, delay: Duration) {
        #[cfg(feature = "tokio-runtime")]
        {
            tokio::time::sleep(delay).await
        }

        #[cfg(feature = "async-std-runtime")]
        {
            async_std::task::sleep(delay).await
        }
    }

    /// Await on a future for a maximum amount of time before returning an error.
    pub(crate) async fn timeout<F: Future>(
        self,
        timeout: Duration,
        future: F,
    ) -> Result<F::Output> {
        #[cfg(feature = "tokio-runtime")]
        {
            tokio::time::timeout(timeout, future)
                .await
                .map_err(|e| ErrorKind::Io(e.into()).into())
        }

        #[cfg(feature = "async-std-runtime")]
        {
            async_std::future::timeout(timeout, future)
                .await
                .map_err(|_| ErrorKind::Io(std::io::ErrorKind::TimedOut.into()).into())
        }
    }

    /// Create a new `Interval` that yields with interval of `duration`.
    /// See: https://docs.rs/tokio/latest/tokio/time/fn.interval.html
    pub(crate) fn interval(self, duration: Duration) -> Interval {
        match self {
            #[cfg(feature = "tokio-runtime")]
            Self::Tokio => tokio::time::interval(duration),

            #[cfg(feature = "async-std-runtime")]
            Self::AsyncStd => Interval::new(duration),
        }
    }

    pub(crate) async fn resolve_address(
        self,
        address: &StreamAddress,
    ) -> Result<impl Iterator<Item = SocketAddr>> {
        match self {
            #[cfg(feature = "tokio-runtime")]
            Self::Tokio => {
                let socket_addrs = tokio::net::lookup_host(format!("{}", address)).await?;
                Ok(socket_addrs)
            }

            #[cfg(feature = "async-std-runtime")]
            Self::AsyncStd => {
                let host = (address.hostname.as_str(), address.port.unwrap_or(27017));
                let socket_addrs = async_std::net::ToSocketAddrs::to_socket_addrs(&host).await?;
                Ok(socket_addrs)
            }
        }
    }
}
