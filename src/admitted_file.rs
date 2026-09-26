//! Bounded file reads/seeks whose blocking worker owns its admission until return.
use crate::response_work::ResponseWorkAdmission;
use std::{
    fs::File,
    future::Future,
    io::{self, Read, Seek, SeekFrom},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncSeek, ReadBuf},
    task::JoinHandle,
};

type ReadResult = (File, Vec<u8>, io::Result<usize>);
type SeekResult = (File, io::Result<u64>);

pub(crate) struct AdmittedFile {
    file: Option<File>,
    read: Option<JoinHandle<ReadResult>>,
    seek: Option<JoinHandle<SeekResult>>,
    buffer: Vec<u8>,
    offset: usize,
    admission: ResponseWorkAdmission,
    position: u64,
}

impl AdmittedFile {
    pub(crate) fn from_std(file: File) -> Self {
        Self {
            file: Some(file),
            read: None,
            seek: None,
            buffer: Vec::new(),
            offset: 0,
            admission: ResponseWorkAdmission::current(),
            position: 0,
        }
    }
}

impl AsyncRead for AdmittedFile {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.offset < this.buffer.len() {
                let count = output.remaining().min(this.buffer.len() - this.offset);
                output.put_slice(&this.buffer[this.offset..this.offset + count]);
                this.offset += count;
                return Poll::Ready(Ok(()));
            }
            if let Some(worker) = this.read.as_mut() {
                let (file, mut buffer, result) = match std::task::ready!(Pin::new(worker).poll(cx))
                {
                    Ok(result) => result,
                    Err(error) => {
                        this.read = None;
                        return Poll::Ready(Err(io::Error::other(error)));
                    }
                };
                this.read = None;
                this.file = Some(file);
                let count = result?;
                buffer.truncate(count);
                this.buffer = buffer;
                this.offset = 0;
                this.position += count as u64;
                if count == 0 {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }
            let Some(mut file) = this.file.take() else {
                return Poll::Ready(Err(io::Error::other("file operation already in progress")));
            };
            let capacity = output
                .remaining()
                .min(crate::http_contract::STREAM_BUFFER_BYTES);
            let mut buffer = std::mem::take(&mut this.buffer);
            buffer.resize(capacity, 0);
            this.read = Some(this.admission.spawn_blocking(move || {
                #[cfg(test)]
                {
                    use std::os::fd::AsRawFd as _;
                    crate::test_checkpoint::hit(&format!("file-read:{}", file.as_raw_fd()));
                }
                let result = file.read(&mut buffer);
                (file, buffer, result)
            }));
        }
    }
}

impl AsyncSeek for AdmittedFile {
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        let this = self.get_mut();
        if this.read.is_some() || this.seek.is_some() {
            return Err(io::Error::other("file operation already in progress"));
        }
        let position = match position {
            SeekFrom::Current(offset) => SeekFrom::Current(
                offset
                    .checked_sub((this.buffer.len() - this.offset) as i64)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "seek offset overflow")
                    })?,
            ),
            other => other,
        };
        let mut file = this
            .file
            .take()
            .ok_or_else(|| io::Error::other("file unavailable"))?;
        this.buffer.clear();
        this.offset = 0;
        this.seek = Some(this.admission.spawn_blocking(move || {
            #[cfg(test)]
            {
                use std::os::fd::AsRawFd as _;
                crate::test_checkpoint::hit(&format!("file-seek:{}", file.as_raw_fd()));
            }
            let result = file.seek(position);
            (file, result)
        }));
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let this = self.get_mut();
        let Some(worker) = this.seek.as_mut() else {
            return Poll::Ready(Ok(this.position - (this.buffer.len() - this.offset) as u64));
        };
        let (file, result) = match std::task::ready!(Pin::new(worker).poll(cx)) {
            Ok(result) => result,
            Err(error) => {
                this.seek = None;
                return Poll::Ready(Err(io::Error::other(error)));
            }
        };
        this.seek = None;
        this.file = Some(file);
        this.position = result?;
        Poll::Ready(Ok(this.position))
    }
}
