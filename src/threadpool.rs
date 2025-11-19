// src/threadpool.rs
use anyhow::Result;
use kanal::{Sender, bounded};
use std::thread;
use tracing::debug;

type SendType<J, R> = Sender<Option<(J, Sender<R>)>>;
pub struct ThreadPool<J, R> {
    workers: Vec<thread::JoinHandle<()>>,
    sender: Option<SendType<J, R>>,
}

impl<J, R> ThreadPool<J, R>
where
    J: Send + 'static,
    R: Send + 'static,
{
    /// Create a new `ThreadPool` with the specified number of workers
    /// and a worker function that processes jobs
    pub fn new<F>(size: usize, worker_fn: F) -> Self
    where
        F: Fn(J) -> R + Send + Sync + Clone + 'static,
    {
        let (sender, receiver) = bounded::<Option<(J, Sender<R>)>>(size * 2);
        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            let receiver = receiver.clone();
            let worker_fn = worker_fn.clone();

            let worker = thread::spawn(move || {
                debug!("Worker {} started", id);
                while let Ok(Some((job, result_sender))) = receiver.recv() {
                    let result = worker_fn(job);
                    let _ = result_sender.send(result);
                }
                debug!("Worker {} shutting down", id);
            });
            workers.push(worker);
        }

        Self {
            workers,
            sender: Some(sender),
        }
    }

    /// Execute a job and send the result to the provided sender
    pub fn execute(&self, job: J, result_sender: Sender<R>) -> Result<()> {
        self.sender
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ThreadPool has been shut down"))?
            .send(Some((job, result_sender)))
            .map_err(|e| anyhow::anyhow!("Failed to send job to worker thread: {}", e))
    }
}

impl<J, R> Drop for ThreadPool<J, R> {
    fn drop(&mut self) {
        // Drop the sender to signal workers to shut down
        drop(self.sender.take());

        // Wait for all workers to finish
        while let Some(worker) = self.workers.pop() {
            let _ = worker.join();
        }
    }
}
