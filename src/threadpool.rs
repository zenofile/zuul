// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2025 zenofile <zenofile-sf6@unsha.re>

use std::thread;

use anyhow::Result;
use kanal::{Sender, bounded};
use tracing::trace;

pub struct ThreadPool<J, R> {
    pub workers: Vec<thread::JoinHandle<()>>,
    pub sender: Option<Sender<(J, Sender<R>)>>,
}

impl<J, R> ThreadPool<J, R>
where
    J: Send + 'static,
    R: Send + 'static,
{
    /// Create a new `ThreadPool` with the specified number of workers
    /// and a worker function that processes jobs
    pub fn new<F>(size: std::num::NonZeroUsize, worker_fn: F) -> Self
    where
        F: Fn(J) -> R + Send + Sync + Clone + 'static,
    {
        let num = size.get();
        let (sender, receiver) = bounded::<(J, Sender<R>)>(num * 2);
        let mut workers = Vec::with_capacity(num);

        for id in 0..num {
            let receiver = receiver.clone();
            let worker_fn = worker_fn.clone();

            let worker = thread::Builder::new()
                .name(format!("worker-{}", id))
                .spawn(move || {
                    trace!("Worker {} started", id);
                    while let Ok((job, result_sender)) = receiver.recv() {
                        let result = worker_fn(job);
                        let _ = result_sender.send(result);
                    }
                    trace!("Worker {} shutting down", id);
                })
                .expect("Failed to spawn worker thread");
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
            .send((job, result_sender))
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
