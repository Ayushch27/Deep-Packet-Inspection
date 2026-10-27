package com.dpi.processing;

import com.dpi.flow.FlowKey;
import com.dpi.model.PacketInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Manages a pool of worker threads to process packets concurrently.
 * Employs Flow-Aware Load Balancing to guarantee packets from the same flow
 * are consistently routed to the exact same thread, eliminating race conditions on Flow state.
 */
public class WorkerPool {
    private static final Logger logger = LoggerFactory.getLogger(WorkerPool.class);

    // Poison pill object used to signal workers to cleanly terminate
    private static final PacketInfo POISON_PILL = new PacketInfo.Builder().build();

    private final int workerCount;
    private final List<BlockingQueue<PacketInfo>> queues;
    private final ExecutorService executor;
    private final Consumer<PacketInfo> processor;

    public WorkerPool(int workerCount, int queueCapacity, Consumer<PacketInfo> processor) {
        this.workerCount = workerCount;
        this.processor = processor;
        this.queues = new ArrayList<>(workerCount);
        this.executor = Executors.newFixedThreadPool(workerCount);

        for (int i = 0; i < workerCount; i++) {
            BlockingQueue<PacketInfo> queue = new ArrayBlockingQueue<>(queueCapacity);
            queues.add(queue);
            executor.submit(createWorker(queue, i));
        }
        logger.info("Initialized WorkerPool with {} workers (Queue Capacity: {})", workerCount, queueCapacity);
    }

    private Runnable createWorker(BlockingQueue<PacketInfo> queue, int workerId) {
        return () -> {
            logger.debug("Worker-{} thread started.", workerId);
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    PacketInfo info = queue.take();
                    if (info == POISON_PILL) {
                        break;
                    }
                    try {
                        processor.accept(info);
                    } catch (Exception e) {
                        logger.error("Worker-{} failed to process packet", workerId, e);
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            logger.debug("Worker-{} thread terminated.", workerId);
        };
    }

    /**
     * Hashes the packet's 5-tuple and dispatches it to the corresponding worker queue.
     */
    public void dispatch(PacketInfo info) {
        if (info.getSrcIp() == null || info.getDstIp() == null) {
            // Un-trackable flows (like ARP) go to worker 0
            try {
                queues.get(0).put(info);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return;
        }

        int srcPort = info.getSrcPort() != null ? info.getSrcPort() : 0;
        int dstPort = info.getDstPort() != null ? info.getDstPort() : 0;

        // Using FlowKey guarantees A->B and B->A hash to the exact same worker
        FlowKey key = new FlowKey(info.getSrcIp(), info.getDstIp(), srcPort, dstPort, info.getProtocol());
        int hash = Math.abs(key.hashCode()) % workerCount;

        try {
            queues.get(hash).put(info);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Enqueues poison pills and blocks until all queues have been fully drained and threads terminate.
     */
    public void shutdownAndWait() {
        logger.info("Initiating graceful shutdown of WorkerPool...");
        try {
            for (BlockingQueue<PacketInfo> q : queues) {
                q.put(POISON_PILL);
            }
            executor.shutdown();
            if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
                logger.warn("WorkerPool did not terminate within 60 seconds. Forcing shutdown.");
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }
        logger.info("WorkerPool shutdown complete.");
    }
}
