"""
Redis Streams ingestion adapter — near-real-time alert streaming.

Design:
- Producers (connectors) XADD alert payloads to a Redis Stream
- StreamConsumer reads with XREADGROUP for at-least-once delivery
- Back-pressure: consumer blocks (BLOCK=timeout) rather than busy-polling
- ACK on successful processing; failed messages go to PEL for retry
- Dead-letter handling after max_retries

Stream key convention:
    threaticap:alerts:{source_type}   e.g. threaticap:alerts:SIEM
    threaticap:alerts:all             unified ingestion stream

Consumer group: threaticap-pipeline

Kafka support follows the same interface — swap the Redis client for
a confluent-kafka consumer. The StreamProcessor interface is identical.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterator

logger = logging.getLogger(__name__)

try:
    import redis
    _HAS_REDIS = True
except ImportError:
    _HAS_REDIS = False
    logger.warning("redis-py not available — streaming ingestion disabled")

# Stream key for all alerts
DEFAULT_STREAM_KEY = "threaticap:alerts:all"
CONSUMER_GROUP = "threaticap-pipeline"


@dataclass
class StreamConfig:
    """Configuration for the Redis stream consumer."""
    redis_url: str = "redis://localhost:6379/0"
    redis_password: str | None = None
    stream_key: str = DEFAULT_STREAM_KEY
    consumer_group: str = CONSUMER_GROUP
    consumer_name: str = "worker-1"
    block_ms: int = 1000        # Block duration per XREADGROUP call
    batch_size: int = 50        # Max messages per read
    max_retries: int = 3        # Before dead-lettering
    process_timeout_seconds: int = 30
    # Back-pressure: pause if pipeline queue exceeds this
    max_queue_depth: int = 1000


class AlertStreamProducer:
    """
    Publishes raw alert payloads to a Redis stream.

    Usage (in a connector's streaming mode):
        producer = AlertStreamProducer(config)
        producer.publish(raw_alert_dict, source_type="SIEM")
    """

    def __init__(self, config: StreamConfig) -> None:
        if not _HAS_REDIS:
            raise RuntimeError("redis-py required for streaming: pip install redis")
        self._config = config
        self._client = redis.from_url(
            config.redis_url,
            password=config.redis_password,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
        )

    def publish(
        self,
        payload: dict[str, Any],
        source_type: str = "UNKNOWN",
        maxlen: int = 100_000,
    ) -> str:
        """
        Publish a raw alert payload to the stream.
        Returns the stream entry ID.
        """
        entry = {
            "payload": json.dumps(payload, default=str),
            "source_type": source_type,
            "published_at": datetime.now(timezone.utc).isoformat(),
        }
        msg_id = self._client.xadd(
            self._config.stream_key,
            entry,
            maxlen=maxlen,
            approximate=True,
        )
        logger.debug("Published to stream %s: id=%s", self._config.stream_key, msg_id)
        return msg_id

    def publish_batch(
        self,
        payloads: list[dict[str, Any]],
        source_type: str = "UNKNOWN",
    ) -> list[str]:
        """Publish multiple payloads using a pipeline for efficiency."""
        pipe = self._client.pipeline()
        for p in payloads:
            entry = {
                "payload": json.dumps(p, default=str),
                "source_type": source_type,
                "published_at": datetime.now(timezone.utc).isoformat(),
            }
            pipe.xadd(
                self._config.stream_key,
                entry,
                maxlen=100_000,
                approximate=True,
            )
        return pipe.execute()


class AlertStreamConsumer:
    """
    Consumes alert payloads from a Redis stream with at-least-once delivery.

    Back-pressure model:
    - If the downstream queue is full (>max_queue_depth), the consumer
      pauses reading until capacity is available.
    - This prevents runaway memory growth under burst load.
    """

    def __init__(
        self,
        config: StreamConfig,
        on_message: Callable[[dict[str, Any], str], None],
    ) -> None:
        """
        Args:
            config:     Stream configuration.
            on_message: Callback(payload_dict, source_type) for each message.
        """
        if not _HAS_REDIS:
            raise RuntimeError("redis-py required for streaming: pip install redis")
        self._config = config
        self._on_message = on_message
        self._stop_event = threading.Event()
        self._client = redis.from_url(
            config.redis_url,
            password=config.redis_password,
            decode_responses=True,
            socket_timeout=config.block_ms // 1000 + 5,
        )
        self._queue_depth = 0
        self._processed = 0
        self._errors = 0
        self._ensure_group()

    def _ensure_group(self) -> None:
        """Create consumer group if it doesn't exist."""
        try:
            self._client.xgroup_create(
                self._config.stream_key,
                self._config.consumer_group,
                id="0",  # Start from beginning for new groups
                mkstream=True,
            )
            logger.info(
                "Created consumer group %s on stream %s",
                self._config.consumer_group, self._config.stream_key
            )
        except Exception as exc:
            # BUSYGROUP = group already exists, which is fine
            if "BUSYGROUP" in str(exc):
                logger.debug("Consumer group already exists")
            else:
                logger.warning("Group creation warning: %s", exc)

    def start(self) -> None:
        """Start consuming in the current thread (blocks until stop() called)."""
        logger.info(
            "Stream consumer starting: %s / %s",
            self._config.stream_key, self._config.consumer_group
        )
        # First process any pending (unACKed) messages from previous run
        self._process_pending()

        while not self._stop_event.is_set():
            # Back-pressure check
            if self._queue_depth >= self._config.max_queue_depth:
                logger.warning(
                    "Back-pressure: queue depth %d >= %d, pausing 1s",
                    self._queue_depth, self._config.max_queue_depth
                )
                time.sleep(1)
                continue

            try:
                messages = self._client.xreadgroup(
                    self._config.consumer_group,
                    self._config.consumer_name,
                    {self._config.stream_key: ">"},  # ">" = new messages only
                    count=self._config.batch_size,
                    block=self._config.block_ms,
                )
                if messages:
                    self._process_messages(messages)
            except Exception as exc:
                self._errors += 1
                logger.error("Stream read error: %s", exc, exc_info=True)
                time.sleep(1)

    def start_background(self) -> threading.Thread:
        """Start consuming in a background daemon thread."""
        thread = threading.Thread(
            target=self.start,
            name=f"stream-consumer-{self._config.consumer_name}",
            daemon=True,
        )
        thread.start()
        return thread

    def stop(self) -> None:
        self._stop_event.set()
        logger.info("Stream consumer stop requested")

    def _process_messages(
        self, messages: list[tuple[str, list[tuple[str, dict[str, str]]]]]
    ) -> None:
        for stream_name, entries in messages:
            for msg_id, fields in entries:
                self._queue_depth += 1
                try:
                    payload_str = fields.get("payload", "{}")
                    source_type = fields.get("source_type", "UNKNOWN")
                    payload = json.loads(payload_str)

                    self._on_message(payload, source_type)

                    # ACK on success
                    self._client.xack(
                        self._config.stream_key,
                        self._config.consumer_group,
                        msg_id,
                    )
                    self._processed += 1
                    logger.debug("Processed and ACKed message %s", msg_id)

                except Exception as exc:
                    self._errors += 1
                    logger.error(
                        "Error processing message %s: %s", msg_id, exc, exc_info=True
                    )
                    # Do NOT ACK — message stays in PEL for retry
                finally:
                    self._queue_depth -= 1

    def _process_pending(self) -> None:
        """
        Process Pending Entry List (PEL) — messages that were delivered
        but not ACKed in a previous session (crash recovery).
        """
        try:
            pending = self._client.xpending_range(
                self._config.stream_key,
                self._config.consumer_group,
                min="-",
                max="+",
                count=100,
                consumername=self._config.consumer_name,
            )
            if not pending:
                return

            logger.info("Processing %d pending (unACKed) messages", len(pending))
            for entry in pending:
                msg_id = entry["message_id"]
                delivery_count = entry.get("times_delivered", 0)

                if delivery_count > self._config.max_retries:
                    logger.warning(
                        "Dead-lettering message %s (delivery_count=%d)",
                        msg_id, delivery_count
                    )
                    self._dead_letter(msg_id)
                    continue

                # Claim and reprocess
                claimed = self._client.xclaim(
                    self._config.stream_key,
                    self._config.consumer_group,
                    self._config.consumer_name,
                    min_idle_time=0,
                    message_ids=[msg_id],
                )
                if claimed:
                    self._process_messages(
                        [(self._config.stream_key, [(msg_id, claimed[0][1])])]
                    )
        except Exception as exc:
            logger.warning("PEL processing error: %s", exc)

    def _dead_letter(self, msg_id: str) -> None:
        """Move failed message to dead-letter stream and ACK from main stream."""
        try:
            # Get message data
            msgs = self._client.xrange(
                self._config.stream_key, min=msg_id, max=msg_id, count=1
            )
            if msgs:
                _, fields = msgs[0]
                self._client.xadd(
                    f"{self._config.stream_key}:dead-letter",
                    {**fields, "dead_lettered_at": datetime.now(timezone.utc).isoformat()},
                )
            self._client.xack(
                self._config.stream_key,
                self._config.consumer_group,
                msg_id,
            )
        except Exception as exc:
            logger.error("Dead-letter failed for %s: %s", msg_id, exc)

    @property
    def stats(self) -> dict[str, int]:
        return {
            "processed": self._processed,
            "errors": self._errors,
            "queue_depth": self._queue_depth,
        }


class StreamingIngestionManager:
    """
    High-level manager that connects a Redis stream consumer to the
    IngestionPipeline, providing a continuous near-real-time processing path.

    Architecture:
        Redis Stream -> StreamConsumer -> IngestionPipeline -> ThreatPipeline
                                                              (batch accumulator)

    The batch accumulator collects alerts until either:
    - batch_size alerts are queued, OR
    - flush_interval_seconds has elapsed
    Then fires the pipeline on the accumulated batch.
    """

    def __init__(
        self,
        stream_config: StreamConfig,
        connector_factory: Callable[[str], Any],  # source_type -> BaseConnector
        pipeline_callback: Callable[[list[Any]], None],
        batch_size: int = 20,
        flush_interval_seconds: float = 5.0,
    ) -> None:
        self._connector_factory = connector_factory
        self._pipeline_callback = pipeline_callback
        self._batch_size = batch_size
        self._flush_interval = flush_interval_seconds
        self._pending: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._last_flush = time.time()

        self._consumer = AlertStreamConsumer(
            config=stream_config,
            on_message=self._handle_message,
        )

        # Periodic flush thread
        self._flush_thread = threading.Thread(
            target=self._flush_loop, daemon=True, name="stream-flusher"
        )

    def start(self) -> None:
        self._flush_thread.start()
        self._consumer.start()  # Blocks

    def start_background(self) -> list[threading.Thread]:
        self._flush_thread.start()
        t = self._consumer.start_background()
        return [t, self._flush_thread]

    def stop(self) -> None:
        self._consumer.stop()

    def _handle_message(self, payload: dict[str, Any], source_type: str) -> None:
        """Called for each stream message — accumulates into pending batch."""
        with self._lock:
            self._pending.append({"payload": payload, "source_type": source_type})
            if len(self._pending) >= self._batch_size:
                self._flush()

    def _flush_loop(self) -> None:
        """Periodically flush pending alerts regardless of batch size."""
        while True:
            time.sleep(0.5)
            elapsed = time.time() - self._last_flush
            if elapsed >= self._flush_interval:
                with self._lock:
                    if self._pending:
                        self._flush()

    def _flush(self) -> None:
        """Flush pending alerts to pipeline. Must be called with self._lock held."""
        if not self._pending:
            return
        batch = self._pending.copy()
        self._pending.clear()
        self._last_flush = time.time()

        try:
            self._pipeline_callback(batch)
            logger.info("Stream flush: processed %d alert(s)", len(batch))
        except Exception as exc:
            logger.error("Stream flush error: %s", exc, exc_info=True)
