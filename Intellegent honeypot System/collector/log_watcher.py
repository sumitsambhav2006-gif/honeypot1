import os
import sys
import time
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from config.settings import settings
from config.logging_config import setup_logging
from collector.json_parser import JSONParser
from collector.event_normalizer import EventNormalizer
from collector.event_collector import EventCollector

logger = setup_logging("ihtip-log-watcher")

class LogWatcher:
    """Tails Cowrie JSON logs continuously and feeds events into the ingestion pipeline."""

    def __init__(self, log_path: Path = None):
        self.log_path = log_path or settings.COWRIE_LOG_PATH
        self.offset_file = settings.BASE_DIR / "data" / "watcher_offset.txt"
        self.parser = JSONParser()
        self.normalizer = EventNormalizer()
        self.collector = EventCollector()
        self.running = False

    def _read_saved_offset(self) -> int:
        if self.offset_file.exists():
            try:
                return int(self.offset_file.read_text(encoding="utf-8").strip())
            except Exception:
                return 0
        return 0

    def _save_offset(self, offset: int):
        try:
            self.offset_file.parent.mkdir(parents=True, exist_ok=True)
            self.offset_file.write_text(str(offset), encoding="utf-8")
        except Exception:
            pass

    def process_file_from_start(self):
        """Processes any unread backlog records from last saved offset."""
        if not self.log_path.exists():
            logger.info(f"Log file {self.log_path} does not exist yet. Waiting for honeypot to generate logs...")
            return 0

        file_size = self.log_path.stat().st_size
        offset = self._read_saved_offset()
        if offset > file_size:
            offset = 0

        count = 0
        with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(offset)
            for line in f:
                raw = self.parser.parse_line(line)
                if raw:
                    normalized = self.normalizer.normalize(raw)
                    if normalized:
                        self.collector.process_normalized_event(normalized)
                        count += 1
            self._save_offset(f.tell())

        logger.info(f"Processed {count} new backlog events from {self.log_path.name}.")
        return count

    def tail_forever(self, poll_interval: float = 0.2):
        """Continuous tailing loop (equivalent to tail -f)."""
        self.running = True
        logger.info(f"[*] Starting LogWatcher on: {self.log_path}")

        # Ensure file exists
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.exists():
            self.log_path.touch()

        with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
            # Resume from saved offset so no events written during startup are missed
            saved_offset = self._read_saved_offset()
            file_size = self.log_path.stat().st_size
            if 0 <= saved_offset <= file_size:
                f.seek(saved_offset)
            else:
                f.seek(0, os.SEEK_END)
            self._save_offset(f.tell())

            while self.running:
                line = f.readline()
                if not line:
                    # Handle log rotation / truncation
                    if self.log_path.exists() and self.log_path.stat().st_size < f.tell():
                        f.seek(0)
                    time.sleep(poll_interval)
                    continue

                raw = self.parser.parse_line(line)
                if raw:
                    normalized = self.normalizer.normalize(raw)
                    if normalized:
                        evt_id = self.collector.process_normalized_event(normalized)
                        logger.info(f"[+] Ingested event {normalized['event_type']} from {normalized['source_ip']} (ID: {evt_id})")
                self._save_offset(f.tell())

    def stop(self):
        self.running = False

if __name__ == "__main__":
    watcher = LogWatcher()
    # Process backlog
    watcher.process_file_from_start()
    # Follow new lines
    try:
        watcher.tail_forever()
    except KeyboardInterrupt:
        logger.info("LogWatcher stopped by user.")

