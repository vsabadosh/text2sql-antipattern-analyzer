from __future__ import annotations

from pathlib import Path
from typing import Iterator, Dict, Any, Union, Optional
import csv

from text2sql_antipattern.core.contracts import Loader
from text2sql_antipattern.pipeline.registry import register_loader


@register_loader("csv")
class CsvLoader(Loader):
    """
    CSV Loader:
      - reads rows as dict (csv.DictReader)
      - if delimiter is not specified, tries to detect via csv.Sniffer
      - if has_header=False, generates column names: col_1, col_2, ...
    """

    def __init__(
        self,
        path: Union[str, Path],
        encoding: str = "utf-8",
        delimiter: Optional[str] = None,
        quotechar: Optional[str] = None,
        has_header: Optional[bool] = None,
        sniff_bytes: int = 4096,
    ) -> None:
        self.path = Path(path)
        self.encoding = encoding
        self.delimiter = delimiter
        self.quotechar = quotechar
        self.has_header = has_header
        self.sniff_bytes = sniff_bytes

        if not self.path.exists():
            raise FileNotFoundError(self.path)

    def load(self) -> Iterator[Dict[str, Any]]:
        with open(self.path, "rt", encoding=self.encoding, newline="") as f:
            sample = f.read(self.sniff_bytes)
            f.seek(0)

            dialect = None
            if self.delimiter is None:
                try:
                    dialect = csv.Sniffer().sniff(sample)
                except Exception:
                    dialect = None

            if self.has_header is None:
                try:
                    self.has_header = csv.Sniffer().has_header(sample)
                except Exception:
                    self.has_header = True

            reader_kwargs: Dict[str, Any] = {}
            if dialect is not None:
                reader_kwargs["dialect"] = dialect
            else:
                if self.delimiter is not None:
                    reader_kwargs["delimiter"] = self.delimiter
                if self.quotechar is not None:
                    reader_kwargs["quotechar"] = self.quotechar

            reader = csv.DictReader(f, **reader_kwargs)

            if self.has_header is False:
                if reader.fieldnames:
                    reader.fieldnames = [f"col_{i+1}" for i in range(len(reader.fieldnames))]

            for row in reader:
                yield dict(row)
