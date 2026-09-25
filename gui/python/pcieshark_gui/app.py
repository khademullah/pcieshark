from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from .window import MainWindow


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv
    app = QApplication(args)
    app.setApplicationName("pcieshark")
    window = MainWindow()
    if len(args) > 1:
        window.load_trace(args[1])
    window.show()
    return app.exec()
