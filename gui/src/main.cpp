/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026 Khadem Ullah
 */

#include "MainWindow.h"

#include <QApplication>

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    MainWindow window;

    if (argc > 1) {
        window.loadTraceFile(QString::fromLocal8Bit(argv[1]));
    }

    window.show();
    return app.exec();
}
