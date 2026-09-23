#include "MainWindow.h"

#include "pcapcie/pcapcie.h"
#include "pcapcie/tlp.h"

#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QSortFilterProxyModel>
#include <QDebug>
#include <QDateTime>
#include <QProcess>
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStandardPaths>
#include <QTemporaryFile>

#include <algorithm>

namespace {

void stopProcessAndDelete(QProcess *process)
{
    if (!process) {
        return;
    }

    if (process->state() != QProcess::NotRunning) {
        process->terminate();
        if (!process->waitForFinished(2000)) {
            process->kill();
            process->waitForFinished();
        }
    }

    process->deleteLater();
}

bool parseRawTraceLine(const QString &line,
                       QString *ts,
                       QString *direction,
                       QString *type,
                       QString *requester,
                       QString *completer,
                       QString *tag,
                       QString *length,
                       QString *addr,
                       QString *payload);

QString normalizeDirection(const QString &value)
{
    QString v = value.trimmed().toUpper();
    if (v == "TX" || v == "1") return "TX";
    if (v == "RX" || v == "2") return "RX";
    return v;
}

QString decodeTypeName(const QString &value)
{
    const QString v = value.trimmed();
    if (v == "0") return "MemRd";
    if (v == "1") return "MemWr";
    if (v == "4") return "CfgRd";
    if (v == "5") return "CfgWr";
    if (v == "10") return "Cpl";
    return v.isEmpty() ? "Unknown" : v;
}

QString sanitizeType(const QString &value)
{
    return decodeTypeName(value);
}

QString formatHexDump(const QString &payload)
{
    QString normalized = payload.trimmed();
    normalized.remove(' ');
    normalized.remove('\t');
    normalized.remove('\n');
    normalized.remove('\r');

    if (normalized.isEmpty()) {
        return "<no payload>";
    }

    QByteArray bytes = QByteArray::fromHex(normalized.toLatin1());
    if (bytes.isEmpty() && !normalized.isEmpty()) {
        return QString("%1\n<not valid hex payload>").arg(normalized);
    }

    QStringList lines;
    for (int i = 0; i < bytes.size(); i += 16) {
        QByteArray chunk = bytes.mid(i, 16);
        QString hex;
        QString ascii;
        for (int j = 0; j < chunk.size(); ++j) {
            const unsigned char value = static_cast<unsigned char>(chunk.at(j));
            hex += QString("%1 ").arg(value, 2, 16, QLatin1Char('0'));
            ascii += (value >= 0x20 && value <= 0x7e) ? QChar(value) : '.';
        }
        while (hex.size() < 48) {
            hex += "   ";
        }
        lines << QString("%1  %2  %3").arg(i, 4, 16, QLatin1Char('0')).arg(hex).arg(ascii);
    }
    return lines.join("\n");
}

void summarizeTraceFile(const QString &path,
                        int *totalEntries,
                        int *txCount,
                        int *rxCount,
                        double *firstTs,
                        double *lastTs)
{
    if (totalEntries) *totalEntries = 0;
    if (txCount) *txCount = 0;
    if (rxCount) *rxCount = 0;
    if (firstTs) *firstTs = 0.0;
    if (lastTs) *lastTs = 0.0;

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return;
    }

    QTextStream stream(&file);
    QString line;
    int total = 0;
    int tx = 0;
    int rx = 0;
    double first = 0.0;
    double last = 0.0;
    bool firstSet = false;

    while (!stream.atEnd()) {
        line = stream.readLine().trimmed();
        if (line.isEmpty()) {
            continue;
        }

        QString ts, dir, type, requester, completer, tag, length, addr, payload;
        if (!parseRawTraceLine(line, &ts, &dir, &type, &requester, &completer, &tag, &length, &addr, &payload)) {
            continue;
        }

        const double tsValue = ts.toDouble();
        if (!firstSet || tsValue < first) {
            first = tsValue;
        }
        if (!firstSet || tsValue > last) {
            last = tsValue;
        }
        firstSet = true;

        ++total;
        if (dir == "TX") {
            ++tx;
        } else if (dir == "RX") {
            ++rx;
        }
    }

    file.close();

    if (totalEntries) *totalEntries = total;
    if (txCount) *txCount = tx;
    if (rxCount) *rxCount = rx;
    if (firstTs) *firstTs = first;
    if (lastTs) *lastTs = last;
}

void summarizeModelRows(QStandardItemModel *model,
                        int *totalEntries,
                        int *txCount,
                        int *rxCount,
                        double *firstTs,
                        double *lastTs)
{
    if (!model) {
        return;
    }

    if (totalEntries) *totalEntries = model->rowCount();
    int tx = 0;
    int rx = 0;
    double first = 0.0;
    double last = 0.0;
    bool firstSet = false;

    for (int row = 0; row < model->rowCount(); ++row) {
        const QString direction = model->index(row, 1).data().toString();
        if (direction == "TX") {
            ++tx;
        } else if (direction == "RX") {
            ++rx;
        }

        const QString tsText = model->index(row, 0).data().toString();
        const double tsValue = tsText.toDouble();
        if (!tsText.isEmpty()) {
            if (!firstSet || tsValue < first) first = tsValue;
            if (!firstSet || tsValue > last) last = tsValue;
            firstSet = true;
        }
    }

    if (txCount) *txCount = tx;
    if (rxCount) *rxCount = rx;
    if (firstTs) *firstTs = first;
    if (lastTs) *lastTs = last;
}

QString pciVendorName(uint16_t vendorId)
{
    switch (vendorId) {
        case 0x10EC: return "Realtek";
        case 0x8086: return "Intel";
        case 0x14E4: return "Broadcom";
        case 0x1AF4: return "Red Hat, Inc.";
        case 0x10DE: return "NVIDIA";
        case 0x10B5: return "PLX";
        default: return "Unknown vendor";
    }
}

QString pciClassName(uint32_t classCode)
{
    switch ((classCode >> 8) & 0xFFFFFF) {
        case 0x020000: return "Ethernet controller";
        case 0x010000: return "SCSI controller";
        case 0x0C0300: return "USB controller";
        case 0x060000: return "Bridge device";
        case 0x030000: return "VGA compatible controller";
        default: return "Unknown class";
    }
}

QString makeHexLabel(uint32_t value, int width)
{
    return QString("0x%1").arg(value, width, 16, QLatin1Char('0')).toUpper();
}

QStringList extractPcieLsEntries(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return {};
    }

    QStringList entries;
    QTextStream stream(&file);
    while (!stream.atEnd()) {
        const QString line = stream.readLine().trimmed();
        if (line.isEmpty()) {
            continue;
        }

        static const QRegularExpression pcieLsRe(
            QStringLiteral(R"(^\d+:\d+\.\d+\s+ID\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}\b.*$)"));

        if (pcieLsRe.match(line).hasMatch()) {
            entries << line;
        }
    }
    return entries;
}

QString cellHtml(const QString &title, const QString &sub, const QString &body)
{
    return QStringLiteral(
               "<td align='center' style='border:1px solid #b7bec9;padding:8px;vertical-align:top;'>"
               "<div style='font-weight:bold;'>[%1]</div>"
               "<div style='font-size:12px;opacity:0.9;'>%2</div>"
               "<div>%3</div></td>")
        .arg(title.toHtmlEscaped(), sub.toHtmlEscaped(), body.toHtmlEscaped());
}

QString tableRow(const QString &cells)
{
    if (cells.isEmpty()) {
        return QString();
    }
    return QStringLiteral("<table width='100%' style='border-spacing:8px 6px;'><tr>%1</tr></table>").arg(cells);
}

QJsonObject defaultRootPort(int index)
{
    const int dev = 1 + (index / 8);
    const int fn = index % 8;
    QJsonObject rp;
    rp.insert("id", QString("rp%1").arg(index + 1));
    rp.insert("addr", QString("%1.%2").arg(dev, 2, 16, QLatin1Char('0')).arg(fn));
    rp.insert("bdf", QString("00:%1.%2").arg(dev, 2, 16, QLatin1Char('0')).arg(fn));
    rp.insert("label", QString("Root Port %1").arg(index + 1));
    return rp;
}

QString buildTopologyHtmlFromJson(const QJsonObject &topo)
{
    const QString name = topo.value("topology_name").toString("unnamed topology");
    const QJsonArray rcs = topo.value("root_complexes").toArray();
    const QJsonArray switches = topo.value("switches").toArray();
    const QJsonArray endpoints = topo.value("endpoints").toArray();

    QString rcLabel = QStringLiteral("CPU Complex");
    QString busLabel = QStringLiteral("PCIe Bus 00");
    QString rpCells;
    QString swCells;
    QString dpCells;
    QString epCells;

    for (const QJsonValue &rcv : rcs) {
        const QJsonObject rc = rcv.toObject();
        if (!rc.value("label").toString().isEmpty()) {
            rcLabel = rc.value("label").toString();
        }
        if (!rc.value("root_bus").toString().isEmpty()) {
            busLabel = QStringLiteral("PCIe Bus ") + rc.value("root_bus").toString();
        }
        const QJsonArray ports = rc.value("root_ports").toArray();
        for (int i = 0; i < ports.size(); ++i) {
            QString id = QString("rp%1").arg(i + 1);
            QString bdf;
            QString label;
            QString sec;
            if (ports.at(i).isString()) {
                bdf = ports.at(i).toString();
            } else {
                const QJsonObject p = ports.at(i).toObject();
                id = p.value("id").toString(id);
                bdf = p.value("bdf").toString(p.value("addr").toString());
                label = p.value("label").toString();
                sec = p.value("secondary_bus").toString();
            }
            QString sub = bdf;
            if (!sec.isEmpty()) {
                sub += QStringLiteral("  Bus ") + sec;
            }
            rpCells += cellHtml(id, sub, label);
        }
    }

    for (const QJsonValue &swv : switches) {
        const QJsonObject sw = swv.toObject();
        const QString swName = sw.value("name").toString("switch");
        const QString up = sw.value("upstream_port").toString();
        const QString parent = sw.value("parent").toString();
        swCells += cellHtml(swName + QStringLiteral("_up"), up, parent);
        const QJsonArray dps = sw.value("downstream_ports").toArray();
        for (int d = 0; d < dps.size(); ++d) {
            dpCells += QStringLiteral(
                           "<td align='center' style='border:1px solid #9aa4b2;padding:6px;'>"
                           "[%1 dp%2]<div style='font-size:12px;opacity:0.9;'>%3</div></td>")
                           .arg(swName.toHtmlEscaped())
                           .arg(d)
                           .arg(dps.at(d).toString().toHtmlEscaped());
        }
    }

    for (const QJsonValue &epv : endpoints) {
        const QJsonObject ep = epv.toObject();
        const QString display = ep.value("display").toString(ep.value("label").toString("endpoint"));
        const QString bdf = ep.value("bdf").toString();
        const QString label = ep.value("label").toString();
        const QString type = ep.value("type").toString();
        epCells += cellHtml(display, bdf.isEmpty() ? type : bdf, label);
    }

    return QStringLiteral(
               "<html><body style='background:#0f1117;color:#e7ebf3;font-family:monospace;'>"
               "<div style='padding:8px;'>"
               "<div style='text-align:center;font-weight:bold;font-size:18px;padding:8px;'>[ %1 ]</div>"
               "<div style='text-align:center;font-size:14px;padding-bottom:4px;'>[ %2 ]</div>"
               "<div style='text-align:center;font-size:12px;opacity:0.85;padding-bottom:10px;'>%3</div>"
               "%4"
               "<div style='border-top:2px solid #dfe5ee; margin:10px 0;'></div>"
               "%5%6%7"
               "</div></body></html>")
        .arg(rcLabel.toHtmlEscaped(),
             busLabel.toHtmlEscaped(),
             name.toHtmlEscaped(),
             tableRow(rpCells),
             tableRow(swCells),
             tableRow(dpCells),
             tableRow(epCells));
}

void appendCfgReadRows(QStandardItemModel *model, const QString &bdf, const QString &role)
{
    static const uint64_t enumAddrs[] = {0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c};
    for (size_t i = 0; i < sizeof(enumAddrs) / sizeof(enumAddrs[0]); ++i) {
        const QString ts = QString::number(QDateTime::currentMSecsSinceEpoch()) + QString(".%1").arg(i);
        const QList<QStandardItem *> items = {
            new QStandardItem(ts),
            new QStandardItem("TX"),
            new QStandardItem("CfgRd"),
            new QStandardItem(bdf.isEmpty() ? QStringLiteral("0") : bdf),
            new QStandardItem("0"),
            new QStandardItem(QString::number(static_cast<int>(i))),
            new QStandardItem("4"),
            new QStandardItem(QString("0x%1").arg(enumAddrs[i], 0, 16)),
            new QStandardItem(role)
        };
        model->appendRow(items);
    }
}

} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , aiEmulatorDialog(nullptr)
    , pcieLsDialog(nullptr)
    , liveTraceTimer(nullptr)
    , liveTraceProcess(nullptr)
    , aiTopologyView(nullptr)
    , aiTopologyPathLabel(nullptr)
    , suppressAiRunnerExitWarning(false)
{
    QWidget *central = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(central);
    QHBoxLayout *toolbar = new QHBoxLayout();

    darkMode = false;

    openButton = new QPushButton("Open trace", this);
    saveButton = new QPushButton("Save trace", this);
    enumerateButton = new QPushButton("Enumerate PCI", this);
    aiPerfButton = new QPushButton("AI PCIe Emulator", this);
    themeButton = new QPushButton("Dark", this);
    typeFilter = new QComboBox(this);
    directionFilter = new QComboBox(this);
    backendFilter = new QComboBox(this);
    deviceIdBox = new QLineEdit(this);
    scenarioBox = new QLineEdit(this);
    searchBox = new QLineEdit(this);
    statusLabel = new QLabel("No trace loaded", this);
    totalLabel = new QLabel("Total: 0", this);
    txLabel = new QLabel("TX: 0", this);
    rxLabel = new QLabel("RX: 0", this);
    filteredLabel = new QLabel("Visible: 0", this);

    typeFilter->addItem("All types");
    typeFilter->addItem("CfgRd");
    typeFilter->addItem("CfgWr");
    typeFilter->addItem("MemRd");
    typeFilter->addItem("MemWr");
    typeFilter->addItem("Cpl");

    directionFilter->addItem("All directions");
    directionFilter->addItem("TX");
    directionFilter->addItem("RX");

    backendFilter->addItem("pci");
    backendFilter->addItem("golden");
    backendFilter->addItem("dummy");
    backendFilter->addItem("fpga");
    backendFilter->addItem("armds");
    backendFilter->addItem("xgig");
    backendFilter->setCurrentText("golden");

    deviceIdBox->setPlaceholderText("PCI device (default: 0000:00:03.0)");
    deviceIdBox->setText("0000:00:03.0");
    scenarioBox->setPlaceholderText("Golden profile: gen8x16, latency=250ns, tps=250000");
    scenarioBox->setText("gen8x16,latency=250ns,tps=250000,burst=16,jitter=50ns");
    searchBox->setPlaceholderText("Filter by requester ID or address");

    toolbar->addWidget(openButton);
    toolbar->addWidget(saveButton);
    toolbar->addWidget(enumerateButton);
    toolbar->addWidget(aiPerfButton);
    toolbar->addWidget(themeButton);
    toolbar->addWidget(new QLabel("Backend:", this));
    toolbar->addWidget(backendFilter);
    toolbar->addWidget(new QLabel("Device:", this));
    toolbar->addWidget(deviceIdBox);
    toolbar->addWidget(new QLabel("Scenario:", this));
    toolbar->addWidget(scenarioBox);
    toolbar->addWidget(new QLabel("Type:", this));
    toolbar->addWidget(typeFilter);
    toolbar->addWidget(new QLabel("Direction:", this));
    toolbar->addWidget(directionFilter);
    toolbar->addWidget(searchBox);

    QWidget *statsWidget = new QWidget(this);
    QHBoxLayout *statsLayout = new QHBoxLayout(statsWidget);
    statsLayout->setContentsMargins(0, 0, 0, 0);
    statsLayout->setSpacing(12);

    totalLabel->setFrameShape(QFrame::StyledPanel);
    txLabel->setFrameShape(QFrame::StyledPanel);
    rxLabel->setFrameShape(QFrame::StyledPanel);
    filteredLabel->setFrameShape(QFrame::StyledPanel);

    totalLabel->setAlignment(Qt::AlignCenter);
    txLabel->setAlignment(Qt::AlignCenter);
    rxLabel->setAlignment(Qt::AlignCenter);
    filteredLabel->setAlignment(Qt::AlignCenter);

    totalLabel->setMinimumWidth(120);
    txLabel->setMinimumWidth(120);
    rxLabel->setMinimumWidth(120);
    filteredLabel->setMinimumWidth(140);

    statsLayout->addWidget(totalLabel);
    statsLayout->addWidget(txLabel);
    statsLayout->addWidget(rxLabel);
    statsLayout->addWidget(filteredLabel);

    tableView = new QTableView(this);
    detailsView = new QTextEdit(this);
    detailsView->setReadOnly(true);
    detailsView->setPlaceholderText("Select a packet to inspect details");
    detailsView->setMinimumHeight(120);

    decodeTree = new QTreeWidget(this);
    decodeTree->setHeaderLabels({"Field", "Value"});
    decodeTree->setColumnWidth(0, 220);
    decodeTree->setAlternatingRowColors(true);
    decodeTree->setMinimumHeight(150);

    QSplitter *detailsSplitter = new QSplitter(Qt::Vertical, this);
    detailsSplitter->addWidget(detailsView);
    detailsSplitter->addWidget(decodeTree);
    detailsSplitter->setStretchFactor(0, 2);
    detailsSplitter->setStretchFactor(1, 1);

    model = new QStandardItemModel(this);
    model->setHorizontalHeaderLabels({
        "Timestamp",
        "Direction",
        "Type",
        "Requester",
        "Completer",
        "Tag",
        "Length",
        "Addr",
        "Payload"
    });

    tableView->setModel(model);
    tableView->horizontalHeader()->setStretchLastSection(true);
    tableView->setAlternatingRowColors(true);
    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableView->setSelectionMode(QAbstractItemView::SingleSelection);
    tableView->setSortingEnabled(false);

    splitter = new QSplitter(Qt::Vertical, this);
    splitter->addWidget(tableView);
    splitter->addWidget(detailsSplitter);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);

    layout->addLayout(toolbar);
    layout->addWidget(statsWidget);
    layout->addWidget(splitter);
    layout->addWidget(statusLabel);

    setCentralWidget(central);
    setWindowTitle("pcieshark");
    resize(1100, 700);

    applyTheme();

    openButton->setObjectName("openButton");
    themeButton->setObjectName("themeButton");
    statusLabel->setObjectName("statusLabel");
    totalLabel->setObjectName("summaryCard");
    txLabel->setObjectName("summaryCard");
    rxLabel->setObjectName("summaryCard");
    filteredLabel->setObjectName("summaryCard");

    connect(openButton, &QPushButton::clicked, this, &MainWindow::openTrace);
    connect(saveButton, &QPushButton::clicked, this, &MainWindow::saveTrace);
    connect(enumerateButton, &QPushButton::clicked, this, &MainWindow::enumeratePciDevice);
    connect(aiPerfButton, &QPushButton::clicked, this, &MainWindow::openAiPerfDialog);
    connect(themeButton, &QPushButton::clicked, this, [this]() {
        darkMode = !darkMode;
        applyTheme();
    });
    connect(typeFilter, &QComboBox::currentTextChanged, this, &MainWindow::applyFilter);
    connect(directionFilter, &QComboBox::currentTextChanged, this, &MainWindow::applyFilter);
    connect(searchBox, &QLineEdit::textChanged, this, &MainWindow::applyFilter);
    connect(tableView->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &MainWindow::showPacketDetails);
}

void MainWindow::applyTheme()
{
    if (darkMode) {
        setStyleSheet(R"(
            QMainWindow {
                background: #0f172a;
                color: #e2e8f0;
            }
            QWidget {
                font-family: "Segoe UI", "Noto Sans", sans-serif;
                color: #e2e8f0;
            }
            QVBoxLayout, QHBoxLayout {
                spacing: 8px;
            }
            QPushButton {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 12px;
                color: #e2e8f0;
                min-height: 28px;
            }
            QPushButton:hover {
                background: #243244;
            }
            QPushButton#openButton {
                background: #2563eb;
                border: 1px solid #2563eb;
                color: #ffffff;
                font-weight: 600;
            }
            QPushButton#themeButton {
                background: #232f3e;
            }
            QComboBox, QLineEdit, QTextEdit {
                background: #111827;
                color: #e2e8f0;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 10px;
                selection-background-color: #1d4ed8;
                selection-color: #ffffff;
            }
            QTableView {
                background: #0b1220;
                alternate-background-color: #111827;
                color: #e2e8f0;
                border: 1px solid #334155;
                gridline-color: #273548;
                selection-background-color: #1d4ed8;
                selection-color: #ffffff;
                font-size: 12px;
            }
            QTableView::item {
                padding: 4px 6px;
                border: 0px;
                background: #0b1220;
                color: #e2e8f0;
            }
            QTableView::item:alternate {
                background: #111827;
            }
            QTableView::item:selected {
                background: #1d4ed8;
                color: #ffffff;
                border: 1px solid #60a5fa;
            }
            QHeaderView::section {
                background: #172033;
                color: #e2e8f0;
                padding: 8px 6px;
                font-weight: 600;
                border: 1px solid #334155;
            }
            QSplitter::handle {
                background: #334155;
            }
            QTextEdit {
                background: #0f172a;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 8px;
            }
            QTreeWidget {
                background: #0b1220;
                alternate-background-color: #111827;
                color: #e2e8f0;
                border: 1px solid #334155;
                border-radius: 6px;
                selection-background-color: #1d4ed8;
                selection-color: #ffffff;
            }
            QTreeWidget::item {
                color: #e2e8f0;
                background: transparent;
                border: none;
                padding: 4px 2px;
            }
            QTreeWidget::item:selected {
                background: #1d4ed8;
                color: #ffffff;
                border: 1px solid #60a5fa;
            }
            QLabel#statusLabel {
                background: transparent;
                color: #94a3b8;
                padding-top: 4px;
                font-size: 12px;
            }
            QLabel#summaryCard {
                background: #111827;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 8px 10px;
                min-height: 38px;
                font-weight: 600;
                color: #e2e8f0;
            }
        )");
        themeButton->setText("Light");
    } else {
        setStyleSheet(R"(
            QMainWindow {
                background: #f3f4f6;
                color: #1f2328;
            }
            QWidget {
                font-family: "Segoe UI", "Noto Sans", sans-serif;
                color: #1f2328;
            }
            QVBoxLayout, QHBoxLayout {
                spacing: 8px;
            }
            QPushButton {
                background: #ffffff;
                border: 1px solid #d0d7de;
                border-radius: 6px;
                padding: 6px 12px;
                color: #1f2328;
                min-height: 28px;
            }
            QPushButton:hover {
                background: #f6f8fa;
                border-color: #b6c2cf;
            }
            QPushButton:pressed {
                background: #eaeef2;
            }
            QPushButton#openButton {
                background: #2f6feb;
                border: 1px solid #2f6feb;
                color: #ffffff;
                font-weight: 600;
            }
            QPushButton#themeButton {
                background: #ffffff;
            }
            QComboBox, QLineEdit, QTextEdit {
                background: #ffffff;
                color: #1f2328;
                border: 1px solid #d0d7de;
                border-radius: 6px;
                padding: 6px 10px;
                selection-background-color: #cfe2ff;
                selection-color: #1f2328;
            }
            QTableView {
                background: #fbfbfc;
                alternate-background-color: #f2f5f8;
                color: #1f2328;
                border: 1px solid #d0d7de;
                gridline-color: #dfe3e8;
                selection-background-color: #dfeaff;
                selection-color: #1f2328;
                font-size: 12px;
            }
            QTableView::item {
                padding: 4px 6px;
                border: 0px;
                background: #fbfbfc;
                color: #1f2328;
            }
            QTableView::item:alternate {
                background: #f2f5f8;
            }
            QTableView::item:selected {
                background: #dfeaff;
                color: #1f2328;
                border: 1px solid #93c5fd;
            }
            QHeaderView::section {
                background: #e9edf3;
                color: #1f2328;
                padding: 8px 6px;
                font-weight: 600;
                border: 1px solid #d0d7de;
            }
            QLabel {
                color: #1f2328;
            }
            QSplitter::handle {
                background: #d0d7de;
            }
            QTextEdit {
                background: #f8fafc;
                border: 1px solid #d0d7de;
                border-radius: 6px;
                padding: 8px;
            }
            QTreeWidget {
                background: #f8fafc;
                alternate-background-color: #f1f5f9;
                color: #1f2328;
                border: 1px solid #d0d7de;
                border-radius: 6px;
                selection-background-color: #dfeaff;
                selection-color: #1f2328;
            }
            QTreeWidget::item {
                color: #1f2328;
                background: transparent;
                border: none;
                padding: 4px 2px;
            }
            QTreeWidget::item:selected {
                background: #dfeaff;
                color: #1f2328;
            }
            QLabel#statusLabel {
                background: transparent;
                color: #4b5563;
                padding-top: 4px;
                font-size: 12px;
            }
            QLabel#summaryCard {
                background: #ffffff;
                border: 1px solid #d0d7de;
                border-radius: 6px;
                padding: 8px 10px;
                min-height: 38px;
                font-weight: 600;
                color: #1f2328;
            }
        )");
        themeButton->setText("Dark");
    }
}

void MainWindow::loadTraceFile(const QString &path)
{
    if (path.isEmpty()) {
        return;
    }
    loadCsv(path);
}

void MainWindow::openTraceDialog()
{
    const QString path = QFileDialog::getOpenFileName(
        this,
        "Open PCIe trace",
        QString(),
        "Trace files (*.csv *.log *.txt *.pcie);;CSV files (*.csv);;All files (*.*)");

    if (path.isEmpty()) {
        return;
    }

    loadTraceFile(path);
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (liveTraceProcess) {
        suppressAiRunnerExitWarning = true;
        stopProcessAndDelete(liveTraceProcess);
        liveTraceProcess = nullptr;
    }

    if (liveTraceTimer) {
        liveTraceTimer->stop();
        liveTraceTimer->deleteLater();
        liveTraceTimer = nullptr;
    }

    const QString pidFile = QDir::currentPath() + "/qemu.pid";
    QFile pidData(pidFile);
    if (pidData.open(QIODevice::ReadOnly | QIODevice::Text)) {
        const QByteArray pidBytes = pidData.readAll().trimmed();
        pidData.close();
        if (!pidBytes.isEmpty()) {
            bool ok = false;
            const int pid = pidBytes.toInt(&ok);
            if (ok && pid > 0) {
                QProcess::startDetached("kill", {"-TERM", QString::number(pid)});
                QProcess::startDetached("kill", {"-KILL", QString::number(pid)});
            }
        }
    }

    QMainWindow::closeEvent(event);
}

void MainWindow::openTrace()
{
    openTraceDialog();
}

void MainWindow::showPcieLsWindow(const QString &path)
{
    if (pcieLsDialog) {
        pcieLsDialog->close();
        pcieLsDialog->deleteLater();
        pcieLsDialog = nullptr;
    }

    pcieLsDialog = new QDialog(this);
    pcieLsDialog->setWindowTitle("Zephyr PCIe ls");
    pcieLsDialog->resize(900, 500);
    pcieLsDialog->setAttribute(Qt::WA_DeleteOnClose, true);

    QTextBrowser *browser = new QTextBrowser(pcieLsDialog);
    browser->setReadOnly(true);

    const QStringList entries = extractPcieLsEntries(path);
    browser->setPlainText(entries.isEmpty()
                              ? QString("No pcie ls output found.\n\nFile: %1").arg(path)
                              : entries.join("\n"));

    QVBoxLayout *layout = new QVBoxLayout(pcieLsDialog);
    layout->addWidget(browser);

    pcieLsDialog->show();
    pcieLsDialog->raise();
    pcieLsDialog->activateWindow();
}

void MainWindow::pollLiveTrace()
{
    if (liveTracePath.isEmpty()) {
        return;
    }

    QFile file(liveTracePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return;
    }

    const QStringList lines = QString::fromUtf8(file.readAll()).split('\n');
    file.close();

    int added = 0;
    for (const QString &rawLine : lines) {
        const QString line = rawLine.trimmed();
        if (line.isEmpty() || liveTraceSeen.contains(line)) {
            continue;
        }

        QString ts, dir, type, requester, completer, tag, length, addr, payload;
        if (!parseRawTraceLine(line, &ts, &dir, &type, &requester, &completer, &tag, &length, &addr, &payload)) {
            continue;
        }

        liveTraceSeen.insert(line);
        const QList<QStandardItem *> items = {
            new QStandardItem(ts),
            new QStandardItem(dir),
            new QStandardItem(type),
            new QStandardItem(requester),
            new QStandardItem(completer),
            new QStandardItem(tag),
            new QStandardItem(length),
            new QStandardItem(addr),
            new QStandardItem(payload)
        };
        model->insertRow(model->rowCount(), items);
        ++added;
    }

    if (added > 0) {
        applyFilter();
        if (model->rowCount() > 0) {
            tableView->selectRow(model->rowCount() - 1);
        }
        updateSummaryStats();
        updateAiPerformanceReadout();
        statusLabel->setText(QString("Live trace: %1 entries").arg(model->rowCount()));
    }

    if (liveTraceProcess && liveTraceProcess->state() == QProcess::NotRunning) {
        liveTraceTimer->stop();
        updateAiPerformanceReadout();
        statusLabel->setText(QString("Loaded %1 live trace entries from %2").arg(model->rowCount()).arg(liveTracePath));
        liveTraceProcess = nullptr;
    }
}

void MainWindow::saveTrace()
{
    if (model->rowCount() == 0) {
        QMessageBox::information(this, "Save trace", "There is no trace to save yet.");
        return;
    }

    const QString path = QFileDialog::getSaveFileName(
        this,
        "Save PCIe trace",
        QStringLiteral("pcie_trace.log"),
        "Trace files (*.log *.txt *.csv);;CSV files (*.csv);;All files (*.*)");

    if (path.isEmpty()) {
        return;
    }

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Save failed", "Unable to write trace file: " + path);
        return;
    }

    QTextStream out(&file);
    for (int row = 0; row < model->rowCount(); ++row) {
        const QString direction = model->item(row, 1) ? model->item(row, 1)->text() : QString();
        const QString type = model->item(row, 2) ? model->item(row, 2)->text() : QString();
        const QString requester = model->item(row, 3) ? model->item(row, 3)->text() : QString();
        const QString completer = model->item(row, 4) ? model->item(row, 4)->text() : QString();
        const QString addr = model->item(row, 7) ? model->item(row, 7)->text() : QString();
        const QString payload = model->item(row, 8) ? model->item(row, 8)->text() : QString();
        const QString op = (type == "CfgWr" || direction == "TX") ? "write" : "read";
        const QString arrow = (op == "write") ? "<-" : "->";

        if (addr.isEmpty()) {
            continue;
        }

        out << QString("pci_cfg_%1 %2 %3 @%4 %5 %6\n")
            .arg(op)
            .arg(requester)
            .arg(completer)
            .arg(addr)
            .arg(arrow)
            .arg(payload);
    }

    file.close();
    statusLabel->setText(QString("Saved %1 trace entries to %2").arg(model->rowCount()).arg(path));
}

QStringList MainWindow::splitCsvLine(const QString &line) const
{
    QStringList result;
    QString current;
    bool inQuotes = false;

    for (int i = 0; i < line.size(); ++i) {
        const QChar ch = line.at(i);
        if (ch == '"') {
            if (inQuotes && i + 1 < line.size() && line.at(i + 1) == '"') {
                current += '"';
                ++i;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (ch == ',' && !inQuotes) {
            result << current;
            current.clear();
        } else {
            current += ch;
        }
    }

    result << current;
    return result;
}

namespace {
bool parseRawTraceLine(const QString &line,
                       QString *ts,
                       QString *direction,
                       QString *type,
                       QString *requester,
                       QString *completer,
                       QString *tag,
                       QString *length,
                       QString *addr,
                       QString *payload)
{
    static const QRegularExpression re(
        QStringLiteral(R"(^pci_cfg_(?<op>read|write)\s+(?<dev>[A-Za-z0-9_.-]+)\s+(?<bdf>[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-9A-Fa-f])\s+@(?<offset>0x[0-9A-Fa-f]+)\s*(?<arrow>->|<-)\s*(?<value>0x[0-9A-Fa-f]+)\s*$)"));

    const QRegularExpressionMatch match = re.match(line.trimmed());
    if (!match.hasMatch()) {
        return false;
    }

    const QString op = match.captured("op");
    const QString device = match.captured("dev");
    const QString bdf = match.captured("bdf");
    const QString offset = match.captured("offset");
    const QString value = match.captured("value");

    *ts = QString::number(QDateTime::currentMSecsSinceEpoch());
    *direction = (op == "write") ? QStringLiteral("TX") : QStringLiteral("RX");
    *type = (op == "write") ? QStringLiteral("CfgWr") : QStringLiteral("CfgRd");
    *requester = device;
    *completer = bdf;
    *tag = QStringLiteral("0");
    *length = QStringLiteral("4");
    *addr = offset;
    *payload = value;
    return true;
}

}

void MainWindow::loadCsv(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Open failed", "Unable to open trace file: " + path);
        return;
    }

    model->removeRows(0, model->rowCount());
    QTextStream stream(&file);
    const QStringList lines = stream.readAll().split('\n');
    file.close();

    if (lines.isEmpty() || lines.first().trimmed().isEmpty()) {
        QMessageBox::warning(this, "Invalid trace", "The trace file is empty.");
        return;
    }

    const bool isCsv = std::any_of(lines.begin(), lines.end(), [](const QString &line) {
        const QString trimmed = line.trimmed();
        return !trimmed.isEmpty() && trimmed.contains(',') && trimmed.toLower().contains("timestamp");
    });

    int row = 0;
    for (const QString &rawLine : lines) {
        const QString line = rawLine.trimmed();
        if (line.isEmpty()) {
            continue;
        }

        if (isCsv) {
            if (line.toLower().startsWith("timestamp")) {
                continue;
            }
            const auto fields = splitCsvLine(line);
            if (fields.size() < 9) {
                continue;
            }

            const QString ts = fields.at(0).trimmed();
            const QString dir = normalizeDirection(fields.at(1));
            const QString type = sanitizeType(fields.at(2));
            const QString requester = fields.at(3).trimmed();
            const QString completer = fields.at(4).trimmed();
            const QString tag = fields.at(5).trimmed();
            const QString length = fields.at(6).trimmed();
            const QString addr = fields.at(7).trimmed();
            const QString payload = fields.at(8).trimmed();

            const QList<QStandardItem *> items = {
                new QStandardItem(ts),
                new QStandardItem(dir),
                new QStandardItem(type),
                new QStandardItem(requester),
                new QStandardItem(completer),
                new QStandardItem(tag),
                new QStandardItem(length),
                new QStandardItem(addr),
                new QStandardItem(payload)
            };
            model->insertRow(row, items);
            ++row;
            continue;
        }

        QString ts, dir, type, requester, completer, tag, length, addr, payload;
        if (!parseRawTraceLine(line, &ts, &dir, &type, &requester, &completer, &tag, &length, &addr, &payload)) {
            continue;
        }

        const QList<QStandardItem *> items = {
            new QStandardItem(ts),
            new QStandardItem(dir),
            new QStandardItem(type),
            new QStandardItem(requester),
            new QStandardItem(completer),
            new QStandardItem(tag),
            new QStandardItem(length),
            new QStandardItem(addr),
            new QStandardItem(payload)
        };
        model->insertRow(row, items);
        ++row;
    }

    applyFilter();
    if (model->rowCount() > 0) {
        tableView->selectRow(0);
    }
    updateSummaryStats();
    statusLabel->setText(QString("Loaded %1 TLP entries from %2").arg(row).arg(path));
}

QString MainWindow::findRepoPath(const QStringList &relativeCandidates) const
{
    const QStringList roots = {
        QDir::currentPath(),
        QCoreApplication::applicationDirPath(),
        QDir::cleanPath(QCoreApplication::applicationDirPath() + "/.."),
        QDir::cleanPath(QCoreApplication::applicationDirPath() + "/../.."),
        QDir::cleanPath(QCoreApplication::applicationDirPath() + "/../../..")
    };

    for (const QString &root : roots) {
        for (const QString &rel : relativeCandidates) {
            const QString candidate = QDir::cleanPath(root + "/" + rel);
            if (QFileInfo::exists(candidate)) {
                return candidate;
            }
        }
    }
    return QString();
}

QJsonObject MainWindow::generateTopologyFromCounts(int rootPorts, int endpointsPerRoot) const
{
    QJsonObject topo;
    topo.insert("topology_name", QString("custom %1 root ports x %2 endpoints").arg(rootPorts).arg(endpointsPerRoot));

    QJsonArray rps;
    for (int i = 0; i < rootPorts; ++i) {
        rps.append(defaultRootPort(i));
    }

    QJsonObject rc;
    rc.insert("domain", "0000");
    rc.insert("root_bus", "00");
    rc.insert("label", "CPU Complex");
    rc.insert("root_ports", rps);

    QJsonArray switches;
    QJsonArray endpoints;
    const QStringList types = {"GPU_ACCEL", "NVME", "NIC_SMART"};
    int epIndex = 0;
    for (int i = 0; i < rootPorts; ++i) {
        QJsonObject sw;
        const QString name = QString("switch%1").arg(i);
        sw.insert("name", name);
        sw.insert("parent", QString("rp%1").arg(i + 1));
        sw.insert("upstream_port", QString("%1:00.0").arg(i + 1, 2, 16, QLatin1Char('0')));
        sw.insert("p2p_allowed", true);
        QJsonArray dps;
        for (int e = 0; e < endpointsPerRoot; ++e) {
            dps.append(QString("%1:%2.0")
                           .arg(i + 2, 2, 16, QLatin1Char('0'))
                           .arg(e, 2, 16, QLatin1Char('0')));
            QJsonObject ep;
            const QString type = types.at(epIndex % types.size());
            ep.insert("type", type);
            ep.insert("label", QString("ep%1").arg(epIndex));
            ep.insert("display", QString("%1 %2").arg(type).arg(epIndex));
            ep.insert("parent", QString("%1_dp%2").arg(name).arg(e));
            ep.insert("bdf", QString("%1:00.0").arg(8 + epIndex, 2, 16, QLatin1Char('0')));
            if (type == QLatin1String("GPU_ACCEL") || type == QLatin1String("NVME")) {
                ep.insert("serial", QString("EP_%1").arg(epIndex, 2, 10, QLatin1Char('0')));
            }
            endpoints.append(ep);
            ++epIndex;
        }
        sw.insert("downstream_ports", dps);
        switches.append(sw);
    }

    topo.insert("root_complexes", QJsonArray{rc});
    topo.insert("switches", switches);
    topo.insert("endpoints", endpoints);
    return topo;
}

bool MainWindow::loadTopologyFile(const QString &path, QString *error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        if (error) {
            *error = QString("Unable to open %1").arg(path);
        }
        return false;
    }

    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll(), &parseError);
    if (!doc.isObject()) {
        if (error) {
            *error = QString("Invalid topology JSON in %1: %2").arg(path, parseError.errorString());
        }
        return false;
    }

    currentTopology = doc.object();
    currentTopologyJsonPath = path;
    return true;
}

QString MainWindow::materializeCurrentTopology(const QString &workDir)
{
    if (!currentTopologyJsonPath.isEmpty() && QFileInfo::exists(currentTopologyJsonPath) &&
        !currentTopologyJsonPath.startsWith(QDir::tempPath())) {
        return currentTopologyJsonPath;
    }

    const QString outPath = QDir(workDir).filePath("pcieshark_custom_topology.json");
    QFile out(outPath);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        return currentTopologyJsonPath;
    }
    out.write(QJsonDocument(currentTopology).toJson(QJsonDocument::Indented));
    out.close();
    currentTopologyJsonPath = outPath;
    return outPath;
}

void MainWindow::renderCurrentTopology()
{
    if (aiTopologyView) {
        aiTopologyView->setHtml(buildTopologyHtmlFromJson(currentTopology));
    }
    if (aiTopologyPathLabel) {
        const QString name = currentTopology.value("topology_name").toString("unnamed");
        const QString path = currentTopologyJsonPath.isEmpty() ? QStringLiteral("(generated)") : currentTopologyJsonPath;
        aiTopologyPathLabel->setText(QString("Topology: %1  |  %2").arg(name, path));
    }
}

void MainWindow::injectFabricEnumerationPackets()
{
    model->removeRows(0, model->rowCount());

    const QJsonArray rcs = currentTopology.value("root_complexes").toArray();
    for (const QJsonValue &rcv : rcs) {
        const QJsonArray ports = rcv.toObject().value("root_ports").toArray();
        for (int i = 0; i < ports.size(); ++i) {
            if (ports.at(i).isString()) {
                appendCfgReadRows(model, ports.at(i).toString(), QString("rp%1").arg(i + 1));
            } else {
                const QJsonObject p = ports.at(i).toObject();
                appendCfgReadRows(model, p.value("bdf").toString(), p.value("id").toString("root-port"));
            }
        }
    }

    const QJsonArray switches = currentTopology.value("switches").toArray();
    for (const QJsonValue &swv : switches) {
        const QJsonObject sw = swv.toObject();
        appendCfgReadRows(model, sw.value("upstream_port").toString(), sw.value("name").toString("switch"));
        const QJsonArray dps = sw.value("downstream_ports").toArray();
        for (int d = 0; d < dps.size(); ++d) {
            appendCfgReadRows(model, dps.at(d).toString(),
                              QString("%1_dp%2").arg(sw.value("name").toString("switch")).arg(d));
        }
    }

    const QJsonArray endpoints = currentTopology.value("endpoints").toArray();
    for (const QJsonValue &epv : endpoints) {
        const QJsonObject ep = epv.toObject();
        appendCfgReadRows(model, ep.value("bdf").toString(),
                          ep.value("label").toString(ep.value("display").toString("endpoint")));
    }

    applyFilter();
    if (model->rowCount() > 0) {
        tableView->selectRow(0);
    }
    updateSummaryStats();
}

void MainWindow::enumeratePciDevice()
{
    QString backend = backendFilter->currentText();
    const QString deviceId = deviceIdBox->text().trimmed();
    const QString scenario = scenarioBox->text().trimmed();

    if (!deviceId.isEmpty() && backend == "pci") {
        setenv("PCIE_PCI_DEVICE", deviceId.toLocal8Bit().constData(), 1);
    } else {
        unsetenv("PCIE_PCI_DEVICE");
    }

    if (backend == "dummy" || backend == "golden") {
        if (!scenario.isEmpty()) {
            setenv("PCIE_DUMMY_SCENARIO", scenario.toLocal8Bit().constData(), 1);
            setenv("PCIE_DUMMY_PROFILE", scenario.toLocal8Bit().constData(), 1);
        } else {
            unsetenv("PCIE_DUMMY_SCENARIO");
            unsetenv("PCIE_DUMMY_PROFILE");
        }
    } else {
        unsetenv("PCIE_DUMMY_SCENARIO");
        unsetenv("PCIE_DUMMY_PROFILE");
    }

    pcie_ctx_t *ctx = pcie_open(backend.toLocal8Bit().constData());
    if (!ctx) {
        QMessageBox::warning(this, "PCI enumeration failed",
                             "Unable to open the selected backend. Make sure the backend exists and the device is accessible.");
        return;
    }

    pcie_device_info_t deviceInfo = {};
    pcie_link_status_t linkStatus = {};
    int rc = pcie_get_device_info(ctx, &deviceInfo);
    if (rc != 0) {
        QMessageBox::warning(this, "PCI enumeration failed",
                             "The PCI backend is available but the device could not be queried.");
        pcie_close(ctx);
        return;
    }

    pcie_get_link_status(ctx, &linkStatus);

    model->removeRows(0, model->rowCount());

    static const uint64_t enumAddrs[] = {0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c};
    for (size_t i = 0; i < sizeof(enumAddrs) / sizeof(enumAddrs[0]); ++i) {
        pcie_tlp_t cfgRead = pcie_tlp_cfg_read(static_cast<uint32_t>(enumAddrs[i]));
        uint8_t payload[4] = {0};
        cfgRead.requester_id = 0x0001;
        cfgRead.tag = 0x0F;
        cfgRead.length = 4;
        cfgRead.mem.data = payload;

        const int result = pcie_send(ctx, &cfgRead);
        if (result != 0) {
            statusLabel->setText(QString("PCI enumeration failed at offset 0x%1").arg(enumAddrs[i], 0, 16));
            pcie_close(ctx);
            return;
        }

        QString payloadHex;
        for (int j = 0; j < cfgRead.length; ++j) {
            payloadHex += QString("%1").arg(payload[j], 2, 16, QLatin1Char('0'));
            if (j + 1 < cfgRead.length) {
                payloadHex += " ";
            }
        }

        const QString ts = QString::number(QDateTime::currentMSecsSinceEpoch());
        const QList<QStandardItem *> items = {
            new QStandardItem(ts),
            new QStandardItem("TX"),
            new QStandardItem("CfgRd"),
            new QStandardItem("1"),
            new QStandardItem("0"),
            new QStandardItem("15"),
            new QStandardItem("4"),
            new QStandardItem(QString("0x%1").arg(enumAddrs[i], 0, 16)),
            new QStandardItem(payloadHex)
        };

        model->insertRow(static_cast<int>(i), items);
    }

    pcie_close(ctx);

    applyFilter();
    if (model->rowCount() > 0) {
        tableView->selectRow(0);
    }
    updateSummaryStats();

    const QString linkSpeedName = (linkStatus.negotiated_link_speed == PCIE_LINK_SPEED_UNKNOWN)
        ? QStringLiteral("Unknown")
        : QString::fromUtf8(pcie_link_speed_name(linkStatus.negotiated_link_speed));

    const QString deviceSummary = QString("Vendor 0x%1 Device 0x%2 Class 0x%3 Rev 0x%4 | Link %5/%6 lanes")
        .arg(deviceInfo.vendor_id, 4, 16, QLatin1Char('0'))
        .arg(deviceInfo.device_id, 4, 16, QLatin1Char('0'))
        .arg(deviceInfo.class_code, 6, 16, QLatin1Char('0'))
        .arg(deviceInfo.revision_id, 2, 16, QLatin1Char('0'))
        .arg(linkSpeedName)
        .arg(linkStatus.negotiated_link_width);

    statusLabel->setText(QString("Enumerated PCI device (%1)").arg(deviceSummary));
}

void MainWindow::runAiPerformanceScenario(const QString &profile,
                                         int rootPorts,
                                         int endpointsPerRoot,
                                         int iterations,
                                         int latencyNs,
                                         int tps,
                                         int burstSize,
                                         int jitterNs,
                                         double dropRate,
                                         int busCount)
{
    const QString scenarioSpec = QString("profile=%1,latency=%2ns,tps=%3,burst=%4,jitter=%5ns,drop_rate=%6")
        .arg(profile)
        .arg(latencyNs)
        .arg(tps)
        .arg(burstSize)
        .arg(jitterNs)
        .arg(QString::number(dropRate, 'f', 6));

    const QStringList candidateScripts = {
        QDir::cleanPath(QDir::currentPath() + "/scripts/run_zephyr_ai_topology.sh"),
        QDir::cleanPath(QCoreApplication::applicationDirPath() + "/../scripts/run_zephyr_ai_topology.sh"),
        QDir::cleanPath(QCoreApplication::applicationDirPath() + "/../../scripts/run_zephyr_ai_topology.sh"),
        QDir::cleanPath(QCoreApplication::applicationDirPath() + "/../../../scripts/run_zephyr_ai_topology.sh")
    };

    QString resolvedScript;
    for (const QString &candidate : candidateScripts) {
        if (QFileInfo::exists(candidate)) {
            resolvedScript = candidate;
            break;
        }
    }

    if (resolvedScript.isEmpty()) {
        QMessageBox::warning(this, "AI performance measurement failed",
                             "Unable to locate scripts/run_zephyr_ai_topology.sh. The AI performance path requires the real Zephyr topology runner.");
        return;
    }

    const QString workDir = QFileInfo(resolvedScript).absolutePath() + "/..";
    if (currentTopology.isEmpty()) {
        currentTopology = generateTopologyFromCounts(rootPorts, endpointsPerRoot);
    }
    const QString topoPath = materializeCurrentTopology(workDir);
    const QString traceLog = QDir(workDir).filePath("zephyr_ai_topology_trace.log");
    currentAiPerformanceTargetTps = tps;
    currentAiPerformanceTargetLatencyNs = latencyNs;
    liveTraceSeen.clear();
    liveTracePath = traceLog;

    if (liveTraceTimer) {
        liveTraceTimer->stop();
        delete liveTraceTimer;
    }
    liveTraceTimer = new QTimer(this);
    connect(liveTraceTimer, &QTimer::timeout, this, &MainWindow::pollLiveTrace);
    liveTraceTimer->start(500);

    if (liveTraceProcess) {
        suppressAiRunnerExitWarning = true;
        stopProcessAndDelete(liveTraceProcess);
        liveTraceProcess = nullptr;
    }

    liveTraceProcess = new QProcess(this);
    liveTraceProcess->setWorkingDirectory(workDir);
    liveTraceProcess->setProgram("bash");
    const QString perfCommand = QString("TRACE_LOG='%1' RUN_TIMEOUT_SECONDS=5 PCIE_DUMMY_PROFILE='%2' PCIE_DUMMY_SCENARIO='%3' TOPOLOGY_JSON='%4' '%5'")
        .arg(traceLog)
        .arg(profile)
        .arg(scenarioSpec)
        .arg(topoPath)
        .arg(resolvedScript);
    liveTraceProcess->setArguments({"-lc", perfCommand});
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
        env.insert("PCIE_DUMMY_PROFILE", profile);
        env.insert("PCIE_DUMMY_SCENARIO", scenarioSpec);
        env.insert("RUN_TIMEOUT_SECONDS", "5");
        env.insert("TRACE_LOG", traceLog);
        if (!topoPath.isEmpty()) {
            env.insert("TOPOLOGY_JSON", topoPath);
        }
    liveTraceProcess->setProcessEnvironment(env);

    connect(liveTraceProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this, traceLog, profile, rootPorts, endpointsPerRoot, iterations, latencyNs, tps, burstSize, jitterNs, dropRate, busCount](int exitCode, QProcess::ExitStatus status) {
                if (suppressAiRunnerExitWarning) {
                    suppressAiRunnerExitWarning = false;
                    return;
                }
                if (status == QProcess::CrashExit || exitCode != 0) {
                    QMessageBox::warning(this, "AI performance measurement failed",
                                         "The Zephyr AI topology measure run exited with an error. "
                                         "Check the generated trace log and the runner output.");
                    return;
                }
                if (QFileInfo::exists(traceLog) || model->rowCount() > 0) {
                    int totalEntries = 0;
                    int txCount = 0;
                    int rxCount = 0;
                    double firstTs = 0.0;
                    double lastTs = 0.0;

                    if (QFileInfo::exists(traceLog)) {
                        summarizeTraceFile(traceLog, &totalEntries, &txCount, &rxCount, &firstTs, &lastTs);
                    }
                    if (totalEntries == 0 && model->rowCount() > 0) {
                        summarizeModelRows(model, &totalEntries, &txCount, &rxCount, &firstTs, &lastTs);
                    }

                    const double durationSec = (lastTs > firstTs) ? ((lastTs - firstTs) / 1000.0) : 1.0;
                    const double observedTps = (durationSec > 0.0) ? (totalEntries / durationSec) : 0.0;
                    const double observedLatencyUs = latencyNs / 1000.0;
                    const double observedUtilization = (tps > 0) ? std::min(100.0, (observedTps / tps) * 100.0) : 0.0;

                    updateAiPerformanceReadout();
                    statusLabel->setText(QString("AI performance summary: profile=%1 | packets=%2 | throughput=%3 ops/s | latency=%4 us | util=%5%")
                        .arg(profile)
                        .arg(totalEntries)
                        .arg(observedTps, 0, 'f', 2)
                        .arg(observedLatencyUs, 0, 'f', 2)
                        .arg(observedUtilization, 0, 'f', 1));

                    QMessageBox::information(this, "AI PCIe performance summary",
                                             QString("Profile: %1\n"
                                                     "Root ports: %2\n"
                                                     "Endpoints/root: %3\n"
                                                     "Iterations: %4\n"
                                                     "Target latency: %5 ns\n"
                                                     "Target token rate: %6 tps\n"
                                                     "Target burst: %7\n"
                                                     "Target jitter: %8 ns\n"
                                                     "Drop rate: %9\n\n"
                                                     "Observed entries: %10\n"
                                                     "TX: %11\n"
                                                     "RX: %12\n"
                                                     "Observed throughput: %13 ops/s\n"
                                                     "Observed latency: %14 us\n"
                                                     "Utilization: %15%")
                                             .arg(profile)
                                             .arg(rootPorts)
                                             .arg(endpointsPerRoot)
                                             .arg(iterations)
                                             .arg(latencyNs)
                                             .arg(tps)
                                             .arg(burstSize)
                                             .arg(jitterNs)
                                             .arg(dropRate, 0, 'f', 3)
                                             .arg(totalEntries)
                                             .arg(txCount)
                                             .arg(rxCount)
                                             .arg(observedTps, 0, 'f', 2)
                                             .arg(observedLatencyUs, 0, 'f', 2)
                                             .arg(observedUtilization, 0, 'f', 1));
                }
            });

    updateAiPerformanceReadout();
    liveTraceProcess->start();
    if (!liveTraceProcess->waitForStarted()) {
        QMessageBox::warning(this, "AI performance measurement failed",
                             "The Zephyr AI topology runner could not be started.");
        return;
    }

    statusLabel->setText("Running AI topology performance measurement...");
    QMessageBox::information(this, "AI PCIe topology measurement started",
                             QString("A fresh Zephyr AI topology session is running for a bounded performance window. "
                                     "pcieshark is reading %1 and updating the live counters until the run completes.")
                             .arg(traceLog));
}

void MainWindow::openAiPerfDialog()
{
    if (!aiEmulatorDialog) {
        aiEmulatorDialog = new QDialog(this);
        aiEmulatorDialog->setWindowTitle("AI PCIe Emulator");
        aiEmulatorDialog->resize(980, 760);
        aiEmulatorDialog->setAttribute(Qt::WA_DeleteOnClose, false);
        aiEmulatorDialog->setModal(false);

        QVBoxLayout *mainLayout = new QVBoxLayout(aiEmulatorDialog);

        aiPerformanceReadout = new QLabel("Live performance: waiting for trace...", aiEmulatorDialog);
        aiPerformanceReadout->setStyleSheet("QLabel { font-weight: 600; color: #1f2937; } ");

        QTextBrowser *topologyView = new QTextBrowser(aiEmulatorDialog);
        topologyView->setOpenExternalLinks(false);
        topologyView->setReadOnly(true);
        topologyView->setMinimumHeight(320);
        aiTopologyView = topologyView;

        aiTopologyPathLabel = new QLabel("Topology: (none)", aiEmulatorDialog);
        aiTopologyPathLabel->setWordWrap(true);

        QHBoxLayout *topoButtons = new QHBoxLayout();
        QPushButton *loadTopoButton = new QPushButton("Load topology JSON...", aiEmulatorDialog);
        QPushButton *generateTopoButton = new QPushButton("Generate from fields", aiEmulatorDialog);
        topoButtons->addWidget(loadTopoButton);
        topoButtons->addWidget(generateTopoButton);
        topoButtons->addStretch();

        QFormLayout *form = new QFormLayout();
        QComboBox *preset = new QComboBox(aiEmulatorDialog);
        preset->addItem("AI golden topology");
        preset->addItem("Low latency mesh");
        preset->addItem("High throughput fabric");
        preset->addItem("Custom");
        preset->setCurrentText("AI golden topology");

        QSpinBox *rootPorts = new QSpinBox(aiEmulatorDialog);
        rootPorts->setRange(1, 16);
        rootPorts->setValue(4);
        QSpinBox *endpointPerRoot = new QSpinBox(aiEmulatorDialog);
        endpointPerRoot->setRange(1, 16);
        endpointPerRoot->setValue(2);
        QSpinBox *buses = new QSpinBox(aiEmulatorDialog);
        buses->setRange(1, 8);
        buses->setValue(4);
        QSpinBox *iterations = new QSpinBox(aiEmulatorDialog);
        iterations->setRange(1, 1000);
        iterations->setValue(10);
        QSpinBox *latencyNs = new QSpinBox(aiEmulatorDialog);
        latencyNs->setRange(0, 1000000);
        latencyNs->setValue(250);
        QSpinBox *tps = new QSpinBox(aiEmulatorDialog);
        tps->setRange(1, 100000000);
        tps->setValue(250000);
        QSpinBox *burstSize = new QSpinBox(aiEmulatorDialog);
        burstSize->setRange(1, 64);
        burstSize->setValue(16);
        QSpinBox *jitterNs = new QSpinBox(aiEmulatorDialog);
        jitterNs->setRange(0, 1000000);
        jitterNs->setValue(50);
        QDoubleSpinBox *dropRate = new QDoubleSpinBox(aiEmulatorDialog);
        dropRate->setRange(0.0, 1.0);
        dropRate->setSingleStep(0.001);
        dropRate->setValue(0.0);

        form->addRow("Preset", preset);
        form->addRow("Root ports", rootPorts);
        form->addRow("Endpoints / root", endpointPerRoot);
        form->addRow("Buses", buses);
        form->addRow("Iterations", iterations);
        form->addRow("Latency (ns)", latencyNs);
        form->addRow("Tokens/sec", tps);
        form->addRow("Burst size", burstSize);
        form->addRow("Jitter (ns)", jitterNs);
        form->addRow("Drop rate", dropRate);

        QPushButton *enumerateButton = new QPushButton("Enumerate complete flow", aiEmulatorDialog);
        QPushButton *measureButton = new QPushButton("Measure performance", aiEmulatorDialog);
        QPushButton *pcieLsButton = new QPushButton("Show pcie ls", aiEmulatorDialog);
        auto *actionButtons = new QDialogButtonBox(Qt::Horizontal, aiEmulatorDialog);
        actionButtons->addButton(enumerateButton, QDialogButtonBox::ActionRole);
        actionButtons->addButton(measureButton, QDialogButtonBox::ActionRole);
        actionButtons->addButton(pcieLsButton, QDialogButtonBox::ActionRole);
        auto *closeButton = new QPushButton("Close", aiEmulatorDialog);
        actionButtons->addButton(closeButton, QDialogButtonBox::ActionRole);

        mainLayout->addWidget(topologyView);
        mainLayout->addWidget(aiTopologyPathLabel);
        mainLayout->addLayout(topoButtons);
        mainLayout->addWidget(aiPerformanceReadout);
        mainLayout->addLayout(form);
        mainLayout->addWidget(actionButtons);

        auto applyPreset = [this, preset, rootPorts, endpointPerRoot, buses, iterations, latencyNs, tps, burstSize, jitterNs, dropRate](int index) {
            switch (index) {
                case 0:
                    rootPorts->setValue(4);
                    endpointPerRoot->setValue(2);
                    buses->setValue(4);
                    iterations->setValue(20);
                    latencyNs->setValue(80);
                    tps->setValue(500000);
                    burstSize->setValue(32);
                    jitterNs->setValue(25);
                    dropRate->setValue(0.0);
                    break;
                case 1:
                    rootPorts->setValue(8);
                    endpointPerRoot->setValue(2);
                    buses->setValue(4);
                    iterations->setValue(20);
                    latencyNs->setValue(80);
                    tps->setValue(500000);
                    burstSize->setValue(32);
                    jitterNs->setValue(25);
                    dropRate->setValue(0.001);
                    break;
                case 2:
                    rootPorts->setValue(8);
                    endpointPerRoot->setValue(4);
                    buses->setValue(4);
                    iterations->setValue(25);
                    latencyNs->setValue(120);
                    tps->setValue(1000000);
                    burstSize->setValue(64);
                    jitterNs->setValue(75);
                    dropRate->setValue(0.005);
                    break;
                default:
                    break;
            }

            QString error;
            if (index == 0) {
                const QString golden = findRepoPath({"config/ai_golden_topology.json"});
                if (!golden.isEmpty() && loadTopologyFile(golden, &error)) {
                    renderCurrentTopology();
                    return;
                }
            } else if (index == 1) {
                const QString cluster = findRepoPath({"config/ai_cluster_8gpu.json"});
                if (!cluster.isEmpty() && loadTopologyFile(cluster, &error)) {
                    renderCurrentTopology();
                    return;
                }
            }

            currentTopology = generateTopologyFromCounts(rootPorts->value(), endpointPerRoot->value());
            currentTopologyJsonPath.clear();
            renderCurrentTopology();
        };
        connect(preset, QOverload<int>::of(&QComboBox::currentIndexChanged), applyPreset);
        connect(loadTopoButton, &QPushButton::clicked, this, [this, preset]() {
            const QString startDir = findRepoPath({"config/ai_golden_topology.json"});
            const QString path = QFileDialog::getOpenFileName(
                this,
                "Load PCIe topology JSON",
                startDir.isEmpty() ? QDir::currentPath() : QFileInfo(startDir).absolutePath(),
                "Topology JSON (*.json);;All files (*)");
            if (path.isEmpty()) {
                return;
            }
            QString error;
            if (!loadTopologyFile(path, &error)) {
                QMessageBox::warning(this, "Invalid topology", error);
                return;
            }
            preset->setCurrentText("Custom");
            renderCurrentTopology();
            statusLabel->setText(QString("Loaded topology %1").arg(path));
        });
        connect(generateTopoButton, &QPushButton::clicked, this, [this, preset, rootPorts, endpointPerRoot]() {
            currentTopology = generateTopologyFromCounts(rootPorts->value(), endpointPerRoot->value());
            currentTopologyJsonPath.clear();
            preset->setCurrentText("Custom");
            renderCurrentTopology();
        });
        connect(enumerateButton, &QPushButton::clicked, this, [this, rootPorts, endpointPerRoot]() {
            if (currentTopology.isEmpty()) {
                currentTopology = generateTopologyFromCounts(rootPorts->value(), endpointPerRoot->value());
            }
            renderCurrentTopology();
            injectFabricEnumerationPackets();

            const QString resolvedScript = findRepoPath({"scripts/run_zephyr_ai_topology.sh"});
            if (resolvedScript.isEmpty()) {
                statusLabel->setText(QString("Enumerated fabric '%1' in-process (Zephyr runner not found)")
                                         .arg(currentTopology.value("topology_name").toString()));
                QMessageBox::information(this, "Topology enumerated",
                                         "The defined fabric was walked and CfgRd traffic was generated. "
                                         "Install the Zephyr runner to also enumerate the same topology in QEMU.");
                return;
            }

            const QString workingDir = QFileInfo(resolvedScript).absolutePath() + "/..";
            const QString topoPath = materializeCurrentTopology(workingDir);
            const QString traceLog = QDir(workingDir).filePath("zephyr_ai_topology_trace.log");
            statusLabel->setText(QString("Enumerating topology %1 ...").arg(currentTopology.value("topology_name").toString()));

            liveTraceSeen.clear();
            liveTracePath = traceLog;
            if (liveTraceTimer) {
                liveTraceTimer->stop();
                delete liveTraceTimer;
            }
            liveTraceTimer = new QTimer(this);
            connect(liveTraceTimer, &QTimer::timeout, this, &MainWindow::pollLiveTrace);
            liveTraceTimer->start(500);

            if (liveTraceProcess) {
                suppressAiRunnerExitWarning = true;
                stopProcessAndDelete(liveTraceProcess);
                liveTraceProcess = nullptr;
            }
            liveTraceProcess = new QProcess(this);
            liveTraceProcess->setWorkingDirectory(workingDir);
            liveTraceProcess->setProgram("bash");
            liveTraceProcess->setArguments({"-lc", resolvedScript});
            QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
            env.insert("TOPOLOGY_JSON", topoPath);
            liveTraceProcess->setProcessEnvironment(env);

            connect(liveTraceProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                    this, [this, traceLog](int exitCode, QProcess::ExitStatus status) {
                        if (suppressAiRunnerExitWarning) {
                            suppressAiRunnerExitWarning = false;
                            return;
                        }
                        if (status == QProcess::CrashExit || exitCode != 0) {
                            QMessageBox::warning(this, "Zephyr topology enumeration failed",
                                                 "The Zephyr AI topology runner exited with an error. "
                                                 "The in-process fabric walk is still in the packet table.");
                            return;
                        }
                        if (QFileInfo::exists(traceLog)) {
                            loadTraceFile(traceLog);
                            statusLabel->setText(QString("Loaded %1 trace entries from %2").arg(model->rowCount()).arg(traceLog));
                        }
                    });

            liveTraceProcess->start();
            QMessageBox::information(this, "Topology enumeration started",
                                     QString("Fabric '%1' was enumerated in pcieshark.\n"
                                             "QEMU is also launching with TOPOLOGY_JSON=%2")
                                         .arg(currentTopology.value("topology_name").toString(), topoPath));
        });
        connect(measureButton, &QPushButton::clicked, this, [this, preset, rootPorts, endpointPerRoot, buses, iterations, latencyNs, tps, burstSize, jitterNs, dropRate]() {
            QString profile = "gen8x16";
            if (preset->currentText() == "AI golden topology") profile = "gen8x16";
            else if (preset->currentText() == "Low latency mesh") profile = "gen7x8";
            else if (preset->currentText() == "High throughput fabric") profile = "gen8x16";

            runAiPerformanceScenario(profile,
                                     rootPorts->value(),
                                     endpointPerRoot->value(),
                                     iterations->value(),
                                     latencyNs->value(),
                                     tps->value(),
                                     burstSize->value(),
                                     jitterNs->value(),
                                     dropRate->value(),
                                     buses->value());
        });
        connect(pcieLsButton, &QPushButton::clicked, this, [this]() {
            const QStringList candidateScripts = {
                QDir::cleanPath(QDir::currentPath() + "/scripts/run_zephyr_ai_topology.sh"),
                QDir::cleanPath(QCoreApplication::applicationDirPath() + "/../scripts/run_zephyr_ai_topology.sh"),
                QDir::cleanPath(QCoreApplication::applicationDirPath() + "/../../scripts/run_zephyr_ai_topology.sh"),
                QDir::cleanPath(QCoreApplication::applicationDirPath() + "/../../../scripts/run_zephyr_ai_topology.sh")
            };

            QString resolvedScript;
            for (const QString &candidate : candidateScripts) {
                if (QFileInfo::exists(candidate)) {
                    resolvedScript = candidate;
                    break;
                }
            }

            if (resolvedScript.isEmpty()) {
                QMessageBox::warning(this, "Zephyr runner missing",
                                     "Unable to locate scripts/run_zephyr_ai_topology.sh.");
                return;
            }

            const QString workingDir = QFileInfo(resolvedScript).absolutePath() + "/..";
            const QString pcieLsLog = QDir(workingDir).filePath("zephyr_pcie_ls.log");

            QProcess *proc = new QProcess(this);
            proc->setWorkingDirectory(workingDir);
            proc->setProgram("bash");
            QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
            env.insert("PCIE_LS_CAPTURE", "1");
            env.insert("PCIE_LS_LOG", pcieLsLog);
            env.insert("RUN_TIMEOUT_SECONDS", "15");
            if (!currentTopologyJsonPath.isEmpty()) {
                env.insert("TOPOLOGY_JSON", currentTopologyJsonPath);
            } else if (!currentTopology.isEmpty()) {
                env.insert("TOPOLOGY_JSON", materializeCurrentTopology(workingDir));
            }
            proc->setProcessEnvironment(env);
            proc->setArguments({"-lc", resolvedScript});
            connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                    this, [this, pcieLsLog](int exitCode, QProcess::ExitStatus status) {
                        if (status == QProcess::CrashExit || exitCode != 0) {
                            QMessageBox::warning(this, "pcie ls failed",
                                                 "The Zephyr guest did not return valid pcie ls output.");
                            return;
                        }
                        if (QFileInfo::exists(pcieLsLog)) {
                            showPcieLsWindow(pcieLsLog);
                        }
                    });
            proc->start();
            statusLabel->setText("Capturing guest pcie ls output in a separate log...");
        });
        connect(closeButton, &QPushButton::clicked, aiEmulatorDialog, &QDialog::close);
        connect(aiEmulatorDialog, &QDialog::finished, this, [this]() {
            aiEmulatorDialog = nullptr;
            aiTopologyView = nullptr;
            aiTopologyPathLabel = nullptr;
        });

        applyPreset(preset->currentIndex());
    }

    aiEmulatorDialog->show();
    aiEmulatorDialog->raise();
    aiEmulatorDialog->activateWindow();
}

void MainWindow::applyFilter()
{
    const QString type = typeFilter->currentText();
    const QString direction = directionFilter->currentText();
    const QString text = searchBox->text().trimmed();

    for (int row = 0; row < model->rowCount(); ++row) {
        bool visible = true;
        const QString rowType = model->index(row, 2).data().toString();
        const QString rowDirection = model->index(row, 1).data().toString();
        const QString rowText = (rowType + " " +
                                 model->index(row, 3).data().toString() + " " +
                                 model->index(row, 7).data().toString()).toLower();

        if (type != "All types" && rowType != type) {
            visible = false;
        }

        if (direction != "All directions" && rowDirection != direction) {
            visible = false;
        }

        if (!text.isEmpty() && !rowText.contains(text.toLower())) {
            visible = false;
        }

        tableView->setRowHidden(row, !visible);
    }

    colorRows();
    showPacketDetails();
    updateSummaryStats();
}

void MainWindow::updateAiPerformanceReadout()
{
    if (!aiPerformanceReadout || !model) {
        return;
    }

    int totalEntries = 0;
    int txCount = 0;
    int rxCount = 0;
    double firstTs = 0.0;
    double lastTs = 0.0;
    summarizeModelRows(model, &totalEntries, &txCount, &rxCount, &firstTs, &lastTs);

    const double durationSec = (lastTs > firstTs) ? ((lastTs - firstTs) / 1000.0) : 1.0;
    const double observedTps = (durationSec > 0.0) ? (totalEntries / durationSec) : 0.0;
    const double observedLatencyUs = (currentAiPerformanceTargetLatencyNs > 0) ? (currentAiPerformanceTargetLatencyNs / 1000.0) : 0.0;
    const double utilization = (currentAiPerformanceTargetTps > 0) ? std::min(100.0, (observedTps / currentAiPerformanceTargetTps) * 100.0) : 0.0;

    aiPerformanceReadout->setText(QString("Live performance: %1 entries | throughput=%2 ops/s | latency=%3 us | util=%4%")
        .arg(totalEntries)
        .arg(observedTps, 0, 'f', 2)
        .arg(observedLatencyUs, 0, 'f', 2)
        .arg(utilization, 0, 'f', 1));
}

void MainWindow::updateSummaryStats()
{
    int total = 0;
    int tx = 0;
    int rx = 0;
    int visible = 0;

    for (int row = 0; row < model->rowCount(); ++row) {
        if (model->index(row, 1).data().toString() == "TX") {
            tx++;
        } else if (model->index(row, 1).data().toString() == "RX") {
            rx++;
        }

        total++;
        if (!tableView->isRowHidden(row)) {
            visible++;
        }
    }

    totalLabel->setText(QString("Total: %1").arg(total));
    txLabel->setText(QString("TX: %1").arg(tx));
    rxLabel->setText(QString("RX: %1").arg(rx));
    filteredLabel->setText(QString("Visible: %1").arg(visible));
}

void MainWindow::colorRows()
{
    const bool hasSelection = tableView->currentIndex().isValid();

    for (int row = 0; row < model->rowCount(); ++row) {
        const QString direction = model->index(row, 1).data().toString();
        const QString type = model->index(row, 2).data().toString();
        const bool isSelected = hasSelection && tableView->currentIndex().row() == row;

        QColor bgColor = darkMode ? QColor("#17263a") : QColor("#f4f6fb");
        QColor fgColor = darkMode ? QColor("#e5edf7") : QColor("#1f2328");

        if (isSelected) {
            bgColor = darkMode ? QColor("#2a68bf") : QColor("#dfeaff");
            fgColor = darkMode ? QColor("#ffffff") : QColor("#0f172a");
        } else if (darkMode) {
            bgColor = QColor("#1a2d3d");

            if (direction == "TX") {
                bgColor = QColor("#1d3a4f");
            } else if (direction == "RX") {
                bgColor = QColor("#1f382e");
            }

            if (type == "CfgRd") {
                bgColor = QColor("#224b70");
            } else if (type == "CfgWr") {
                bgColor = QColor("#5a3240");
            } else if (type == "MemRd") {
                bgColor = QColor("#1e3d5a");
            } else if (type == "MemWr") {
                bgColor = QColor("#594d25");
            } else if (type == "Cpl") {
                bgColor = QColor("#2e3459");
            }
        } else {
            if (direction == "TX") {
                bgColor = QColor("#eaf4ff");
            } else if (direction == "RX") {
                bgColor = QColor("#edf9ee");
            }

            if (type == "CfgRd") {
                bgColor = QColor("#eaf1ff");
            } else if (type == "CfgWr") {
                bgColor = QColor("#fff0ef");
            } else if (type == "MemRd") {
                bgColor = QColor("#eef3ff");
            } else if (type == "MemWr") {
                bgColor = QColor("#fff8eb");
            } else if (type == "Cpl") {
                bgColor = QColor("#f2f0ff");
            }
        }

        for (int col = 0; col < model->columnCount(); ++col) {
            auto *item = model->item(row, col);
            if (!item) {
                continue;
            }
            item->setBackground(bgColor);
            item->setForeground(fgColor);
        }
    }
}

void MainWindow::showPacketDetails()
{
    const QModelIndex index = tableView->currentIndex();
    if (!index.isValid()) {
        detailsView->setPlainText("No packet selected.");
        decodeTree->clear();
        return;
    }

    const int row = index.row();
    const QString timestamp = model->index(row, 0).data().toString();
    const QString direction = model->index(row, 1).data().toString();
    const QString typeText = model->index(row, 2).data().toString();
    const QString requester = model->index(row, 3).data().toString();
    const QString completer = model->index(row, 4).data().toString();
    const QString tag = model->index(row, 5).data().toString();
    const QString lengthText = model->index(row, 6).data().toString();
    const QString addrText = model->index(row, 7).data().toString();
    const QString payload = model->index(row, 8).data().toString();

    bool ok = false;
    const uint8_t typeCode = static_cast<uint8_t>(typeText.toUInt(&ok, 16));
    const uint16_t requesterId = static_cast<uint16_t>(requester.toUInt());
    const uint16_t completerId = static_cast<uint16_t>(completer.toUInt());
    const uint8_t tagValue = static_cast<uint8_t>(tag.toUInt());
    const uint16_t lengthValue = static_cast<uint16_t>(lengthText.toUInt());
    const uint64_t addrValue = static_cast<uint64_t>(addrText.toULongLong(nullptr, 16));
    const pcie_tlp_type_t decodedType = pcie_tlp_type_from_code(typeCode);
    const pcie_tlp_t decoded = pcie_tlp_decode(typeCode, requesterId, completerId,
                                              tagValue, lengthValue, addrValue, nullptr);

    const QString typeName = pcie_tlp_type_name(decodedType);
    const QString payloadHex = formatHexDump(payload);

    QString details;
    details += QString("Packet #%1\n").arg(row + 1);
    details += QString("Timestamp: %1\n").arg(timestamp);
    details += QString("Direction: %1\n").arg(direction);
    details += QString("Type: %1 (0x%2)\n\n").arg(typeName).arg(typeText);
    details += QString("Header fields:\n");
    details += QString("  - type: %1\n").arg(typeName);
    details += QString("  - requester_id: %1\n").arg(decoded.requester_id);
    details += QString("  - completer_id: %1\n").arg(decoded.completer_id);
    details += QString("  - tag: %1\n").arg(decoded.tag);
    details += QString("  - length: %1\n").arg(decoded.length);
    details += QString("  - address: 0x%1\n").arg(decoded.mem.addr, 0, 16);
    details += QString("  - payload_len: %1\n\n").arg(payload.isEmpty() ? 0 : payload.size());
    details += QString("Payload (hex):\n%1\n").arg(payloadHex);
    details += QString("Raw payload string: %1\n").arg(payload.isEmpty() ? QString("<none>") : payload);

    detailsView->setPlainText(details);

    decodeTree->clear();
    auto *root = new QTreeWidgetItem(decodeTree, {"PCIe TLP", ""});
    auto addField = [&](const QString &name, const QString &value) {
        new QTreeWidgetItem(root, {name, value});
    };

    addField("Direction", direction);
    addField("Type", QString("%1 (0x%2)").arg(typeName).arg(typeText));
    addField("Requester ID", requester);
    addField("Completer ID", completer);
    addField("Tag", tag);
    addField("Length", lengthText);
    addField("Address", QString("0x%1").arg(addrValue, 0, 16));
    addField("Payload length", QString::number(payload.isEmpty() ? 0 : payload.size()));
    addField("Payload", payload.isEmpty() ? "<none>" : payload);

    if ((typeText == "CfgRd" || typeText == "CfgWr") && !payload.isEmpty()) {
        QString normalizedPayload = payload;
        normalizedPayload.remove(' ');
        normalizedPayload.remove('\t');
        normalizedPayload.remove('\n');
        normalizedPayload.remove('\r');

        const QByteArray rawBytes = QByteArray::fromHex(normalizedPayload.toLatin1());
        if (rawBytes.size() >= 4) {
            uint32_t regValue = 0;
            for (int i = 0; i < 4 && i < rawBytes.size(); ++i) {
                regValue |= static_cast<uint32_t>(static_cast<unsigned char>(rawBytes.at(i))) << (8 * i);
            }

            auto *pciRoot = new QTreeWidgetItem(decodeTree, {"PCI config decode", ""});
            const uint64_t regAddr = addrValue;

            switch (static_cast<int>(regAddr)) {
                case 0x00:
                    new QTreeWidgetItem(pciRoot, {"Vendor ID", makeHexLabel(static_cast<uint16_t>(regValue & 0xFFFF), 4)});
                    new QTreeWidgetItem(pciRoot, {"Vendor name", pciVendorName(static_cast<uint16_t>(regValue & 0xFFFF))});
                    new QTreeWidgetItem(pciRoot, {"Device ID", makeHexLabel(static_cast<uint16_t>((regValue >> 16) & 0xFFFF), 4)});
                    break;
                case 0x04:
                    new QTreeWidgetItem(pciRoot, {"Command", makeHexLabel(static_cast<uint16_t>(regValue & 0xFFFF), 4)});
                    new QTreeWidgetItem(pciRoot, {"Status", makeHexLabel(static_cast<uint16_t>((regValue >> 16) & 0xFFFF), 4)});
                    break;
                case 0x08:
                    new QTreeWidgetItem(pciRoot, {"Revision ID", makeHexLabel(static_cast<uint8_t>(regValue & 0xFF), 2)});
                    new QTreeWidgetItem(pciRoot, {"Class code", makeHexLabel(static_cast<uint32_t>((regValue >> 8) & 0xFFFFFF), 6)});
                    new QTreeWidgetItem(pciRoot, {"Class name", pciClassName(static_cast<uint32_t>((regValue >> 8) & 0xFFFFFF))});
                    break;
                case 0x10:
                case 0x14:
                case 0x18:
                case 0x1C:
                    new QTreeWidgetItem(pciRoot, {"BAR", makeHexLabel(regValue, 8)});
                    break;
                default:
                    new QTreeWidgetItem(pciRoot, {"Raw register", makeHexLabel(regValue, 8)});
                    break;
            }

            auto *deviceSummary = new QTreeWidgetItem(decodeTree, {"PCI device summary", ""});
            const uint16_t vendorId = (regAddr == 0x00) ? static_cast<uint16_t>(regValue & 0xFFFF) : 0;
            const uint16_t deviceId = (regAddr == 0x00) ? static_cast<uint16_t>((regValue >> 16) & 0xFFFF) : 0;
            const uint32_t classCode = (regAddr == 0x08) ? static_cast<uint32_t>((regValue >> 8) & 0xFFFFFF) : 0;

            if (vendorId != 0) {
                new QTreeWidgetItem(deviceSummary, {"Vendor", QString("%1 (%2)").arg(pciVendorName(vendorId)).arg(makeHexLabel(vendorId, 4))});
                new QTreeWidgetItem(deviceSummary, {"Device", makeHexLabel(deviceId, 4)});
            }
            if (classCode != 0) {
                new QTreeWidgetItem(deviceSummary, {"Class", QString("%1 (%2)").arg(pciClassName(classCode)).arg(makeHexLabel(classCode, 6))});
            }
            if (regAddr == 0x10 || regAddr == 0x14 || regAddr == 0x18 || regAddr == 0x1C) {
                new QTreeWidgetItem(deviceSummary, {"BAR", makeHexLabel(regValue, 8)});
            }
        }
    }

    auto *specRoot = new QTreeWidgetItem(decodeTree, {"Spec structure", ""});
    new QTreeWidgetItem(specRoot, {"type", typeName});
    new QTreeWidgetItem(specRoot, {"requester_id", QString::number(decoded.requester_id)});
    new QTreeWidgetItem(specRoot, {"completer_id", QString::number(decoded.completer_id)});
    new QTreeWidgetItem(specRoot, {"tag", QString::number(decoded.tag)});
    new QTreeWidgetItem(specRoot, {"length", QString::number(decoded.length)});
    new QTreeWidgetItem(specRoot, {"addr", QString("0x%1").arg(decoded.mem.addr, 0, 16)});
    new QTreeWidgetItem(specRoot, {"payload_len", QString::number(payload.isEmpty() ? 0 : payload.size())});
    decodeTree->expandAll();
}
