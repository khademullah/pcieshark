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
#include <QGroupBox>
#include <QGridLayout>
#include <QSizePolicy>
#include <QScreen>
#include <QGuiApplication>
#include <QApplication>
#include <QScrollArea>
#include <QLocale>
#include <QVector>
#include <QHash>
#include <QMap>
#include <QDesktopServices>
#include <QUrl>

#include <algorithm>
#include <cstdlib>
#include <cstring>

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
        case 0x1B36: return "Red Hat, Inc.";
        case 0x10DE: return "NVIDIA";
        case 0x10B5: return "PLX";
        default: return "Unknown vendor";
    }
}

QString pciClassName(uint32_t classCode)
{
    const uint32_t full = classCode > 0xFFFF ? classCode : (classCode << 8);
    switch (full) {
        case 0x020000: return "Ethernet controller";
        case 0x010000: return "SCSI storage controller";
        case 0x010802: return "Non-Volatile memory controller";
        case 0x0C0300: return "USB controller";
        case 0x060000: return "Host bridge";
        case 0x060400: return "PCI bridge";
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

QString cellHtml(const QString &title, const QString &sub, const QString &body, const QString &accent = QString())
{
    const QString border = accent.isEmpty() ? QStringLiteral("#64748b") : accent;
    return QStringLiteral(
               "<td align='center' width='25%' style='border:1px solid %4;padding:10px 8px;vertical-align:top;min-width:140px;'>"
               "<div style='font-weight:700;letter-spacing:0.2px;'>[%1]</div>"
               "<div style='font-size:12px;opacity:0.85;margin-top:4px;'>%2</div>"
               "<div style='margin-top:4px;'>%3</div></td>")
        .arg(title.toHtmlEscaped(), sub.toHtmlEscaped(), body.toHtmlEscaped(), border);
}

QString tableRow(const QString &cells)
{
    if (cells.isEmpty()) {
        return QString();
    }
    return QStringLiteral("<table width='100%' style='border-spacing:10px 8px;table-layout:fixed;'><tr>%1</tr></table>").arg(cells);
}

QString wrapCellRows(const QStringList &cells, int perRow = 4)
{
    if (cells.isEmpty()) {
        return QString();
    }
    QString html;
    for (int i = 0; i < cells.size(); i += perRow) {
        QString row;
        const int end = qMin(i + perRow, cells.size());
        for (int j = i; j < end; ++j) {
            row += cells.at(j);
        }
        html += tableRow(row);
    }
    return html;
}

QString endpointAccent(const QString &type)
{
    const QString t = type.toUpper();
    if (t.contains(QLatin1String("GPU")) || t.contains(QLatin1String("ACCEL"))) {
        return QStringLiteral("#3b82f6");
    }
    if (t.contains(QLatin1String("NVME")) || t.contains(QLatin1String("STOR"))) {
        return QStringLiteral("#10b981");
    }
    if (t.contains(QLatin1String("NIC")) || t.contains(QLatin1String("ETH")) || t.contains(QLatin1String("NET"))) {
        return QStringLiteral("#f59e0b");
    }
    return QStringLiteral("#64748b");
}

void fitToAvailableScreen(QWidget *widget, double scale = 1.0)
{
    if (!widget) {
        return;
    }

    QScreen *screen = widget->screen();
    if (!screen) {
        if (QWidget *parent = widget->parentWidget()) {
            screen = parent->screen();
        }
    }
    if (!screen) {
        screen = QGuiApplication::primaryScreen();
    }
    if (!screen) {
        return;
    }

    const QRect avail = screen->availableGeometry();
    const int margin = (scale >= 0.99) ? 0 : 16;
    const int width = qBound(720, static_cast<int>(avail.width() * scale) - margin, avail.width() - margin);
    const int height = qBound(520, static_cast<int>(avail.height() * scale) - margin, avail.height() - margin);
    const int x = avail.x() + (avail.width() - width) / 2;
    const int y = avail.y() + (avail.height() - height) / 2;
    widget->setMaximumSize(avail.size());
    widget->setGeometry(x, y, width, height);
}

uint8_t tlpCodeFromName(const QString &typeText)
{
    const QString t = typeText.trimmed();
    if (t.compare(QLatin1String("MemRd"), Qt::CaseInsensitive) == 0
        || t.compare(QLatin1String("MemRead"), Qt::CaseInsensitive) == 0
        || t == QLatin1String("0")) {
        return PCIE_TLP_MEM_READ;
    }
    if (t.compare(QLatin1String("MemWr"), Qt::CaseInsensitive) == 0
        || t.compare(QLatin1String("MemWrite"), Qt::CaseInsensitive) == 0
        || t == QLatin1String("1")) {
        return PCIE_TLP_MEM_WRITE;
    }
    if (t.compare(QLatin1String("CfgRd"), Qt::CaseInsensitive) == 0
        || t.compare(QLatin1String("CfgRead"), Qt::CaseInsensitive) == 0
        || t == QLatin1String("4")) {
        return PCIE_TLP_CFG_READ;
    }
    if (t.compare(QLatin1String("CfgWr"), Qt::CaseInsensitive) == 0
        || t.compare(QLatin1String("CfgWrite"), Qt::CaseInsensitive) == 0
        || t == QLatin1String("5")) {
        return PCIE_TLP_CFG_WRITE;
    }
    if (t.compare(QLatin1String("Cpl"), Qt::CaseInsensitive) == 0
        || t.compare(QLatin1String("CplD"), Qt::CaseInsensitive) == 0
        || t.compare(QLatin1String("Completion"), Qt::CaseInsensitive) == 0
        || t == QLatin1String("10")
        || t.compare(QLatin1String("0x0A"), Qt::CaseInsensitive) == 0) {
        return PCIE_TLP_CPL;
    }
    bool ok = false;
    const uint value = t.toUInt(&ok, 0);
    return ok ? static_cast<uint8_t>(value) : static_cast<uint8_t>(PCIE_TLP_UNKNOWN);
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
    QStringList rpCells;
    QStringList swCells;
    QStringList dpCells;
    QStringList epCells;

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
            rpCells << cellHtml(id, sub, label, QStringLiteral("#60a5fa"));
        }
    }

    for (const QJsonValue &swv : switches) {
        const QJsonObject sw = swv.toObject();
        const QString swName = sw.value("name").toString("switch");
        const QString up = sw.value("upstream_port").toString();
        const QString parent = sw.value("parent").toString();
        swCells << cellHtml(swName + QStringLiteral("_up"), up, parent, QStringLiteral("#94a3b8"));
        const QJsonArray dps = sw.value("downstream_ports").toArray();
        for (int d = 0; d < dps.size(); ++d) {
            dpCells << cellHtml(QString("%1 dp%2").arg(swName).arg(d),
                                dps.at(d).toString(),
                                QStringLiteral("downstream"),
                                QStringLiteral("#7dd3fc"));
        }
    }

    for (const QJsonValue &epv : endpoints) {
        const QJsonObject ep = epv.toObject();
        const QString display = ep.value("display").toString(ep.value("label").toString("endpoint"));
        const QString bdf = ep.value("bdf").toString();
        const QString label = ep.value("label").toString();
        const QString type = ep.value("type").toString();
        epCells << cellHtml(display, bdf.isEmpty() ? type : bdf, label, endpointAccent(type));
    }

    return QStringLiteral(
               "<html><body style='background:#0f1117;color:#e7ebf3;font-family:\"Noto Sans Mono\",\"DejaVu Sans Mono\",monospace;'>"
               "<div style='padding:10px;'>"
               "<div style='text-align:center;font-weight:700;font-size:18px;padding:8px;'>[ %1 ]</div>"
               "<div style='text-align:center;font-size:14px;padding-bottom:4px;'>[ %2 ]</div>"
               "<div style='text-align:center;font-size:12px;opacity:0.85;padding-bottom:10px;'>%3</div>"
               "%4"
               "<div style='border-top:2px solid #334155; margin:12px 0;'></div>"
               "%5%6%7"
               "</div></body></html>")
        .arg(rcLabel.toHtmlEscaped(),
             busLabel.toHtmlEscaped(),
             name.toHtmlEscaped(),
             wrapCellRows(rpCells, 4),
             wrapCellRows(swCells, 4),
             wrapCellRows(dpCells, 4),
             wrapCellRows(epCells, 4));
}

QString leDwordPayload(uint32_t value)
{
    return QString("%1 %2 %3 %4")
        .arg(value & 0xff, 2, 16, QLatin1Char('0'))
        .arg((value >> 8) & 0xff, 2, 16, QLatin1Char('0'))
        .arg((value >> 16) & 0xff, 2, 16, QLatin1Char('0'))
        .arg((value >> 24) & 0xff, 2, 16, QLatin1Char('0'));
}

struct PciIdentity {
    uint16_t vendor = 0x1b36;
    uint16_t device = 0x0001;
    uint32_t classCode = 0x060000;
    uint8_t headerType = 0x00;
    QString product;
};

PciIdentity identityFromKind(const QString &kind)
{
    const QString r = kind.toLower();
    PciIdentity id;
    if (r.contains("eth") || r.contains("nic") || r.contains("e1000")) {
        id.vendor = 0x8086;
        id.device = 0x10d3;
        id.classCode = 0x020000;
        id.product = QStringLiteral("82574L Gigabit Network Connection");
    } else if (r.contains("nvme") || r.contains("ai") || r.contains("gpu")) {
        id.vendor = 0x1b36;
        id.device = 0x0010;
        id.classCode = 0x010802;
        id.product = QStringLiteral("QEMU NVMe Ctrl");
    } else if (r.contains("dp") || r.contains("down")) {
        id.vendor = 0x8086;
        id.device = 0x3438;
        id.classCode = 0x060400;
        id.headerType = 0x01;
        id.product = QStringLiteral("XIO3130 Downstream Port");
    } else if (r.contains("switch") || r.contains("up")) {
        id.vendor = 0x8086;
        id.device = 0x3432;
        id.classCode = 0x060400;
        id.headerType = 0x01;
        id.product = QStringLiteral("XIO3130 Upstream Port");
    } else if (r.contains("rp") || r.contains("root") || r.contains("hub")) {
        id.vendor = 0x1b36;
        id.device = 0x000c;
        id.classCode = 0x060400;
        id.headerType = 0x01;
        id.product = QStringLiteral("QEMU PCIe Root port");
    } else {
        id.product = QStringLiteral("QEMU PCI device");
    }
    return id;
}

uint32_t syntheticConfigDword(const QString &role, uint64_t offset)
{
    const PciIdentity id = identityFromKind(role);
    const bool isBridge = id.headerType == 0x01;
    switch (offset) {
        case 0x00:
            return static_cast<uint32_t>(id.vendor) | (static_cast<uint32_t>(id.device) << 16);
        case 0x04:
            return 0x00100006;
        case 0x08:
            return id.classCode << 8;
        case 0x0c:
            return static_cast<uint32_t>(id.headerType) << 16;
        case 0x10:
            return isBridge ? 0x00000000 : 0xffff0004;
        case 0x14:
            return isBridge ? 0x00010100 : 0x00000000;
        case 0x18:
            return isBridge ? 0x00010100 : 0x00000000;
        case 0x1c:
            return 0x00000000;
        default:
            return 0x00000000;
    }
}

QString lspciLine(const QString &bdf, const QString &kind, const QString &note)
{
    const PciIdentity id = identityFromKind(kind);
    const QString classHex = QString("%1").arg((id.classCode >> 8) & 0xffff, 4, 16, QLatin1Char('0'));
    const QString vend = QString("%1").arg(id.vendor, 4, 16, QLatin1Char('0'));
    const QString dev = QString("%1").arg(id.device, 4, 16, QLatin1Char('0'));
    return QString("%1 %2 [%3]: %4 %5 [%6:%7]%8")
        .arg(bdf,
             pciClassName(id.classCode),
             classHex,
             pciVendorName(id.vendor),
             id.product,
             vend,
             dev,
             note.isEmpty() ? QString() : QString("  %1").arg(note));
}

QString formatTopologyPciList(const QJsonObject &topo)
{
    QStringList lines;
    const QString name = topo.value("topology_name").toString("topology");
    lines << QString("# %1").arg(name);
    lines << QStringLiteral("# lspci -nn listing of the emulated fabric");
    lines << QStringLiteral("# This view is built from the topology. A Linux guest image is not required.");
    lines << QString();
    lines << QStringLiteral("00:00.0 Host bridge [0600]: Red Hat, Inc. QEMU Host Bridge [1b36:0008]");

    const QJsonArray rcs = topo.value("root_complexes").toArray();
    for (const QJsonValue &rcv : rcs) {
        const QJsonArray ports = rcv.toObject().value("root_ports").toArray();
        for (int i = 0; i < ports.size(); ++i) {
            if (ports.at(i).isString()) {
                lines << lspciLine(ports.at(i).toString(), QStringLiteral("root-port"),
                                   QString("rp%1").arg(i + 1));
            } else {
                const QJsonObject p = ports.at(i).toObject();
                lines << lspciLine(p.value("bdf").toString(), QStringLiteral("root-port"),
                                   p.value("label").toString(p.value("id").toString("root-port")));
            }
        }
    }

    const QJsonArray switches = topo.value("switches").toArray();
    for (const QJsonValue &swv : switches) {
        const QJsonObject sw = swv.toObject();
        const QString swName = sw.value("name").toString("switch");
        lines << lspciLine(sw.value("upstream_port").toString(), QStringLiteral("switch-up"), swName);
        const QJsonArray dps = sw.value("downstream_ports").toArray();
        for (int d = 0; d < dps.size(); ++d) {
            lines << lspciLine(dps.at(d).toString(), QStringLiteral("switch-dp"),
                               QString("%1_dp%2").arg(swName).arg(d));
        }
    }

    const QJsonArray endpoints = topo.value("endpoints").toArray();
    for (const QJsonValue &epv : endpoints) {
        const QJsonObject ep = epv.toObject();
        const QString display = ep.value("display").toString(ep.value("label").toString("endpoint"));
        const QString label = ep.value("label").toString();
        const QString note = label.isEmpty() || label == display
            ? display
            : QString("%1 (%2)").arg(display, label);
        lines << lspciLine(ep.value("bdf").toString(),
                           ep.value("type").toString(ep.value("label").toString()),
                           note);
    }

    return lines.join('\n');
}

constexpr int kPairRole = Qt::UserRole + 21;

bool isRequestType(const QString &type)
{
    return type.compare(QLatin1String("CfgRd"), Qt::CaseInsensitive) == 0
        || type.compare(QLatin1String("MemRd"), Qt::CaseInsensitive) == 0
        || type.compare(QLatin1String("MemRead"), Qt::CaseInsensitive) == 0
        || type.compare(QLatin1String("CfgRead"), Qt::CaseInsensitive) == 0;
}

bool isCompletionType(const QString &type)
{
    return type.compare(QLatin1String("Cpl"), Qt::CaseInsensitive) == 0
        || type.compare(QLatin1String("CplD"), Qt::CaseInsensitive) == 0
        || type.compare(QLatin1String("Completion"), Qt::CaseInsensitive) == 0;
}

uint16_t parsePciId(const QString &text)
{
    static const QRegularExpression bdfRe(
        QStringLiteral(R"((?:([0-9A-Fa-f]{4}):)?([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})\.([0-9A-Fa-f]))"));
    const QRegularExpressionMatch match = bdfRe.match(text.trimmed());
    if (match.hasMatch()) {
        const uint16_t bus = static_cast<uint16_t>(match.captured(2).toUInt(nullptr, 16));
        const uint16_t dev = static_cast<uint16_t>(match.captured(3).toUInt(nullptr, 16));
        const uint16_t fn = static_cast<uint16_t>(match.captured(4).toUInt(nullptr, 16));
        return static_cast<uint16_t>((bus << 8) | (dev << 3) | fn);
    }
    bool ok = false;
    const uint16_t value = static_cast<uint16_t>(text.trimmed().toUInt(&ok, 0));
    return ok ? value : 0;
}

bool payloadToDword(const QString &payload, uint32_t *out)
{
    QString normalized = payload;
    normalized.remove(' ');
    normalized.remove('\t');
    const QByteArray raw = QByteArray::fromHex(normalized.toLatin1());
    if (raw.size() < 4 || !out) {
        return false;
    }
    uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
        value |= static_cast<uint32_t>(static_cast<unsigned char>(raw.at(i))) << (8 * i);
    }
    *out = value;
    return true;
}

bool looksLikeBdf(const QString &text)
{
    static const QRegularExpression bdfRe(
        QStringLiteral(R"(^(?:[0-9A-Fa-f]{4}:)?[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-9A-Fa-f]$)"));
    return bdfRe.match(text.trimmed()).hasMatch();
}

QString normalizeAddrKey(const QString &addr)
{
    bool ok = false;
    const qulonglong value = addr.trimmed().toULongLong(&ok, 0);
    return ok ? QString::number(value) : addr.trimmed().toLower();
}

bool idsOverlap(const QString &reqRequester,
                const QString &reqCompleter,
                const QString &cplRequester,
                const QString &cplCompleter)
{
    return reqRequester == cplRequester
        || reqCompleter == cplRequester
        || reqRequester == cplCompleter
        || reqCompleter == cplCompleter;
}

QList<QStandardItem *> makeTraceItems(const QString &ts,
                                      const QString &direction,
                                      const QString &type,
                                      const QString &requester,
                                      const QString &completer,
                                      const QString &tag,
                                      const QString &length,
                                      const QString &addr,
                                      const QString &payload,
                                      const QString &role = QString())
{
    auto *payloadItem = new QStandardItem(payload);
    if (!role.isEmpty()) {
        payloadItem->setToolTip(role);
    }
    auto *matchItem = new QStandardItem(QStringLiteral("—"));
    matchItem->setData(-1, kPairRole);
    return {
        new QStandardItem(ts),
        new QStandardItem(direction),
        new QStandardItem(type),
        new QStandardItem(requester),
        new QStandardItem(completer),
        new QStandardItem(tag),
        new QStandardItem(length),
        new QStandardItem(addr),
        payloadItem,
        matchItem
    };
}

void appendTlpRow(QStandardItemModel *model,
                  const QString &direction,
                  const QString &type,
                  const QString &requester,
                  const QString &completer,
                  int tag,
                  const QString &addr,
                  const QString &payload,
                  const QString &role)
{
    const QString ts = QString::number(QDateTime::currentMSecsSinceEpoch())
        + QString(".%1").arg(model->rowCount());
    model->appendRow(makeTraceItems(
        ts, direction, type, requester, completer, QString::number(tag),
        payload.isEmpty() ? QStringLiteral("0") : QStringLiteral("4"),
        addr, payload, role));
}

struct TopologyNode {
    QString bdf;
    QString role;
};

QVector<TopologyNode> topologyNodesFromJson(const QJsonObject &topo)
{
    QVector<TopologyNode> nodes;
    const QJsonArray rcs = topo.value("root_complexes").toArray();
    for (const QJsonValue &rcv : rcs) {
        const QJsonArray ports = rcv.toObject().value("root_ports").toArray();
        for (int i = 0; i < ports.size(); ++i) {
            if (ports.at(i).isString()) {
                nodes.append({ports.at(i).toString(), QString("rp%1").arg(i + 1)});
            } else {
                const QJsonObject p = ports.at(i).toObject();
                nodes.append({p.value("bdf").toString(), p.value("id").toString("root-port")});
            }
        }
    }

    const QJsonArray switches = topo.value("switches").toArray();
    for (const QJsonValue &swv : switches) {
        const QJsonObject sw = swv.toObject();
        const QString name = sw.value("name").toString("switch");
        nodes.append({sw.value("upstream_port").toString(), name});
        const QJsonArray dps = sw.value("downstream_ports").toArray();
        for (int d = 0; d < dps.size(); ++d) {
            nodes.append({dps.at(d).toString(), QString("%1_dp%2").arg(name).arg(d)});
        }
    }

    const QJsonArray endpoints = topo.value("endpoints").toArray();
    for (const QJsonValue &epv : endpoints) {
        const QJsonObject ep = epv.toObject();
        nodes.append({ep.value("bdf").toString(),
                      ep.value("label").toString(ep.value("display").toString("endpoint"))});
    }
    return nodes;
}

void appendCfgReadRows(QStandardItemModel *model, const QString &bdf, const QString &role)
{
    static const uint64_t enumAddrs[] = {0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c};
    const QString target = bdf.isEmpty() ? QStringLiteral("00:00.0") : bdf;
    for (size_t i = 0; i < sizeof(enumAddrs) / sizeof(enumAddrs[0]); ++i) {
        const QString addr = QString("0x%1").arg(enumAddrs[i], 0, 16);
        const int tag = static_cast<int>(i);
        // CfgRd has a 3/4-DW header and no data payload.
        appendTlpRow(model, QStringLiteral("TX"), QStringLiteral("CfgRd"),
                     QStringLiteral("00:00.0"), target, tag, addr, QString(), role);
        // Completer returns one config DWORD as the Cpl data payload.
        appendTlpRow(model, QStringLiteral("RX"), QStringLiteral("Cpl"),
                     target, QStringLiteral("00:00.0"), tag, addr,
                     leDwordPayload(syntheticConfigDword(role, enumAddrs[i])), role);
    }
}

} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , aiPerformanceReadout(nullptr)
    , fabricSizeBox(nullptr)
    , aiEmulatorDialog(nullptr)
    , pcieLsDialog(nullptr)
    , liveTraceTimer(nullptr)
    , liveTraceProcess(nullptr)
    , aiTopologyView(nullptr)
    , aiTopologyPathLabel(nullptr)
    , topologySourceBadge(nullptr)
    , topologyModeCombo(nullptr)
    , topologyFileCombo(nullptr)
    , runTopologyButton(nullptr)
    , topologyRunMode(TopologyRunMode::ZephyrGolden)
    , suppressAiRunnerExitWarning(false)
{
    QWidget *central = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(central);
    QHBoxLayout *toolbar = new QHBoxLayout();
    QHBoxLayout *filterbar = new QHBoxLayout();

    darkMode = false;

    openButton = new QPushButton("Open trace", this);
    saveButton = new QPushButton("Save trace", this);
    auto *reportButton = new QPushButton("Export report", this);
    enumerateButton = new QPushButton("Enumerate PCI", this);
    aiPerfButton = new QPushButton("AI PCIe Emulator", this);
    themeButton = new QPushButton("Dark", this);
    typeFilter = new QComboBox(this);
    directionFilter = new QComboBox(this);
    analysisFilter = new QComboBox(this);
    backendFilter = new QComboBox(this);
    deviceIdBox = new QLineEdit(this);
    scenarioBox = new QLineEdit(this);
    searchBox = new QLineEdit(this);
    statusLabel = new QLabel("No trace loaded", this);
    totalLabel = new QLabel("Total: 0", this);
    txLabel = new QLabel("TX: 0", this);
    rxLabel = new QLabel("RX: 0", this);
    filteredLabel = new QLabel("Visible: 0", this);
    unmatchedLabel = new QLabel("Unmatched: 0", this);

    typeFilter->addItem("All types");
    typeFilter->addItem("CfgRd");
    typeFilter->addItem("CfgWr");
    typeFilter->addItem("MemRd");
    typeFilter->addItem("MemWr");
    typeFilter->addItem("Cpl");

    directionFilter->addItem("All directions");
    directionFilter->addItem("TX");
    directionFilter->addItem("RX");

    analysisFilter->addItem("All packets");
    analysisFilter->addItem("Unmatched");
    analysisFilter->addItem("Matched pairs");

    backendFilter->addItem("pci");
    backendFilter->addItem("dummy");
    backendFilter->setCurrentText("pci");
    backendFilter->hide();

    deviceIdBox->setPlaceholderText("0000:00:03.0");
    deviceIdBox->setText("0000:00:03.0");
    deviceIdBox->hide();
    scenarioBox->setPlaceholderText("gen8x16, latency=250ns, tps=250000");
    scenarioBox->setText("gen8x16,latency=250ns,tps=250000,burst=16,jitter=50ns");
    scenarioBox->hide();
    searchBox->setPlaceholderText("Search type, BDF, tag, address, or payload");

    toolbar->addWidget(openButton);
    toolbar->addWidget(saveButton);
    toolbar->addWidget(reportButton);
    toolbar->addWidget(enumerateButton);
    toolbar->addWidget(aiPerfButton);
    toolbar->addWidget(themeButton);
    toolbar->addStretch();

    filterbar->addWidget(new QLabel("Type:", this));
    filterbar->addWidget(typeFilter);
    filterbar->addWidget(new QLabel("Direction:", this));
    filterbar->addWidget(directionFilter);
    filterbar->addWidget(new QLabel("Analysis:", this));
    filterbar->addWidget(analysisFilter);
    filterbar->addWidget(searchBox, 1);

    QWidget *statsWidget = new QWidget(this);
    QHBoxLayout *statsLayout = new QHBoxLayout(statsWidget);
    statsLayout->setContentsMargins(0, 0, 0, 0);
    statsLayout->setSpacing(12);

    totalLabel->setFrameShape(QFrame::StyledPanel);
    txLabel->setFrameShape(QFrame::StyledPanel);
    rxLabel->setFrameShape(QFrame::StyledPanel);
    filteredLabel->setFrameShape(QFrame::StyledPanel);
    unmatchedLabel->setFrameShape(QFrame::StyledPanel);

    totalLabel->setAlignment(Qt::AlignCenter);
    txLabel->setAlignment(Qt::AlignCenter);
    rxLabel->setAlignment(Qt::AlignCenter);
    filteredLabel->setAlignment(Qt::AlignCenter);
    unmatchedLabel->setAlignment(Qt::AlignCenter);

    totalLabel->setMinimumWidth(120);
    txLabel->setMinimumWidth(120);
    rxLabel->setMinimumWidth(120);
    filteredLabel->setMinimumWidth(140);
    unmatchedLabel->setMinimumWidth(150);

    statsLayout->addWidget(totalLabel);
    statsLayout->addWidget(txLabel);
    statsLayout->addWidget(rxLabel);
    statsLayout->addWidget(filteredLabel);
    statsLayout->addWidget(unmatchedLabel);

    auto *matchLegend = new QLabel(
        "Match: #N = request/completion pair   ·   complete = QEMU one-line cfg access   ·   unmatched = missing Cpl   ·   — = no pair expected",
        this);
    matchLegend->setObjectName("statusLabel");
    matchLegend->setWordWrap(true);

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
        "Payload",
        "Match"
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
    layout->addLayout(filterbar);
    layout->addWidget(statsWidget);
    layout->addWidget(matchLegend);
    layout->addWidget(splitter);
    layout->addWidget(statusLabel);

    setCentralWidget(central);
    setWindowTitle("pcieshark");
    fitToAvailableScreen(this, 1.0);

    applyTheme();

    openButton->setObjectName("openButton");
    themeButton->setObjectName("themeButton");
    statusLabel->setObjectName("statusLabel");
    totalLabel->setObjectName("summaryCard");
    txLabel->setObjectName("summaryCard");
    rxLabel->setObjectName("summaryCard");
    filteredLabel->setObjectName("summaryCard");
    unmatchedLabel->setObjectName("summaryCard");

    connect(openButton, &QPushButton::clicked, this, &MainWindow::openTrace);
    connect(saveButton, &QPushButton::clicked, this, &MainWindow::saveTrace);
    connect(reportButton, &QPushButton::clicked, this, &MainWindow::exportTraceReport);
    connect(enumerateButton, &QPushButton::clicked, this, &MainWindow::enumeratePciDevice);
    connect(aiPerfButton, &QPushButton::clicked, this, &MainWindow::openAiPerfDialog);
    connect(themeButton, &QPushButton::clicked, this, [this]() {
        darkMode = !darkMode;
        applyTheme();
    });
    connect(typeFilter, &QComboBox::currentTextChanged, this, &MainWindow::applyFilter);
    connect(directionFilter, &QComboBox::currentTextChanged, this, &MainWindow::applyFilter);
    connect(analysisFilter, &QComboBox::currentTextChanged, this, &MainWindow::applyFilter);
    connect(searchBox, &QLineEdit::textChanged, this, &MainWindow::applyFilter);
    connect(tableView->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &MainWindow::showPacketDetails);
    connect(tableView, &QTableView::doubleClicked, this, &MainWindow::jumpToPairedPacket);
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
                font-family: "Noto Sans", "DejaVu Sans", "Segoe UI", sans-serif;
                letter-spacing: 0px;
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
            QDialog, QGroupBox {
                background: #0f172a;
                color: #e2e8f0;
            }
            QGroupBox {
                border: 1px solid #334155;
                border-radius: 8px;
                margin-top: 12px;
                padding: 12px 10px 10px 10px;
                font-weight: 600;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
            }
            QTextBrowser {
                background: #0b1220;
                color: #e2e8f0;
                border: 1px solid #334155;
                border-radius: 6px;
            }
            QLabel#topologySourceBadge {
                background: #1e3a5f;
                border: 1px solid #3b82f6;
                border-radius: 6px;
                padding: 8px 10px;
                color: #dbeafe;
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
                font-family: "Noto Sans", "DejaVu Sans", "Segoe UI", sans-serif;
                letter-spacing: 0px;
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
            QDialog, QGroupBox {
                background: #f3f4f6;
                color: #1f2328;
            }
            QGroupBox {
                border: 1px solid #d0d7de;
                border-radius: 8px;
                margin-top: 12px;
                padding: 12px 10px 10px 10px;
                font-weight: 600;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 4px;
            }
            QTextBrowser {
                background: #f8fafc;
                color: #1f2328;
                border: 1px solid #d0d7de;
                border-radius: 6px;
            }
            QLabel#topologySourceBadge {
                background: #eff6ff;
                border: 1px solid #93c5fd;
                border-radius: 6px;
                padding: 8px 10px;
                color: #1e3a8a;
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
    if (loadCustomPcap(path)) {
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

void MainWindow::showPcieLsText(const QString &text)
{
    if (pcieLsDialog) {
        pcieLsDialog->close();
        pcieLsDialog->deleteLater();
        pcieLsDialog = nullptr;
    }

    pcieLsDialog = new QDialog(this);
    pcieLsDialog->setWindowTitle(QString("%1  ·  %2")
                                     .arg(topologyRunMode == TopologyRunMode::LinuxQemu
                                              ? QStringLiteral("lspci")
                                              : QStringLiteral("pcie ls"),
                                          topologyModeTitle()));
    fitToAvailableScreen(pcieLsDialog, 0.75);
    pcieLsDialog->setAttribute(Qt::WA_DeleteOnClose, true);

    QTextBrowser *browser = new QTextBrowser(pcieLsDialog);
    browser->setReadOnly(true);
    browser->setFont(QFont(QStringLiteral("monospace")));
    browser->setPlainText(text);

    QVBoxLayout *layout = new QVBoxLayout(pcieLsDialog);
    layout->addWidget(browser);

    pcieLsDialog->show();
    pcieLsDialog->raise();
    pcieLsDialog->activateWindow();
}

void MainWindow::showPcieLsWindow(const QString &path)
{
    const QStringList entries = extractPcieLsEntries(path);
    if (!entries.isEmpty()) {
        showPcieLsText(entries.join('\n'));
        return;
    }

    QFile file(path);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        const QString raw = QString::fromUtf8(file.readAll()).trimmed();
        if (!raw.isEmpty()) {
            showPcieLsText(raw);
            return;
        }
    }

    if (!currentTopology.isEmpty()) {
        showPcieLsText(formatTopologyPciList(currentTopology));
        return;
    }

    showPcieLsText(QString("No PCI list found.\n\nFile: %1").arg(path));
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
        model->insertRow(model->rowCount(),
                         makeTraceItems(ts, dir, type, requester, completer, tag, length, addr, payload));
        ++added;
    }

    if (added > 0) {
        rebuildTraceAnalysis();
        applyFilter();
        if (model->rowCount() > 0) {
            tableView->selectRow(model->rowCount() - 1);
        }
        updateSummaryStats();
        updateAiPerformanceReadout();
        statusLabel->setText(QString("%1 live trace: %2 entries")
                                 .arg(topologyModeTitle())
                                 .arg(model->rowCount()));
    }

    if (liveTraceProcess && liveTraceProcess->state() == QProcess::NotRunning) {
        liveTraceTimer->stop();
        updateAiPerformanceReadout();
        statusLabel->setText(QString("%1 finished  ·  %2 live entries")
                                 .arg(topologyModeTitle())
                                 .arg(model->rowCount()));
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
        QStringLiteral("pcie_trace.csv"),
        "CSV traces (*.csv);;QEMU logs (*.log *.txt);;All files (*.*)");

    if (path.isEmpty()) {
        return;
    }

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Save failed", "Unable to write trace file: " + path);
        return;
    }

    QTextStream out(&file);
    const bool asLog = path.endsWith(QLatin1String(".log"), Qt::CaseInsensitive)
        || path.endsWith(QLatin1String(".txt"), Qt::CaseInsensitive);
    if (!asLog) {
        out << "timestamp_ns,direction,type,requester_id,completer_id,tag,length,addr,payload\n";
    }
    for (int row = 0; row < model->rowCount(); ++row) {
        const QString ts = model->item(row, 0) ? model->item(row, 0)->text() : QString();
        const QString direction = model->item(row, 1) ? model->item(row, 1)->text() : QString();
        const QString type = model->item(row, 2) ? model->item(row, 2)->text() : QString();
        const QString requester = model->item(row, 3) ? model->item(row, 3)->text() : QString();
        const QString completer = model->item(row, 4) ? model->item(row, 4)->text() : QString();
        const QString tag = model->item(row, 5) ? model->item(row, 5)->text() : QString();
        const QString length = model->item(row, 6) ? model->item(row, 6)->text() : QString();
        const QString addr = model->item(row, 7) ? model->item(row, 7)->text() : QString();
        const QString payload = model->item(row, 8) ? model->item(row, 8)->text() : QString();

        if (asLog) {
            if (addr.isEmpty()) {
                continue;
            }
            const QString op = (type == "CfgWr" || direction == "TX") ? "write" : "read";
            const QString arrow = (op == "write") ? "<-" : "->";
            out << QString("pci_cfg_%1 %2 %3 @%4 %5 %6\n")
                    .arg(op, requester, completer, addr, arrow, payload);
            continue;
        }

        QString escaped = payload;
        escaped.replace('"', "\"\"");
        if (escaped.contains(',') || escaped.contains('"')) {
            escaped = QString("\"%1\"").arg(escaped);
        }
        out << ts << ',' << direction << ',' << type << ','
            << requester << ',' << completer << ',' << tag << ','
            << length << ',' << addr << ',' << escaped << '\n';
    }

    file.close();
    statusLabel->setText(QString("Saved %1 TLP entries to %2").arg(model->rowCount()).arg(path));
}

void MainWindow::exportTraceReport()
{
    if (!model || model->rowCount() == 0) {
        QMessageBox::information(this, "Export report", "There is no trace to report yet.");
        return;
    }

    const QString path = QFileDialog::getSaveFileName(
        this,
        "Export analysis report",
        QStringLiteral("pcieshark_report.html"),
        "HTML report (*.html);;All files (*.*)");
    if (path.isEmpty()) {
        return;
    }

    int tx = 0, rx = 0, cfgRd = 0, cfgWr = 0, memRd = 0, memWr = 0, cpl = 0;
    int matched = 0, complete = 0, unmatched = 0;
    QStringList unmatchedRows;
    QMap<QString, QString> devices;

    for (int row = 0; row < model->rowCount(); ++row) {
        const QString direction = model->index(row, 1).data().toString();
        const QString type = model->index(row, 2).data().toString();
        const QString requester = model->index(row, 3).data().toString();
        const QString completer = model->index(row, 4).data().toString();
        const QString addr = normalizeAddrKey(model->index(row, 7).data().toString());
        const QString payload = model->index(row, 8).data().toString();
        const QString match = model->index(row, 9).data().toString();

        if (direction == QLatin1String("TX")) {
            ++tx;
        } else if (direction == QLatin1String("RX")) {
            ++rx;
        }
        if (type == QLatin1String("CfgRd") || type == QLatin1String("CfgRead")) {
            ++cfgRd;
        } else if (type == QLatin1String("CfgWr") || type == QLatin1String("CfgWrite")) {
            ++cfgWr;
        } else if (type == QLatin1String("MemRd") || type == QLatin1String("MemRead")) {
            ++memRd;
        } else if (type == QLatin1String("MemWr") || type == QLatin1String("MemWrite")) {
            ++memWr;
        } else if (isCompletionType(type)) {
            ++cpl;
        }

        if (match.startsWith(QLatin1Char('#'))) {
            ++matched;
        } else if (match == QLatin1String("complete")) {
            ++complete;
        } else if (match == QLatin1String("unmatched")) {
            ++unmatched;
            if (unmatchedRows.size() < 40) {
                unmatchedRows << QString("#%1  %2  %3 → %4  %5")
                                   .arg(row + 1)
                                   .arg(type, requester, completer, model->index(row, 7).data().toString());
            }
        }

        uint32_t dword = 0;
        if (addr == QLatin1String("0") && payloadToDword(payload, &dword)) {
            const QString bdf = looksLikeBdf(completer) ? completer
                : (looksLikeBdf(requester) ? requester : completer);
            if (!bdf.isEmpty() && !devices.contains(bdf)) {
                const uint16_t vendor = static_cast<uint16_t>(dword & 0xffff);
                const uint16_t device = static_cast<uint16_t>((dword >> 16) & 0xffff);
                devices.insert(bdf, QString("%1  %2 %3")
                                       .arg(pciVendorName(vendor),
                                            makeHexLabel(vendor, 4),
                                            makeHexLabel(device, 4)));
            }
        }
    }

    const QString topoName = currentTopology.value("topology_name").toString();
    QString deviceRows;
    for (auto it = devices.constBegin(); it != devices.constEnd(); ++it) {
        deviceRows += QString("<tr><td>%1</td><td>%2</td></tr>\n")
                          .arg(it.key().toHtmlEscaped(), it.value().toHtmlEscaped());
    }
    if (deviceRows.isEmpty()) {
        deviceRows = QStringLiteral("<tr><td colspan='2'>No vendor/device DWORDs at offset 0x00 in this trace.</td></tr>");
    }

    QString unmatchedHtml;
    if (unmatchedRows.isEmpty()) {
        unmatchedHtml = QStringLiteral("<p>No unmatched requests.</p>");
    } else {
        unmatchedHtml = QStringLiteral("<pre>") + unmatchedRows.join('\n').toHtmlEscaped() + QStringLiteral("</pre>");
        if (unmatched > unmatchedRows.size()) {
            unmatchedHtml += QString("<p>%1 more unmatched rows not listed.</p>").arg(unmatched - unmatchedRows.size());
        }
    }

    const QString html = QStringLiteral(
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>pcieshark analysis report</title>"
        "<style>body{font-family:system-ui,sans-serif;margin:32px;color:#111}"
        "h1{font-size:22px}table{border-collapse:collapse;margin:12px 0}"
        "td,th{border:1px solid #ccc;padding:6px 10px;text-align:left}"
        "th{background:#f3f4f6} .muted{color:#555}</style></head><body>"
        "<h1>pcieshark analysis report</h1>"
        "<p class='muted'>Generated %1</p>"
        "<p>Topology: %2</p>"
        "<h2>Summary</h2>"
        "<table>"
        "<tr><th>Total</th><td>%3</td></tr>"
        "<tr><th>TX / RX</th><td>%4 / %5</td></tr>"
        "<tr><th>CfgRd / CfgWr</th><td>%6 / %7</td></tr>"
        "<tr><th>MemRd / MemWr</th><td>%8 / %9</td></tr>"
        "<tr><th>Completions</th><td>%10</td></tr>"
        "<tr><th>Matched pairs</th><td>%11</td></tr>"
        "<tr><th>Complete (in-line)</th><td>%12</td></tr>"
        "<tr><th>Unmatched</th><td>%13</td></tr>"
        "</table>"
        "<p class='muted'>Match: #N = request/completion pair. "
        "complete = QEMU one-line config access. unmatched = missing Cpl.</p>"
        "<h2>Devices seen (config offset 0x00)</h2>"
        "<table><tr><th>BDF</th><th>Vendor / device</th></tr>%14</table>"
        "<h2>Unmatched requests</h2>%15"
        "</body></html>")
        .arg(QDateTime::currentDateTime().toString(Qt::ISODate),
             (topoName.isEmpty() ? QStringLiteral("none") : topoName).toHtmlEscaped())
        .arg(model->rowCount())
        .arg(tx).arg(rx)
        .arg(cfgRd).arg(cfgWr)
        .arg(memRd).arg(memWr)
        .arg(cpl)
        .arg(matched / 2)
        .arg(complete)
        .arg(unmatched)
        .arg(deviceRows, unmatchedHtml);

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, "Export failed", "Unable to write report: " + path);
        return;
    }
    QTextStream out(&file);
    out << html;
    file.close();

    QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    statusLabel->setText(QString("Exported analysis report to %1").arg(path));
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
        QStringLiteral(R"(^(?:(?<ts>\d+(?:\.\d+)?)\s*:\s*)?pci_cfg_(?<op>read|write)\s+(?<dev>[A-Za-z0-9_.-]+)\s+(?<bdf>(?:[0-9A-Fa-f]{4}:)?[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-9A-Fa-f])\s+@(?<offset>0x[0-9A-Fa-f]+)\s*(?<arrow>->|<-)\s*(?<value>0x[0-9A-Fa-f]+)\s*$)"));

    const QRegularExpressionMatch match = re.match(line.trimmed());
    if (!match.hasMatch()) {
        return false;
    }

    const QString op = match.captured("op");
    const QString device = match.captured("dev");
    const QString bdf = match.captured("bdf");
    const QString offset = match.captured("offset");
    const QString value = match.captured("value");

    *ts = match.captured("ts");
    if (ts->isEmpty()) {
        *ts = QString::number(QDateTime::currentMSecsSinceEpoch());
    }
    *direction = (op == "write") ? QStringLiteral("TX") : QStringLiteral("RX");
    *type = (op == "write") ? QStringLiteral("CfgWr") : QStringLiteral("CfgRd");
    *requester = device;
    *completer = bdf;
    *tag = QStringLiteral("0");
    *length = QStringLiteral("4");
    *addr = offset;
    bool ok = false;
    const uint32_t dword = value.toUInt(&ok, 0);
    *payload = ok ? leDwordPayload(dword) : value;
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

            model->insertRow(row, makeTraceItems(ts, dir, type, requester, completer, tag, length, addr, payload));
            ++row;
            continue;
        }

        QString ts, dir, type, requester, completer, tag, length, addr, payload;
        if (!parseRawTraceLine(line, &ts, &dir, &type, &requester, &completer, &tag, &length, &addr, &payload)) {
            continue;
        }

        model->insertRow(row, makeTraceItems(ts, dir, type, requester, completer, tag, length, addr, payload));
        ++row;
    }

    rebuildTraceAnalysis();
    applyFilter();
    if (model->rowCount() > 0) {
        tableView->selectRow(0);
    }
    updateSummaryStats();
    statusLabel->setText(QString("Loaded %1 TLP entries from %2").arg(row).arg(path));
}

void MainWindow::rebuildTraceAnalysis()
{
    if (!model) {
        return;
    }

    const int rows = model->rowCount();
    QVector<int> pending;
    pending.reserve(rows);

    for (int row = 0; row < rows; ++row) {
        auto *matchItem = model->item(row, 9);
        if (!matchItem) {
            matchItem = new QStandardItem(QStringLiteral("—"));
            model->setItem(row, 9, matchItem);
        }
        matchItem->setText(QStringLiteral("—"));
        matchItem->setData(-1, kPairRole);
        matchItem->setToolTip(QString());
    }

    auto rowType = [this](int row) {
        return model->index(row, 2).data().toString();
    };
    auto hasPayload = [this](int row) {
        return !model->index(row, 8).data().toString().trimmed().isEmpty();
    };

    for (int row = 0; row < rows; ++row) {
        const QString type = rowType(row);
        if (isRequestType(type)) {
            if (hasPayload(row)) {
                auto *matchItem = model->item(row, 9);
                if (matchItem) {
                    matchItem->setText(QStringLiteral("complete"));
                    matchItem->setToolTip(QStringLiteral(
                        "This config access already includes the returned DWORD. "
                        "QEMU pci_cfg logs are not split into a separate Cpl."));
                }
                continue;
            }
            pending.append(row);
            continue;
        }
        if (!isCompletionType(type)) {
            continue;
        }

        const QString cplTag = model->index(row, 5).data().toString();
        const QString cplAddr = normalizeAddrKey(model->index(row, 7).data().toString());
        const QString cplReq = model->index(row, 3).data().toString();
        const QString cplCpl = model->index(row, 4).data().toString();

        int match = -1;
        for (int i = 0; i < pending.size(); ++i) {
            const int reqRow = pending.at(i);
            const QString reqTag = model->index(reqRow, 5).data().toString();
            const QString reqAddr = normalizeAddrKey(model->index(reqRow, 7).data().toString());
            const QString reqReq = model->index(reqRow, 3).data().toString();
            const QString reqCpl = model->index(reqRow, 4).data().toString();
            if (reqTag != cplTag) {
                continue;
            }
            if (!reqAddr.isEmpty() && !cplAddr.isEmpty() && reqAddr != cplAddr) {
                continue;
            }
            if (!idsOverlap(reqReq, reqCpl, cplReq, cplCpl)) {
                continue;
            }
            match = reqRow;
            pending.removeAt(i);
            break;
        }

        if (match < 0) {
            continue;
        }

        auto *reqMatch = model->item(match, 9);
        auto *cplMatch = model->item(row, 9);
        if (reqMatch) {
            reqMatch->setText(QString("#%1").arg(row + 1));
            reqMatch->setData(row, kPairRole);
            reqMatch->setToolTip(QStringLiteral("Completion at packet %1").arg(row + 1));
        }
        if (cplMatch) {
            cplMatch->setText(QString("#%1").arg(match + 1));
            cplMatch->setData(match, kPairRole);
            cplMatch->setToolTip(QStringLiteral("Request at packet %1").arg(match + 1));
        }
    }

    for (int reqRow : pending) {
        auto *matchItem = model->item(reqRow, 9);
        if (matchItem) {
            matchItem->setText(QStringLiteral("unmatched"));
            matchItem->setToolTip(QStringLiteral("No matching completion (Cpl)"));
        }
    }
}

bool MainWindow::loadCustomPcap(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }

    QByteArray header = file.read(28);
    if (header.size() < 28) {
        return false;
    }

    const auto u32 = [](const QByteArray &buf, int off) {
        const auto *p = reinterpret_cast<const uchar *>(buf.constData() + off);
        return static_cast<quint32>(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
    };
    const quint32 magic = u32(header, 0);
    if (magic != 0xa1b2c3d4U && magic != 0xd4c3b2a1U) {
        return false;
    }

    model->removeRows(0, model->rowCount());
    int row = 0;
    while (!file.atEnd()) {
        const QByteArray pktHdr = file.read(16);
        if (pktHdr.size() < 16) {
            break;
        }
        const quint32 tsSec = u32(pktHdr, 0);
        const quint32 tsUsec = u32(pktHdr, 4);
        const quint32 inclLen = u32(pktHdr, 8);
        if (inclLen == 0 || inclLen > 4096) {
            return row > 0;
        }
        const QByteArray body = file.read(inclLen);
        if (body.size() < static_cast<int>(inclLen) || body.size() < 20) {
            break;
        }

        int off = 0;
        const quint8 direction = static_cast<quint8>(body.at(off++));
        const quint8 typeCode = static_cast<quint8>(body.at(off++));
        quint16 requester = 0;
        quint16 completer = 0;
        memcpy(&requester, body.constData() + off, 2);
        off += 2;
        memcpy(&completer, body.constData() + off, 2);
        off += 2;
        const quint8 tag = static_cast<quint8>(body.at(off++));
        quint16 length = 0;
        memcpy(&length, body.constData() + off, 2);
        off += 2;
        quint64 addr = 0;
        memcpy(&addr, body.constData() + off, 8);
        off += 8;
        const QByteArray payload = body.mid(off);
        QString payloadHex;
        const int n = qMin(payload.size(), length > 0 ? static_cast<int>(length) : payload.size());
        for (int i = 0; i < n; ++i) {
            payloadHex += QString("%1").arg(static_cast<unsigned char>(payload.at(i)), 2, 16, QLatin1Char('0'));
            if (i + 1 < n) {
                payloadHex += ' ';
            }
        }

        const QString ts = QString::number(static_cast<qulonglong>(tsSec) * 1000000000ULL
                                           + static_cast<qulonglong>(tsUsec) * 1000ULL);
        model->insertRow(row, makeTraceItems(
            ts,
            (direction == 2) ? QStringLiteral("RX") : QStringLiteral("TX"),
            sanitizeType(QString::number(typeCode)),
            QString::number(requester),
            QString::number(completer),
            QString::number(tag),
            QString::number(length),
            QString("0x%1").arg(addr, 0, 16),
            payloadHex));
        ++row;
    }

    if (row == 0) {
        return false;
    }

    rebuildTraceAnalysis();
    applyFilter();
    if (model->rowCount() > 0) {
        tableView->selectRow(0);
    }
    updateSummaryStats();
    statusLabel->setText(QString("Loaded %1 TLP entries from %2").arg(row).arg(path));
    return true;
}

void MainWindow::jumpToPairedPacket(const QModelIndex &index)
{
    if (!index.isValid() || !model) {
        return;
    }
    auto *matchItem = model->item(index.row(), 9);
    if (!matchItem) {
        return;
    }
    const int pair = matchItem->data(kPairRole).toInt();
    if (pair < 0 || pair >= model->rowCount()) {
        return;
    }
    tableView->selectRow(pair);
    tableView->scrollTo(model->index(pair, 0));
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

QString MainWindow::repoRootPath() const
{
    const QString script = findRepoPath({"scripts/run_zephyr_ai_topology.sh"});
    if (script.isEmpty()) {
        return QDir::currentPath();
    }
    QFileInfo info(script);
    if (info.fileName() == QLatin1String("run_zephyr_ai_topology.sh")) {
        return QDir::cleanPath(info.absolutePath() + "/..");
    }
    return info.absolutePath();
}

QString MainWindow::resolveZephyrScript() const
{
    return findRepoPath({"scripts/run_zephyr_ai_topology.sh"});
}

QString MainWindow::resolveLinuxScript() const
{
    return findRepoPath({"scripts/run_linux_ai_topology.sh"});
}

QString MainWindow::resolveTopologyScript() const
{
    if (topologyRunMode == TopologyRunMode::LinuxQemu) {
        return resolveLinuxScript();
    }
    return resolveZephyrScript();
}

QString MainWindow::topologyModeEnv() const
{
    switch (topologyRunMode) {
        case TopologyRunMode::ZephyrGolden:
            return QStringLiteral("zephyr-golden");
        case TopologyRunMode::LinuxQemu:
            return QStringLiteral("linux-golden");
        case TopologyRunMode::JsonFile:
            return QStringLiteral("json-file");
        case TopologyRunMode::Generated:
            return QStringLiteral("generated");
    }
    return QStringLiteral("generated");
}

QStringList MainWindow::listConfigTopologyFiles() const
{
    const QString configDir = findRepoPath({"config"});
    QDir dir;
    if (configDir.endsWith(QLatin1String(".json"))) {
        dir = QFileInfo(configDir).absoluteDir();
    } else {
        dir = QDir(configDir);
    }
    QStringList files;
    const QStringList names = dir.entryList({"*.json"}, QDir::Files, QDir::Name);
    for (const QString &name : names) {
        files << dir.absoluteFilePath(name);
    }
    return files;
}

QString MainWindow::topologyTraceFileName() const
{
    if (topologyRunMode == TopologyRunMode::ZephyrGolden) {
        return QStringLiteral("zephyr_ai_topology_trace.log");
    }
    if (topologyRunMode == TopologyRunMode::LinuxQemu) {
        return QStringLiteral("linux_ai_topology_trace.log");
    }
    if (topologyRunMode == TopologyRunMode::JsonFile) {
        const QString stem = QFileInfo(currentTopologyJsonPath).completeBaseName();
        return QStringLiteral("zephyr_%1_trace.log").arg(stem.isEmpty() ? QStringLiteral("json") : stem);
    }
    return QStringLiteral("zephyr_generated_trace.log");
}

QString MainWindow::activeTopologyJsonPath(const QString &workDir)
{
    if (topologyRunMode == TopologyRunMode::ZephyrGolden
        || topologyRunMode == TopologyRunMode::LinuxQemu) {
        currentTopologyJsonPath.clear();
        return QString();
    }
    if (topologyRunMode == TopologyRunMode::JsonFile && !currentTopologyJsonPath.isEmpty()
        && QFileInfo::exists(currentTopologyJsonPath)) {
        return currentTopologyJsonPath;
    }
    return materializeCurrentTopology(workDir);
}

QString MainWindow::topologyModeTitle() const
{
    switch (topologyRunMode) {
        case TopologyRunMode::ZephyrGolden:
            return QStringLiteral("Zephyr golden runner");
        case TopologyRunMode::LinuxQemu:
            return QStringLiteral("Linux QEMU runner");
        case TopologyRunMode::JsonFile:
            return QStringLiteral("JSON topology");
        case TopologyRunMode::Generated:
            return QStringLiteral("Generated topology");
    }
    return QStringLiteral("Topology");
}

void MainWindow::updateTopologySourceUi()
{
    const QString name = currentTopology.value("topology_name").toString("unnamed");
    QString detail;
    QString badge;

    if (topologyRunMode == TopologyRunMode::ZephyrGolden) {
        badge = QStringLiteral("Zephyr golden fabric");
        detail = name;
    } else if (topologyRunMode == TopologyRunMode::LinuxQemu) {
        badge = QStringLiteral("Linux QEMU golden fabric");
        detail = name;
    } else if (topologyRunMode == TopologyRunMode::JsonFile) {
        badge = QStringLiteral("Custom topology");
        detail = name;
    } else {
        badge = QStringLiteral("Generated topology");
        detail = name;
    }

    if (topologySourceBadge) {
        topologySourceBadge->setText(badge + QStringLiteral("  ·  ") + detail);
    }
    if (aiTopologyPathLabel) {
        aiTopologyPathLabel->setText(detail);
        aiTopologyPathLabel->hide();
    }
    if (runTopologyButton) {
        if (topologyRunMode == TopologyRunMode::ZephyrGolden) {
            runTopologyButton->setText("Run Zephyr golden");
        } else if (topologyRunMode == TopologyRunMode::LinuxQemu) {
            runTopologyButton->setText("Run Linux QEMU");
        } else if (topologyRunMode == TopologyRunMode::JsonFile) {
            runTopologyButton->setText("Run custom topology");
        } else {
            runTopologyButton->setText("Run generated topology");
        }
    }
    if (topologyFileCombo) {
        topologyFileCombo->setEnabled(topologyRunMode == TopologyRunMode::JsonFile);
    }
    if (fabricSizeBox) {
        fabricSizeBox->setVisible(topologyRunMode == TopologyRunMode::Generated);
    }
}

QJsonObject MainWindow::goldenTopologyObject() const
{
    QJsonObject rp1{{"id", "rp1"}, {"bdf", "00:01.0"}, {"addr", "01.0"}, {"label", "Compute Hub 1"}, {"secondary_bus", "01"}};
    QJsonObject rp2{{"id", "rp2"}, {"bdf", "00:01.1"}, {"addr", "01.1"}, {"label", "Compute Hub 2"}, {"secondary_bus", "07"}};
    QJsonObject rp3{{"id", "rp3"}, {"bdf", "00:01.2"}, {"addr", "01.2"}, {"label", "Storage Array 1"}, {"secondary_bus", "13"}};
    QJsonObject rp4{{"id", "rp4"}, {"bdf", "00:01.3"}, {"addr", "01.3"}, {"label", "Storage Array 2"}, {"secondary_bus", "19"}};

    QJsonObject rc;
    rc.insert("domain", "0000");
    rc.insert("root_bus", "00");
    rc.insert("label", "CPU Complex");
    rc.insert("root_ports", QJsonArray{rp1, rp2, rp3, rp4});

    auto makeSwitch = [](const char *name, const char *parent, const char *up, const char *dp0, const char *dp1) {
        QJsonObject sw;
        sw.insert("name", name);
        sw.insert("parent", parent);
        sw.insert("upstream_port", up);
        sw.insert("downstream_ports", QJsonArray{dp0, dp1});
        sw.insert("p2p_allowed", true);
        return sw;
    };

    auto makeEp = [](const char *bdf, const char *type, const char *label, const char *display,
                     const char *parent, const char *serial = nullptr, int peer = 0) {
        QJsonObject ep;
        ep.insert("bdf", bdf);
        ep.insert("type", type);
        ep.insert("label", label);
        ep.insert("display", display);
        ep.insert("parent", parent);
        if (serial) {
            ep.insert("serial", serial);
        }
        if (peer > 0) {
            ep.insert("peer_group", peer);
        }
        return ep;
    };

    QJsonObject topo;
    topo.insert("topology_name", "AI golden topology");
    topo.insert("root_complexes", QJsonArray{rc});
    topo.insert("switches", QJsonArray{
        makeSwitch("switch0", "rp1", "01:00.0", "02:00.0", "02:01.0"),
        makeSwitch("switch1", "rp2", "07:00.0", "08:00.0", "08:01.0"),
        makeSwitch("switch2", "rp3", "13:00.0", "14:00.0", "14:01.0"),
        makeSwitch("switch3", "rp4", "19:00.0", "20:00.0", "20:01.0"),
    });
    topo.insert("endpoints", QJsonArray{
        makeEp("03:00.0", "GPU_ACCEL", "ai1", "GPU 1", "switch0_dp0", "AI_ACCEL_01", 1),
        makeEp("05:00.0", "GPU_ACCEL", "ai2", "GPU 2", "switch0_dp1", "AI_ACCEL_02", 1),
        makeEp("09:00.0", "GPU_ACCEL", "ai3", "GPU 3", "switch1_dp0", "AI_ACCEL_03", 2),
        makeEp("0b:00.0", "GPU_ACCEL", "ai4", "GPU 4", "switch1_dp1", "AI_ACCEL_04", 2),
        makeEp("15:00.0", "NVME", "nvme1", "NVMe 1", "switch2_dp0", "DATA_POOL_01"),
        makeEp("17:00.0", "NVME", "nvme2", "NVMe 2", "switch2_dp1", "DATA_POOL_02"),
        makeEp("21:00.0", "NIC_SMART", "eth1", "SmartNIC", "switch3_dp0"),
        makeEp("23:00.0", "NIC_SMART", "eth2", "SmartNIC", "switch3_dp1"),
    });
    return topo;
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
    updateTopologySourceUi();
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

    rebuildTraceAnalysis();
    applyFilter();
    if (model->rowCount() > 0) {
        tableView->selectRow(0);
    }
    updateSummaryStats();
}

void MainWindow::enumeratePciDevice()
{
    QDialog dlg(this);
    dlg.setWindowTitle("Enumerate PCI");
    dlg.resize(420, 160);

    auto *form = new QFormLayout(&dlg);
    form->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    form->setFieldGrowthPolicy(QFormLayout::ExpandingFieldsGrow);

    auto *backend = new QComboBox(&dlg);
    for (int i = 0; i < backendFilter->count(); ++i) {
        backend->addItem(backendFilter->itemText(i));
    }
    backend->setCurrentText(backendFilter->currentText());

    auto *device = new QLineEdit(deviceIdBox->text(), &dlg);
    device->setPlaceholderText("0000:00:03.0");

    form->addRow("Backend", backend);
    form->addRow("Device", device);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    buttons->button(QDialogButtonBox::Ok)->setText("Enumerate");
    form->addRow(buttons);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() != QDialog::Accepted) {
        return;
    }

    backendFilter->setCurrentText(backend->currentText());
    deviceIdBox->setText(device->text());

    QString backendName = backendFilter->currentText();
    const QString deviceId = deviceIdBox->text().trimmed();

    if (!deviceId.isEmpty() && backendName == "pci") {
        setenv("PCIE_PCI_DEVICE", deviceId.toLocal8Bit().constData(), 1);
    } else {
        unsetenv("PCIE_PCI_DEVICE");
    }

    unsetenv("PCIE_DUMMY_SCENARIO");
    unsetenv("PCIE_DUMMY_PROFILE");

    pcie_ctx_t *ctx = pcie_open(backendName.toLocal8Bit().constData());
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
        model->insertRow(static_cast<int>(i),
                         makeTraceItems(ts, QStringLiteral("TX"), QStringLiteral("CfgRd"),
                                        QStringLiteral("1"), QStringLiteral("0"),
                                        QStringLiteral("15"), QStringLiteral("4"),
                                        QString("0x%1").arg(enumAddrs[i], 0, 16), payloadHex));
    }

    pcie_close(ctx);

    rebuildTraceAnalysis();
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

void MainWindow::measureDeployedTopologyPerformance()
{
    if (currentTopology.isEmpty()) {
        currentTopology = goldenTopologyObject();
        renderCurrentTopology();
    }

    const QVector<TopologyNode> nodes = topologyNodesFromJson(currentTopology);
    if (nodes.isEmpty()) {
        QMessageBox::warning(this, "Measure failed",
                             "The current topology has no devices to walk.");
        return;
    }

    // Do not apply dummy throttle/latency. Those would invent tokens/sec.
    unsetenv("PCIE_DUMMY_SCENARIO");
    unsetenv("PCIE_DUMMY_PROFILE");
    unsetenv("PCIE_DUMMY_LATENCY_NS");
    unsetenv("PCIE_DUMMY_TOKENS_PER_SEC");
    unsetenv("PCIE_DUMMY_JITTER_NS");
    unsetenv("PCIE_DUMMY_DROP_RATE");

    pcie_ctx_t *ctx = pcie_open("dummy");
    if (!ctx) {
        QMessageBox::warning(this, "Measure failed",
                             "Unable to open the dummy backend to time config reads.");
        return;
    }

    static const uint32_t enumAddrs[] = {0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c};
    const int addrs = static_cast<int>(sizeof(enumAddrs) / sizeof(enumAddrs[0]));
    const qint64 minNs = 50LL * 1000LL * 1000LL;
    const int maxRounds = 64;
    int txns = 0;
    int rounds = 0;
    bool failed = false;

    QElapsedTimer timer;
    timer.start();
    do {
        for (const TopologyNode &node : nodes) {
            for (int i = 0; i < addrs; ++i) {
                pcie_tlp_t cfgRead = pcie_tlp_cfg_read(enumAddrs[i]);
                uint8_t payload[4] = {0};
                cfgRead.requester_id = 0x0000;
                cfgRead.completer_id = 0;
                cfgRead.tag = static_cast<uint8_t>(i);
                cfgRead.length = 4;
                cfgRead.mem.data = payload;
                if (pcie_send(ctx, &cfgRead) != 0) {
                    failed = true;
                    break;
                }
                ++txns;
            }
            if (failed) {
                break;
            }
        }
        ++rounds;
    } while (!failed && timer.nsecsElapsed() < minNs && rounds < maxRounds);
    const qint64 elapsedNs = timer.nsecsElapsed();
    pcie_close(ctx);

    if (failed || txns == 0 || elapsedNs <= 0) {
        QMessageBox::warning(this, "Measure failed",
                             "Config-space walk did not complete on the deployed topology.");
        return;
    }

    lastPerfDevices = nodes.size();
    lastPerfTxns = txns;
    lastPerfElapsedNs = elapsedNs;
    lastPerfCfgPerSec = (static_cast<double>(txns) * 1e9) / static_cast<double>(elapsedNs);

    injectFabricEnumerationPackets();
    updateAiPerformanceReadout();
    statusLabel->setText(QString("Measured %1 devices on %2  ·  %3 cfg/s")
                             .arg(lastPerfDevices)
                             .arg(currentTopology.value("topology_name").toString("topology"))
                             .arg(lastPerfCfgPerSec, 0, 'f', 0));
}

void MainWindow::openAiPerfDialog()
{
    if (!aiEmulatorDialog) {
        aiEmulatorDialog = new QDialog(this);
        aiEmulatorDialog->setWindowTitle("AI PCIe Emulator");
        aiEmulatorDialog->setAttribute(Qt::WA_DeleteOnClose, false);
        aiEmulatorDialog->setModal(false);
        aiEmulatorDialog->setSizeGripEnabled(true);

        QVBoxLayout *mainLayout = new QVBoxLayout(aiEmulatorDialog);
        mainLayout->setContentsMargins(16, 16, 16, 16);
        mainLayout->setSpacing(10);

        auto *sourceBox = new QGroupBox("Topology source", aiEmulatorDialog);
        auto *sourceLayout = new QGridLayout(sourceBox);
        sourceLayout->setContentsMargins(10, 8, 10, 8);
        sourceLayout->setHorizontalSpacing(10);
        sourceLayout->setVerticalSpacing(6);

        topologyModeCombo = new QComboBox(sourceBox);
        topologyModeCombo->addItem("Zephyr golden runner", static_cast<int>(TopologyRunMode::ZephyrGolden));
        topologyModeCombo->addItem("Linux QEMU runner", static_cast<int>(TopologyRunMode::LinuxQemu));
        topologyModeCombo->addItem("Generated from fields", static_cast<int>(TopologyRunMode::Generated));

        topologyFileCombo = nullptr;
        QPushButton *generateTopoButton = new QPushButton("Generate from fields", sourceBox);

        topologySourceBadge = new QLabel(sourceBox);
        topologySourceBadge->setObjectName("topologySourceBadge");
        topologySourceBadge->setWordWrap(false);

        aiTopologyPathLabel = new QLabel("Topology: (none)", sourceBox);
        aiTopologyPathLabel->setWordWrap(true);
        aiTopologyPathLabel->hide();

        sourceLayout->addWidget(new QLabel("Run mode", sourceBox), 0, 0);
        sourceLayout->addWidget(topologyModeCombo, 0, 1);
        sourceLayout->addWidget(generateTopoButton, 0, 2);
        sourceLayout->addWidget(topologySourceBadge, 1, 0, 1, 3);
        sourceLayout->setColumnStretch(1, 1);

        QTextBrowser *topologyView = new QTextBrowser(aiEmulatorDialog);
        topologyView->setOpenExternalLinks(false);
        topologyView->setReadOnly(true);
        topologyView->setMinimumHeight(320);
        topologyView->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        aiTopologyView = topologyView;

        aiPerformanceReadout = new QLabel(aiEmulatorDialog);
        aiPerformanceReadout->setObjectName("summaryCard");
        aiPerformanceReadout->setWordWrap(true);
        aiPerformanceReadout->setTextFormat(Qt::RichText);
        aiPerformanceReadout->setTextInteractionFlags(Qt::TextSelectableByMouse);

        auto *workloadBox = new QGroupBox("Fabric size", aiEmulatorDialog);
        fabricSizeBox = workloadBox;
        auto *form = new QGridLayout(workloadBox);
        form->setContentsMargins(10, 8, 10, 8);
        form->setHorizontalSpacing(12);
        form->setVerticalSpacing(6);

        auto makeFormLabel = [workloadBox](const QString &text) {
            auto *label = new QLabel(text, workloadBox);
            label->setMinimumWidth(110);
            return label;
        };

        QComboBox *preset = new QComboBox(workloadBox);
        preset->addItem("Golden fabric");
        preset->addItem("Wider mesh");
        preset->addItem("Dense fabric");
        preset->addItem("Custom");
        preset->setCurrentText("Golden fabric");

        QSpinBox *rootPorts = new QSpinBox(workloadBox);
        rootPorts->setRange(1, 16);
        rootPorts->setValue(4);
        QSpinBox *endpointPerRoot = new QSpinBox(workloadBox);
        endpointPerRoot->setRange(1, 16);
        endpointPerRoot->setValue(2);

        form->addWidget(makeFormLabel("Preset"), 0, 0);
        form->addWidget(preset, 0, 1);
        form->addWidget(makeFormLabel("Root ports"), 0, 2);
        form->addWidget(rootPorts, 0, 3);
        form->addWidget(makeFormLabel("Endpoints / root"), 1, 0);
        form->addWidget(endpointPerRoot, 1, 1);
        form->setColumnStretch(1, 1);
        form->setColumnStretch(3, 1);

        runTopologyButton = new QPushButton("Run Zephyr golden", aiEmulatorDialog);
        QPushButton *measureButton = new QPushButton("Measure performance", aiEmulatorDialog);
        QPushButton *pcieLsButton = new QPushButton("Show guest PCI list", aiEmulatorDialog);
        auto *closeButton = new QPushButton("Close", aiEmulatorDialog);
        auto *actionButtons = new QDialogButtonBox(Qt::Horizontal, aiEmulatorDialog);
        actionButtons->addButton(runTopologyButton, QDialogButtonBox::ActionRole);
        actionButtons->addButton(measureButton, QDialogButtonBox::ActionRole);
        actionButtons->addButton(pcieLsButton, QDialogButtonBox::ActionRole);
        actionButtons->addButton(closeButton, QDialogButtonBox::ActionRole);

        workloadBox->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);

        mainLayout->addWidget(sourceBox, 0);
        mainLayout->addWidget(topologyView, 1);
        mainLayout->addWidget(workloadBox, 0);
        mainLayout->addWidget(aiPerformanceReadout, 0);
        mainLayout->addWidget(actionButtons, 0);

        auto loadGolden = [this]() {
            currentTopology = goldenTopologyObject();
            currentTopologyJsonPath.clear();
            renderCurrentTopology();
            return true;
        };

        auto applyWorkload = [rootPorts, endpointPerRoot](int index) {
            switch (index) {
                case 0:
                    rootPorts->setValue(4);
                    endpointPerRoot->setValue(2);
                    break;
                case 1:
                    rootPorts->setValue(8);
                    endpointPerRoot->setValue(2);
                    break;
                case 2:
                    rootPorts->setValue(8);
                    endpointPerRoot->setValue(4);
                    break;
                default:
                    break;
            }
        };

        auto applyMode = [this, loadGolden, rootPorts, endpointPerRoot, pcieLsButton](int index) {
            topologyRunMode = static_cast<TopologyRunMode>(topologyModeCombo->itemData(index).toInt());
            if (topologyRunMode == TopologyRunMode::ZephyrGolden
                || topologyRunMode == TopologyRunMode::LinuxQemu) {
                loadGolden();
            } else {
                currentTopology = generateTopologyFromCounts(rootPorts->value(), endpointPerRoot->value());
                currentTopologyJsonPath.clear();
                renderCurrentTopology();
            }
            pcieLsButton->setText(topologyRunMode == TopologyRunMode::LinuxQemu
                                      ? QStringLiteral("Show lspci")
                                      : QStringLiteral("Show pcie ls"));
            updateTopologySourceUi();
        };

        connect(topologyModeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), applyMode);
        connect(generateTopoButton, &QPushButton::clicked, this, [this, rootPorts, endpointPerRoot]() {
            topologyRunMode = TopologyRunMode::Generated;
            const int generatedIndex = topologyModeCombo->findData(static_cast<int>(TopologyRunMode::Generated));
            if (generatedIndex >= 0) {
                topologyModeCombo->setCurrentIndex(generatedIndex);
            }
            currentTopology = generateTopologyFromCounts(rootPorts->value(), endpointPerRoot->value());
            currentTopologyJsonPath.clear();
            renderCurrentTopology();
        });
        connect(preset, QOverload<int>::of(&QComboBox::currentIndexChanged), applyWorkload);
        connect(runTopologyButton, &QPushButton::clicked, this, [this, rootPorts, endpointPerRoot]() {
            if (currentTopology.isEmpty()) {
                currentTopology = generateTopologyFromCounts(rootPorts->value(), endpointPerRoot->value());
            }
            renderCurrentTopology();
            injectFabricEnumerationPackets();

            const QString resolvedScript = resolveTopologyScript();
            if (resolvedScript.isEmpty()) {
                statusLabel->setText(QString("%1 enumerated in-process (QEMU runner not found)")
                                         .arg(topologyModeTitle()));
                QMessageBox::information(this, "Topology enumerated",
                                         "The selected fabric was walked and CfgRd traffic was generated. "
                                         "The live QEMU topology runner is not available.");
                return;
            }

            const QString workingDir = QDir::cleanPath(QFileInfo(resolvedScript).absolutePath() + "/..");
            const QString topoPath = activeTopologyJsonPath(workingDir);
            const QString traceLog = QDir(workingDir).filePath(topologyTraceFileName());
            statusLabel->setText(QString("Starting %1  ·  %2")
                                     .arg(topologyModeTitle(), currentTopology.value("topology_name").toString()));

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
            liveTraceProcess->setArguments({resolvedScript});
            liveTraceProcess->setProcessChannelMode(QProcess::MergedChannels);
            QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
            if (!topoPath.isEmpty()) {
                env.insert("TOPOLOGY_JSON", topoPath);
            }
            env.insert("TRACE_LOG", traceLog);
            env.insert("PCIE_HEADLESS", "1");
            env.insert("TOPOLOGY_MODE", topologyModeEnv());
            liveTraceProcess->setProcessEnvironment(env);

            connect(liveTraceProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                    this, [this, traceLog](int exitCode, QProcess::ExitStatus status) {
                        if (suppressAiRunnerExitWarning) {
                            suppressAiRunnerExitWarning = false;
                            return;
                        }
                        const QString runnerOut = liveTraceProcess
                            ? QString::fromLocal8Bit(liveTraceProcess->readAll()).trimmed()
                            : QString();
                        QString logTail;
                        QFile logFile(traceLog);
                        if (logFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
                            const QString all = QString::fromUtf8(logFile.readAll());
                            const QStringList lines = all.split('\n');
                            logTail = lines.mid(qMax(0, lines.size() - 12)).join('\n').trimmed();
                        }
                        if (status == QProcess::CrashExit || exitCode != 0) {
                            QString detail = runnerOut;
                            if (detail.isEmpty()) {
                                detail = logTail;
                            }
                            if (detail.isEmpty()) {
                                detail = QStringLiteral("No runner output was captured.");
                            }
                            statusLabel->setText(QString("%1 failed  ·  see dialog for QEMU output")
                                                     .arg(topologyModeTitle()));
                            QMessageBox::warning(this, "Topology run failed",
                                                 QString("%1 exited with code %2.\n\n%3")
                                                     .arg(topologyModeTitle())
                                                     .arg(exitCode)
                                                     .arg(detail.left(1200)));
                            return;
                        }
                        if (QFileInfo::exists(traceLog)) {
                            loadTraceFile(traceLog);
                            statusLabel->setText(QString("%1 finished  ·  %2 entries")
                                                     .arg(topologyModeTitle())
                                                     .arg(model->rowCount()));
                        }
                    });

            liveTraceProcess->start();
            statusLabel->setText(QString("%1 started  ·  %2")
                                     .arg(topologyModeTitle(), currentTopology.value("topology_name").toString()));
        });
        connect(measureButton, &QPushButton::clicked, this, [this]() {
            measureDeployedTopologyPerformance();
        });
        connect(pcieLsButton, &QPushButton::clicked, this, [this]() {
            if (currentTopology.isEmpty()) {
                currentTopology = goldenTopologyObject();
            }

            // Linux listing is the golden fabric. A guest disk/kernel is not required.
            if (topologyRunMode == TopologyRunMode::LinuxQemu
                || topologyRunMode == TopologyRunMode::Generated
                || resolveTopologyScript().isEmpty()) {
                showPcieLsText(formatTopologyPciList(currentTopology));
                statusLabel->setText(QString("PCI list for %1").arg(topologyModeTitle()));
                return;
            }

            const QString resolvedScript = resolveTopologyScript();
            const QString workingDir = QDir::cleanPath(QFileInfo(resolvedScript).absolutePath() + "/..");
            const QString stem = QFileInfo(activeTopologyJsonPath(workingDir)).completeBaseName();
            const QString pcieLsLog = QDir(workingDir).filePath(
                topologyRunMode == TopologyRunMode::ZephyrGolden
                    ? QStringLiteral("zephyr_pcie_ls.log")
                    : QString("zephyr_%1_pcie_ls.log").arg(stem.isEmpty() ? QStringLiteral("json") : stem));

            QProcess *proc = new QProcess(this);
            proc->setWorkingDirectory(workingDir);
            proc->setProgram("bash");
            QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
            env.insert("PCIE_LS_CAPTURE", "1");
            env.insert("PCIE_LS_LOG", pcieLsLog);
            env.insert("RUN_TIMEOUT_SECONDS", "15");
            const QString lsTopo = activeTopologyJsonPath(workingDir);
            if (!lsTopo.isEmpty()) {
                env.insert("TOPOLOGY_JSON", lsTopo);
            }
            env.insert("TOPOLOGY_MODE", topologyModeEnv());
            proc->setProcessEnvironment(env);
            proc->setArguments({resolvedScript});
            connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                    this, [this, pcieLsLog](int exitCode, QProcess::ExitStatus status) {
                        if (status == QProcess::CrashExit || exitCode != 0
                            || !QFileInfo::exists(pcieLsLog)) {
                            showPcieLsText(formatTopologyPciList(currentTopology));
                            statusLabel->setText(QString("PCI list for %1 (guest capture unavailable)")
                                                     .arg(topologyModeTitle()));
                            return;
                        }
                        showPcieLsWindow(pcieLsLog);
                    });
            proc->start();
            statusLabel->setText(QString("Capturing guest PCI list for %1 ...").arg(topologyModeTitle()));
        });
        connect(closeButton, &QPushButton::clicked, aiEmulatorDialog, &QDialog::close);
        connect(aiEmulatorDialog, &QDialog::finished, this, [this]() {
            aiEmulatorDialog = nullptr;
            aiTopologyView = nullptr;
            aiTopologyPathLabel = nullptr;
            topologySourceBadge = nullptr;
            topologyModeCombo = nullptr;
            topologyFileCombo = nullptr;
            runTopologyButton = nullptr;
            fabricSizeBox = nullptr;
        });

        loadGolden();
        applyWorkload(0);
        updateTopologySourceUi();
        updateAiPerformanceReadout();
    }

    fitToAvailableScreen(aiEmulatorDialog, 1.0);
    aiEmulatorDialog->show();
    aiEmulatorDialog->raise();
    aiEmulatorDialog->activateWindow();
}

void MainWindow::applyFilter()
{
    const QString type = typeFilter->currentText();
    const QString direction = directionFilter->currentText();
    const QString analysis = analysisFilter ? analysisFilter->currentText() : QStringLiteral("All packets");
    const QString text = searchBox->text().trimmed().toLower();

    for (int row = 0; row < model->rowCount(); ++row) {
        bool visible = true;
        const QString rowType = model->index(row, 2).data().toString();
        const QString rowDirection = model->index(row, 1).data().toString();
        const int pair = model->item(row, 9) ? model->item(row, 9)->data(kPairRole).toInt() : -1;

        if (type != "All types" && rowType != type) {
            visible = false;
        }

        if (direction != "All directions" && rowDirection != direction) {
            visible = false;
        }

        if (analysis == QLatin1String("Unmatched")) {
            visible = visible && model->index(row, 9).data().toString() == QLatin1String("unmatched");
        } else if (analysis == QLatin1String("Matched pairs")) {
            visible = visible && pair >= 0;
        }

        if (!text.isEmpty()) {
            QString haystack;
            for (int col = 0; col < model->columnCount(); ++col) {
                haystack += model->index(row, col).data().toString();
                haystack += ' ';
            }
            if (!haystack.toLower().contains(text)) {
                visible = false;
            }
        }

        tableView->setRowHidden(row, !visible);
    }

    colorRows();
    showPacketDetails();
    updateSummaryStats();
}

void MainWindow::updateAiPerformanceReadout()
{
    if (!aiPerformanceReadout) {
        return;
    }

    const auto statCell = [](const QString &title, const QString &value) {
        return QStringLiteral(
                   "<td style='width:25%;padding:4px 10px;'>"
                   "<div style='font-size:11px;opacity:0.7;'>%1</div>"
                   "<div style='font-size:18px;font-weight:700;margin-top:2px;'>%2</div>"
                   "</td>")
            .arg(title.toHtmlEscaped(), value.toHtmlEscaped());
    };

    QString devices = QStringLiteral("—");
    QString reads = QStringLiteral("—");
    QString elapsed = QStringLiteral("—");
    QString rate = QStringLiteral("—");
    if (lastPerfTxns > 0 && lastPerfElapsedNs > 0) {
        devices = QLocale().toString(lastPerfDevices);
        reads = QLocale().toString(lastPerfTxns);
        elapsed = QString("%1 ms").arg(static_cast<double>(lastPerfElapsedNs) / 1e6, 0, 'f', 2);
        rate = QString("%1 cfg/s").arg(QLocale().toString(qRound(lastPerfCfgPerSec)));
    }

    aiPerformanceReadout->setText(
        QStringLiteral("<table width='100%' cellspacing='0' cellpadding='0'><tr>%1%2%3%4</tr></table>"
                       "<div style='font-size:11px;opacity:0.7;padding:2px 10px 0 10px;'>"
                       "Timed config-space walk of the deployed fabric. Not AI tokens/sec."
                       "</div>")
            .arg(statCell(QStringLiteral("Devices"), devices),
                 statCell(QStringLiteral("Config reads"), reads),
                 statCell(QStringLiteral("Elapsed"), elapsed),
                 statCell(QStringLiteral("Rate"), rate)));
}

void MainWindow::updateSummaryStats()
{
    int total = 0;
    int tx = 0;
    int rx = 0;
    int visible = 0;
    int unmatched = 0;
    int cfgRd = 0;
    int cpl = 0;

    for (int row = 0; row < model->rowCount(); ++row) {
        const QString direction = model->index(row, 1).data().toString();
        const QString type = model->index(row, 2).data().toString();
        const QString matchText = model->index(row, 9).data().toString();
        if (direction == "TX") {
            tx++;
        } else if (direction == "RX") {
            rx++;
        }
        if (isRequestType(type)) {
            ++cfgRd;
        } else         if (isCompletionType(type)) {
            ++cpl;
        }
        if (matchText == QLatin1String("unmatched")) {
            ++unmatched;
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
    if (unmatchedLabel) {
        unmatchedLabel->setText(QString("Unmatched: %1  ·  CfgRd/MemRd %2  ·  Cpl %3")
                                    .arg(unmatched)
                                    .arg(cfgRd)
                                    .arg(cpl));
    }
}

void MainWindow::colorRows()
{
    const bool hasSelection = tableView->currentIndex().isValid();

    for (int row = 0; row < model->rowCount(); ++row) {
        const QString direction = model->index(row, 1).data().toString();
        const QString type = model->index(row, 2).data().toString();
        const QString matchText = model->index(row, 9).data().toString();
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
            if (matchText == QLatin1String("unmatched")) {
                bgColor = QColor("#5b2a2a");
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
            if (matchText == QLatin1String("unmatched")) {
                bgColor = QColor("#fde8e8");
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
    const int pairRow = model->item(row, 9) ? model->item(row, 9)->data(kPairRole).toInt() : -1;
    const QString pairLabel = model->index(row, 9).data().toString();

    const uint8_t typeCode = tlpCodeFromName(typeText);
    const uint16_t requesterId = parsePciId(requester);
    const uint16_t completerId = parsePciId(completer);
    const uint8_t tagValue = static_cast<uint8_t>(tag.toUInt());
    const uint16_t lengthValue = static_cast<uint16_t>(lengthText.toUInt());
    const uint64_t addrValue = static_cast<uint64_t>(addrText.toULongLong(nullptr, 16));
    const pcie_tlp_type_t decodedType = pcie_tlp_type_from_code(typeCode);
    const pcie_tlp_t decoded = pcie_tlp_decode(typeCode, requesterId, completerId,
                                              tagValue, lengthValue, addrValue, nullptr);

    const QString typeName = QString::fromUtf8(pcie_tlp_type_name(decodedType));
    const QString payloadHex = formatHexDump(payload);

    QString details;
    details += QString("Packet #%1\n").arg(row + 1);
    details += QString("Timestamp: %1\n").arg(timestamp);
    details += QString("Direction: %1\n").arg(direction);
    details += QString("Type: %1 (%2)\n").arg(typeName, typeText);
    if (pairRow >= 0) {
        details += QString("Paired packet: #%1 (double-click Match to jump)\n\n").arg(pairRow + 1);
    } else if (pairLabel == QLatin1String("unmatched")) {
        details += QStringLiteral("Paired packet: none (unmatched request)\n\n");
    } else if (pairLabel == QLatin1String("complete")) {
        details += QStringLiteral("Match: complete — QEMU logged the config read and its returned DWORD on one line.\n\n");
    } else {
        details += QStringLiteral("\n");
    }
    details += QString("Header fields:\n");
    details += QString("  - type: %1\n").arg(typeName);
    details += QString("  - requester_id: %1 (0x%2)\n").arg(requester, makeHexLabel(requesterId, 4));
    details += QString("  - completer_id: %1 (0x%2)\n").arg(completer, makeHexLabel(completerId, 4));
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
    addField("Type", QString("%1 (%2)").arg(typeName, typeText));
    addField("Requester ID", QString("%1 (0x%2)").arg(requester, makeHexLabel(requesterId, 4)));
    addField("Completer ID", QString("%1 (0x%2)").arg(completer, makeHexLabel(completerId, 4)));
    addField("RID", QString("bus %1 dev %2 fn %3")
                         .arg((requesterId >> 8) & 0xff, 2, 16, QLatin1Char('0'))
                         .arg((requesterId >> 3) & 0x1f, 2, 16, QLatin1Char('0'))
                         .arg(requesterId & 0x7));
    addField("Match", pairRow >= 0 ? QString("packet #%1").arg(pairRow + 1) : pairLabel);
    addField("Tag", tag);
    addField("Length", lengthText);
    addField("Address", QString("0x%1").arg(addrValue, 0, 16));
    addField("Payload length", QString::number(payload.isEmpty() ? 0 : payload.size()));
    addField("Payload", payload.isEmpty() ? "<none>" : payload);

    QString decodePayload = payload;
    if (decodePayload.trimmed().isEmpty() && pairRow >= 0) {
        decodePayload = model->index(pairRow, 8).data().toString();
    }
    const bool canDecodeConfig = (typeText == "CfgRd" || typeText == "CfgWr" || typeText == "Cpl"
                                  || typeText == "CplD" || typeText == "Completion")
        && !decodePayload.trimmed().isEmpty();
    if (canDecodeConfig) {
        QString normalizedPayload = decodePayload;
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
