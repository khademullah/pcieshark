#pragma once

#include <QMainWindow>
#include <QStandardItemModel>
#include <QTableView>
#include <QPushButton>
#include <QComboBox>
#include <QLineEdit>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QTextBrowser>
#include <QTextEdit>
#include <QSplitter>
#include <QTreeWidget>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QSpinBox>
#include <QDoubleSpinBox>
#include <QElapsedTimer>
#include <QSet>
#include <QTimer>
#include <QProcess>
#include <QJsonObject>
#include <QJsonArray>
#include <QTextBrowser>
#include <QGroupBox>

enum class TopologyRunMode {
    ZephyrGolden,
    LinuxQemu,
    JsonFile,
    Generated
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    void loadTraceFile(const QString &path);
    void openTraceDialog();
    void closeEvent(QCloseEvent *event) override;

private slots:
    void openTrace();
    void saveTrace();
    void pollLiveTrace();
    void enumeratePciDevice();
    void openAiPerfDialog();
    void applyFilter();
    void showPacketDetails();
    void updateSummaryStats();
    void updateAiPerformanceReadout();

private:
    void loadCsv(const QString &path);
    QStringList splitCsvLine(const QString &line) const;

    QTableView *tableView;
    QTextEdit *detailsView;
    QTreeWidget *decodeTree;
    QSplitter *splitter;
    QStandardItemModel *model;
    QComboBox *typeFilter;
    QComboBox *directionFilter;
    QComboBox *backendFilter;
    QLineEdit *deviceIdBox;
    QLineEdit *scenarioBox;
    QLineEdit *searchBox;
    QPushButton *openButton;
    QPushButton *saveButton;
    QPushButton *enumerateButton;
    QPushButton *aiPerfButton;
    QPushButton *themeButton;
    QLabel *statusLabel;
    QLabel *totalLabel;
    QLabel *txLabel;
    QLabel *rxLabel;
    QLabel *filteredLabel;
    QLabel *aiPerformanceReadout;
    QDialog *aiEmulatorDialog;
    QDialog *pcieLsDialog;
    QTimer *liveTraceTimer;
    QProcess *liveTraceProcess;
    QString liveTracePath;
    QString currentTopologyJsonPath;
    QJsonObject currentTopology;
    QTextBrowser *aiTopologyView;
    QLabel *aiTopologyPathLabel;
    QLabel *topologySourceBadge;
    QComboBox *topologyModeCombo;
    QComboBox *topologyFileCombo;
    QPushButton *runTopologyButton;
    TopologyRunMode topologyRunMode;
    QSet<QString> liveTraceSeen;
    int currentAiPerformanceTargetTps = 0;
    int currentAiPerformanceTargetLatencyNs = 0;
    bool darkMode;
    bool suppressAiRunnerExitWarning;
    void applyTheme();
    void colorRows();
    QString findRepoPath(const QStringList &relativeCandidates) const;
    QString repoRootPath() const;
    QString resolveZephyrScript() const;
    QString resolveLinuxScript() const;
    QString resolveTopologyScript() const;
    QString topologyModeEnv() const;
    QStringList listConfigTopologyFiles() const;
    QString topologyTraceFileName() const;
    QString activeTopologyJsonPath(const QString &workDir);
    QString topologyModeTitle() const;
    void updateTopologySourceUi();
    QJsonObject goldenTopologyObject() const;
    QJsonObject generateTopologyFromCounts(int rootPorts, int endpointsPerRoot) const;
    bool loadTopologyFile(const QString &path, QString *error);
    QString materializeCurrentTopology(const QString &workDir);
    void renderCurrentTopology();
    void injectFabricEnumerationPackets();
    void runAiPerformanceScenario(const QString &profile,
                                 int rootPorts,
                                 int endpointsPerRoot,
                                 int iterations,
                                 int latencyNs,
                                 int tps,
                                 int burstSize,
                                 int jitterNs,
                                 double dropRate,
                                 int busCount);
    void showPcieLsWindow(const QString &path);
    void showPcieLsText(const QString &text);
};
