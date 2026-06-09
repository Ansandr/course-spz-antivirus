#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStringList>

class QTabWidget;
class QLabel;
class QLineEdit;
class QPushButton;
class QProgressBar;
class QTableWidget;
class QThread;
class QWidget;

class Scanner;
class SignatureDB;
class ProcessList;
class Quarantine;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void selectScanDirectory();
    void startScan();
    void stopScan();
    void openReport();
    void refreshProcesses();
    void refreshQuarantine();
    void quarantineRestore();
    void quarantineDelete();

    void onScanProgress(int current, int total);
    void onThreatFound(const QString& filePath,
                       const QString& threatName,
                       const QString& md5Hex);
    void onScanFinished(int totalFiles, int threatsFound);

private:
    void buildUi();
    QWidget* buildScanTab();
    QWidget* buildProcessTab();
    QWidget* buildQuarantineTab();
    QWidget* buildPlaceholderTab(const QString& title) const;

    bool loadSignatureDb();
    bool writeScanReport(int totalFiles, int threatsFound);
    QString appDataDir() const;

    QTabWidget* m_tabs = nullptr;

    QLineEdit*    m_scanDirEdit = nullptr;
    QPushButton*  m_btnStart = nullptr;
    QPushButton*  m_btnStop = nullptr;
    QPushButton*  m_btnOpenReport = nullptr;
    QProgressBar* m_scanProgress = nullptr;
    QLabel*       m_scanProgressText = nullptr;
    QTableWidget* m_scanTable = nullptr;
    QTableWidget* m_processTable = nullptr;
    QTableWidget* m_quarantineTable = nullptr;

    QThread*   m_scanThread = nullptr;
    Scanner*   m_scanner = nullptr;
    SignatureDB* m_signatureDb = nullptr;
    ProcessList* m_processList = nullptr;
    Quarantine* m_quarantine = nullptr;

    QString m_lastReportPath;
    QStringList m_detectedRows;
};

#endif // MAINWINDOW_H
