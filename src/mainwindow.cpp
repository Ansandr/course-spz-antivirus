#include "mainwindow.h"

#include <QApplication>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QStandardPaths>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextStream>
#include <QThread>
#include <QUrl>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QWidget>

#include "logger.h"
#include "processlist.h"
#include "scanner.h"
#include "signaturedb.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent) {
    setWindowTitle(QStringLiteral("AntivirusMVP 1.0.0"));
    setMinimumSize(800, 600);
    resize(1000, 700);

    m_signatureDb = new SignatureDB();
    m_processList = new ProcessList();

    buildUi();
}

MainWindow::~MainWindow() {
    if (m_scanner) {
        m_scanner->stop();
    }
    if (m_scanThread) {
        m_scanThread->quit();
        m_scanThread->wait(3000);
    }
    delete m_signatureDb;
    delete m_processList;
}

void MainWindow::buildUi() {
    m_tabs = new QTabWidget(this);
    m_tabs->addTab(buildScanTab(), QStringLiteral("Сканування"));
    m_tabs->addTab(buildProcessTab(), QStringLiteral("Процеси"));
    m_tabs->addTab(buildPlaceholderTab(QStringLiteral("Карантин")), QStringLiteral("Карантин"));
    m_tabs->addTab(buildPlaceholderTab(QStringLiteral("Журнал")), QStringLiteral("Журнал"));
    m_tabs->addTab(buildPlaceholderTab(QStringLiteral("Налаштування")), QStringLiteral("Налаштування"));

    setCentralWidget(m_tabs);
}

QWidget* MainWindow::buildPlaceholderTab(const QString& title) const {
    auto* page = new QWidget;
    auto* layout = new QVBoxLayout(page);
    auto* label = new QLabel(QStringLiteral("Вкладка \"") + title + QStringLiteral("\" буде реалізована в наступних User Stories."));
    label->setWordWrap(true);
    layout->addStretch();
    layout->addWidget(label);
    layout->addStretch();
    return page;
}

QWidget* MainWindow::buildScanTab() {
    auto* page = new QWidget;
    auto* root = new QVBoxLayout(page);

    auto* dirRow = new QHBoxLayout;
    m_scanDirEdit = new QLineEdit;
    m_scanDirEdit->setPlaceholderText(QStringLiteral("Оберіть директорію для сканування..."));
    auto* btnSelect = new QPushButton(QStringLiteral("Обрати..."));
    connect(btnSelect, &QPushButton::clicked, this, &MainWindow::selectScanDirectory);
    dirRow->addWidget(m_scanDirEdit);
    dirRow->addWidget(btnSelect);
    root->addLayout(dirRow);

    auto* actions = new QHBoxLayout;
    m_btnStart = new QPushButton(QStringLiteral("Розпочати сканування"));
    m_btnStop = new QPushButton(QStringLiteral("Зупинити"));
    m_btnOpenReport = new QPushButton(QStringLiteral("Відкрити звіт"));
    m_btnStop->setEnabled(false);
    m_btnOpenReport->setEnabled(false);
    connect(m_btnStart, &QPushButton::clicked, this, &MainWindow::startScan);
    connect(m_btnStop, &QPushButton::clicked, this, &MainWindow::stopScan);
    connect(m_btnOpenReport, &QPushButton::clicked, this, &MainWindow::openReport);
    actions->addWidget(m_btnStart);
    actions->addWidget(m_btnStop);
    actions->addStretch();
    actions->addWidget(m_btnOpenReport);
    root->addLayout(actions);

    m_scanProgress = new QProgressBar;
    m_scanProgress->setRange(0, 100);
    m_scanProgressText = new QLabel(QStringLiteral("Готово"));
    root->addWidget(m_scanProgress);
    root->addWidget(m_scanProgressText);

    m_scanTable = new QTableWidget(0, 3);
    m_scanTable->setHorizontalHeaderLabels({
        QStringLiteral("Файл"),
        QStringLiteral("Статус"),
        QStringLiteral("Загроза")
    });
    m_scanTable->horizontalHeader()->setStretchLastSection(true);
    m_scanTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_scanTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    root->addWidget(m_scanTable);

    return page;
}

QWidget* MainWindow::buildProcessTab() {
    auto* page = new QWidget;
    auto* root = new QVBoxLayout(page);

    auto* btnRefresh = new QPushButton(QStringLiteral("Оновити список"));
    connect(btnRefresh, &QPushButton::clicked, this, &MainWindow::refreshProcesses);
    root->addWidget(btnRefresh);

    m_processTable = new QTableWidget(0, 3);
    m_processTable->setHorizontalHeaderLabels({
        QStringLiteral("PID"),
        QStringLiteral("Ім'я"),
        QStringLiteral("Шлях")
    });
    m_processTable->horizontalHeader()->setStretchLastSection(true);
    m_processTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_processTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    root->addWidget(m_processTable);

    refreshProcesses();
    return page;
}

void MainWindow::selectScanDirectory() {
    const QString dir = QFileDialog::getExistingDirectory(
        this,
        QStringLiteral("Оберіть директорію"),
        QDir::homePath());
    if (!dir.isEmpty()) {
        m_scanDirEdit->setText(dir);
    }
}

bool MainWindow::loadSignatureDb() {
    if (m_signatureDb->count() > 0) {
        return true;
    }

    const QString appDir = QApplication::applicationDirPath();
    const QStringList candidates = {
        QStringLiteral("signatures.db"),
        QDir(appDir).filePath(QStringLiteral("signatures.db")),
        QDir(appDir).filePath(QStringLiteral("..\\..\\signatures.db"))
    };

    for (const QString& path : candidates) {
        if (QFile::exists(path) && m_signatureDb->load(path)) {
            Logger::instance()->info(QStringLiteral("SignatureDB loaded from: ") + path);
            return true;
        }
    }

    QMessageBox::warning(this,
                         QStringLiteral("Сканування"),
                         QStringLiteral("Не вдалося завантажити signatures.db"));
    return false;
}

void MainWindow::startScan() {
    const QString dir = m_scanDirEdit->text().trimmed();
    if (dir.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("Сканування"), QStringLiteral("Оберіть директорію для сканування."));
        return;
    }
    if (!QDir(dir).exists()) {
        QMessageBox::warning(this, QStringLiteral("Сканування"), QStringLiteral("Директорія не існує."));
        return;
    }
    if (!loadSignatureDb()) {
        return;
    }

    m_detectedRows.clear();
    m_lastReportPath.clear();
    m_scanTable->setRowCount(0);
    m_scanProgress->setValue(0);
    m_scanProgressText->setText(QStringLiteral("Сканування..."));
    m_btnStart->setEnabled(false);
    m_btnStop->setEnabled(true);
    m_btnOpenReport->setEnabled(false);

    m_scanThread = new QThread(this);
    m_scanner = new Scanner();
    m_scanner->setDirectory(dir);
    m_scanner->setSignatureDB(m_signatureDb);
    m_scanner->moveToThread(m_scanThread);

    connect(m_scanThread, &QThread::started, m_scanner, &Scanner::run);
    connect(m_scanner, &Scanner::progress, this, &MainWindow::onScanProgress);
    connect(m_scanner, &Scanner::threatFound, this, &MainWindow::onThreatFound);
    connect(m_scanner, &Scanner::finished, this, &MainWindow::onScanFinished);
    connect(m_scanner, &Scanner::finished, m_scanThread, &QThread::quit);

    connect(m_scanner, &Scanner::logMessage, this, [](const QString& level, const QString& message) {
        if (level == QStringLiteral("INFO")) {
            Logger::instance()->info(message);
        } else if (level == QStringLiteral("WARNING")) {
            Logger::instance()->warning(message);
        } else {
            Logger::instance()->error(message);
        }
    });

    connect(m_scanThread, &QThread::finished, m_scanner, &QObject::deleteLater);
    connect(m_scanThread, &QThread::finished, m_scanThread, &QObject::deleteLater);
    connect(m_scanThread, &QThread::finished, this, [this]() {
        m_scanner = nullptr;
        m_scanThread = nullptr;
    });

    m_scanThread->start();
}

void MainWindow::stopScan() {
    if (m_scanner) {
        m_scanner->stop();
    }
}

void MainWindow::onScanProgress(int current, int total) {
    if (total > 0) {
        m_scanProgress->setValue((current * 100) / total);
    }
    m_scanProgressText->setText(QStringLiteral("Перевірено %1 / %2 файлів").arg(current).arg(total));
}

void MainWindow::onThreatFound(const QString& filePath,
                               const QString& threatName,
                               const QString&) {
    const int row = m_scanTable->rowCount();
    m_scanTable->insertRow(row);

    auto* fileItem = new QTableWidgetItem(filePath);
    auto* statusItem = new QTableWidgetItem(QStringLiteral("Загроза"));
    auto* threatItem = new QTableWidgetItem(threatName);

    fileItem->setForeground(Qt::red);
    statusItem->setForeground(Qt::red);
    threatItem->setForeground(Qt::red);

    m_scanTable->setItem(row, 0, fileItem);
    m_scanTable->setItem(row, 1, statusItem);
    m_scanTable->setItem(row, 2, threatItem);

    m_detectedRows << QStringLiteral("%1 | %2").arg(filePath, threatName);
}

bool MainWindow::writeScanReport(int totalFiles, int threatsFound) {
    const QString reportsDir = QDir(appDataDir()).filePath(QStringLiteral("Reports"));
    QDir().mkpath(reportsDir);

    const QString fileName = QStringLiteral("scan_")
        + QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))
        + QStringLiteral(".txt");
    m_lastReportPath = QDir(reportsDir).filePath(fileName);

    QFile outFile(m_lastReportPath);
    if (!outFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        m_lastReportPath.clear();
        return false;
    }

    QTextStream out(&outFile);
    out << "AntivirusMVP Scan Report\n";
    out << "Time: " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
    out << "Directory: " << m_scanDirEdit->text().trimmed() << "\n";
    out << "Total files: " << totalFiles << "\n";
    out << "Threats found: " << threatsFound << "\n\n";
    out << "Threat list:\n";
    if (m_detectedRows.isEmpty()) {
        out << "(none)\n";
    } else {
        for (const QString& line : m_detectedRows) {
            out << line << "\n";
        }
    }
    out.flush();
    return true;
}

QString MainWindow::appDataDir() const {
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
}

void MainWindow::onScanFinished(int totalFiles, int threatsFound) {
    m_scanProgress->setValue(100);
    m_scanProgressText->setText(
        QStringLiteral("Завершено: %1 файлів, %2 загроз").arg(totalFiles).arg(threatsFound));

    m_btnStart->setEnabled(true);
    m_btnStop->setEnabled(false);

    if (writeScanReport(totalFiles, threatsFound)) {
        m_btnOpenReport->setEnabled(true);
    }
}

void MainWindow::openReport() {
    if (m_lastReportPath.isEmpty() || !QFile::exists(m_lastReportPath)) {
        QMessageBox::information(this, QStringLiteral("Звіт"), QStringLiteral("Звіт ще не створено."));
        return;
    }
    QDesktopServices::openUrl(QUrl::fromLocalFile(m_lastReportPath));
}

void MainWindow::refreshProcesses() {
    if (!m_processList || !m_processTable) {
        return;
    }

    const auto processes = m_processList->snapshot();
    m_processTable->setRowCount(0);

    for (const ProcessInfo& process : processes) {
        const int row = m_processTable->rowCount();
        m_processTable->insertRow(row);

        auto* pidItem = new QTableWidgetItem(QString::number(process.pid));
        auto* nameItem = new QTableWidgetItem(process.name);
        auto* pathItem = new QTableWidgetItem(process.executablePath);

        if (process.isSuspicious) {
            pidItem->setForeground(Qt::red);
            nameItem->setForeground(Qt::red);
            pathItem->setForeground(Qt::red);
        }

        m_processTable->setItem(row, 0, pidItem);
        m_processTable->setItem(row, 1, nameItem);
        m_processTable->setItem(row, 2, pathItem);
    }
}
