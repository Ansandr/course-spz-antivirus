#pragma once

#include <QObject>
#include <QStringList>
#include <atomic>

#include "signaturedb.h"

/**
 * @brief Recursive file-system scanner.
 *
 * Designed to run inside a QThread:
 *   scanner->moveToThread(thread);
 *   connect(thread, &QThread::started, scanner, &Scanner::run);
 *
 * Emits progress(), threatFound(), and finished() to be connected
 * to GUI slots via Qt::QueuedConnection (automatic for cross-thread signals).
 */
class Scanner : public QObject {
    Q_OBJECT

public:
    explicit Scanner(QObject* parent = nullptr);

    void setDirectory(const QString& path)      { m_directory = path; }
    void setWhitelist(const QStringList& paths) { m_whitelist = paths; }
    void setSignatureDB(SignatureDB* db)         { m_db = db; }

    /** Thread-safe stop: may be called from the GUI thread. */
    void stop() { m_running.store(false); }

public slots:
    void run();

signals:
    /** Fired for every file processed. */
    void progress(int current, int total);

    /** Fired when a file matches a signature. */
    void threatFound(const QString& filePath,
                     const QString& threatName,
                     const QString& md5Hex);

    /** Fired once when scan completes or is stopped. */
    void finished(int totalFiles, int threatsFound);

    /** General log messages (routed to Logger in GUI thread). */
    void logMessage(const QString& level, const QString& message);

private:
    static QString computeMd5(const QString& filePath);

    QString               m_directory;
    QStringList           m_whitelist;
    SignatureDB*          m_db     = nullptr;
    std::atomic<bool>     m_running{false};
};
