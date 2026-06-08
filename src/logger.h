#pragma once

#include <QFile>
#include <QMutex>
#include <QString>
#include <QTextStream>

/**
 * @brief Singleton thread-safe logger.
 *
 * Write all application events to a UTF-8 text file with timestamp and level.
 * Safe to call from any thread (Scanner runs in QThread).
 *
 * Usage:
 *   Logger::instance()->open(path);
 *   Logger::instance()->info("Scan started");
 */
class Logger {
public:
    static Logger* instance();

    /** Open (append) the log file. Must be called once from the main thread. */
    bool open(const QString& filePath);

    void info(const QString& message);
    void warning(const QString& message);
    void error(const QString& message);

    /** Returns the path passed to open(), or empty if not opened. */
    QString filePath() const { return m_logFile.fileName(); }

private:
    Logger() = default;
    ~Logger();

    void write(const QString& level, const QString& message);

    static Logger* s_instance;

    QFile       m_logFile;
    QTextStream m_stream;
    QMutex      m_mutex;
};
