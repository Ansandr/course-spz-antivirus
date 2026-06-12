#include "logger.h"

#include <QDateTime>
#include <QDir>
#include <QFileInfo>

Logger* Logger::s_instance = nullptr;

Logger* Logger::instance() {
    if (!s_instance)
        s_instance = new Logger();
    return s_instance;
}

Logger::~Logger() {
    if (m_logFile.isOpen())
        m_logFile.close();
}

bool Logger::open(const QString& filePath) {
    QDir().mkpath(QFileInfo(filePath).absolutePath());
    m_logFile.setFileName(filePath);
    const bool ok = m_logFile.open(QIODevice::Append | QIODevice::Text);
    if (ok) {
        m_stream.setDevice(&m_logFile);
        m_stream.setEncoding(QStringConverter::Utf8);
    }
    return ok;
}

void Logger::write(const QString& level, const QString& message) {
    QMutexLocker lock(&m_mutex);
    const QString ts = QDateTime::currentDateTime()
                           .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
    m_stream << QStringLiteral("[%1] [%2] %3\n").arg(ts, level, message);
    m_stream.flush();
}

void Logger::info(const QString& message)    { write(QStringLiteral("INFO"),    message); }
void Logger::warning(const QString& message) { write(QStringLiteral("WARNING"), message); }
void Logger::error(const QString& message)   { write(QStringLiteral("ERROR"),   message); }
