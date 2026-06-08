#include "scanner.h"

#include <QCryptographicHash>
#include <QDirIterator>
#include <QFile>

Scanner::Scanner(QObject* parent) : QObject(parent) {}

// -- Private helper ---------------------------------------------------------

QString Scanner::computeMd5(const QString& filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly))
        return {};

    QCryptographicHash hasher(QCryptographicHash::Md5);
    hasher.addData(&file);
    return QString::fromLatin1(hasher.result().toHex());
}

// -- Main scan loop ---------------------------------------------------------

void Scanner::run() {
    m_running.store(true);

    int total = 0;
    {
        QDirIterator counter(m_directory,
                             QDir::Files | QDir::NoSymLinks,
                             QDirIterator::Subdirectories);
        while (counter.hasNext()) {
            counter.next();
            ++total;
        }
    }

    int current = 0;
    int threats = 0;

    QDirIterator it(m_directory,
                    QDir::Files | QDir::NoSymLinks,
                    QDirIterator::Subdirectories);

    while (it.hasNext() && m_running.load()) {
        const QString filePath = it.next();
        emit progress(++current, total);

        bool skip = false;
        for (const QString& whitelistPath : std::as_const(m_whitelist)) {
            if (filePath.startsWith(whitelistPath, Qt::CaseInsensitive)) {
                skip = true;
                break;
            }
        }
        if (skip) {
            continue;
        }

        const QString md5 = computeMd5(filePath);
        if (md5.isEmpty()) {
            emit logMessage(QStringLiteral("WARNING"),
                            QStringLiteral("Cannot open: ") + filePath);
            continue;
        }

        if (m_db) {
            const QString threat = m_db->lookup(md5);
            if (!threat.isEmpty()) {
                ++threats;
                emit threatFound(filePath, threat, md5);
                emit logMessage(QStringLiteral("WARNING"),
                                QStringLiteral("THREAT [%1] in: %2")
                                    .arg(threat, filePath));
            }
        }
    }

    emit finished(current, threats);
    emit logMessage(QStringLiteral("INFO"),
                    QStringLiteral("Scan done: %1 files, %2 threats")
                        .arg(current)
                        .arg(threats));
}
