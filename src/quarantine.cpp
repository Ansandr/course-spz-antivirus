#include "quarantine.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStorageInfo>

Quarantine::Quarantine(const QString& quarantineDir) : m_dir(quarantineDir) {
    QDir().mkpath(m_dir);
    loadIndex();
}

bool Quarantine::isolate(const QString& filePath, const QString& threatName) {
    QStorageInfo si(m_dir);
    if (si.bytesFree() < 100LL * 1024 * 1024)
        return false;

    const QFileInfo fi(filePath);
    const QString dest = generateDest(fi.fileName());

    if (!QFile::rename(filePath, dest))
        return false;

    QJsonObject obj;
    obj[QStringLiteral("originalPath")] = filePath;
    obj[QStringLiteral("quarantinedPath")] = dest;
    obj[QStringLiteral("threatName")] = threatName;
    obj[QStringLiteral("fileName")] = fi.fileName();
    obj[QStringLiteral("date")] =
        QDateTime::currentDateTime().toString(QStringLiteral("dd.MM.yyyy HH:mm:ss"));

    m_index.append(obj);
    saveIndex();
    return true;
}

bool Quarantine::restore(int index) {
    if (index < 0 || index >= m_index.size())
        return false;

    const QJsonObject obj = m_index.at(index).toObject();
    const QString src = obj[QStringLiteral("quarantinedPath")].toString();
    const QString dest = obj[QStringLiteral("originalPath")].toString();

    QDir().mkpath(QFileInfo(dest).absolutePath());
    if (!QFile::rename(src, dest))
        return false;

    m_index.removeAt(index);
    saveIndex();
    return true;
}

bool Quarantine::removeEntry(int index) {
    if (index < 0 || index >= m_index.size())
        return false;

    QFile::remove(
        m_index.at(index).toObject()[QStringLiteral("quarantinedPath")].toString());
    m_index.removeAt(index);
    saveIndex();
    return true;
}

QVector<QuarantineEntry> Quarantine::entries() const {
    QVector<QuarantineEntry> result;
    result.reserve(m_index.size());

    for (const QJsonValue& v : m_index) {
        const QJsonObject obj = v.toObject();
        QuarantineEntry e;
        e.originalPath = obj[QStringLiteral("originalPath")].toString();
        e.quarantinedPath = obj[QStringLiteral("quarantinedPath")].toString();
        e.threatName = obj[QStringLiteral("threatName")].toString();
        e.fileName = obj[QStringLiteral("fileName")].toString();
        e.date = obj[QStringLiteral("date")].toString();
        result.append(std::move(e));
    }
    return result;
}

void Quarantine::loadIndex() {
    QFile f(m_dir + QLatin1String("/quarantine_index.json"));
    if (!f.open(QIODevice::ReadOnly))
        return;

    m_index = QJsonDocument::fromJson(f.readAll()).array();
}

void Quarantine::saveIndex() {
    QFile f(m_dir + QLatin1String("/quarantine_index.json"));
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return;

    f.write(QJsonDocument(m_index).toJson());
}

QString Quarantine::generateDest(const QString& fileName) const {
    const QFileInfo fi(fileName);
    const QString ts = QDateTime::currentDateTime()
                           .toString(QStringLiteral("yyyyMMdd_HHmmss"));
    const QString base = fi.completeBaseName().isEmpty() ? fileName
                                                          : fi.completeBaseName();
    const QString ext = fi.suffix().isEmpty()
                            ? QString()
                            : QLatin1Char('.') + fi.suffix();

    return m_dir + QLatin1Char('/') + base + QLatin1Char('_') + ts + ext;
}
