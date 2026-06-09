#pragma once

#include <QJsonArray>
#include <QString>
#include <QVector>

struct QuarantineEntry {
    QString originalPath;
    QString quarantinedPath;
    QString threatName;
    QString fileName;
    QString date;
};

class Quarantine {
public:
    explicit Quarantine(const QString& quarantineDir);

    bool isolate(const QString& filePath, const QString& threatName);
    bool restore(int index);
    bool removeEntry(int index);

    QVector<QuarantineEntry> entries() const;

private:
    void loadIndex();
    void saveIndex();
    QString generateDest(const QString& fileName) const;

    QString m_dir;
    QJsonArray m_index;
};
