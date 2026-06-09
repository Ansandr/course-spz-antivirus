#ifndef REPORTWRITER_H
#define REPORTWRITER_H

#include <QList>
#include <QString>

struct ThreatEntry {
    QString filePath;
    QString threatName;
    QString md5Hex;
};

struct ScanResult {
    QString directory;
    int totalFiles = 0;
    int threatsFound = 0;
    QList<ThreatEntry> threats;
};

class ReportWriter {
public:
    static bool write(const QString& path, const ScanResult& result);
};

#endif // REPORTWRITER_H
