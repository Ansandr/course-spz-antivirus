#include "reportwriter.h"

#include <QDateTime>
#include <QFile>
#include <QTextStream>

bool ReportWriter::write(const QString& path, const ScanResult& result) {
    QFile outFile(path);
    if (!outFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        return false;
    }

    QTextStream out(&outFile);
    out << "AntivirusMVP Scan Report\n";
    out << "Time: " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
    out << "Directory: " << result.directory << "\n";
    out << "Total files: " << result.totalFiles << "\n";
    out << "Threats found: " << result.threatsFound << "\n\n";
    out << "Threat list:\n";

    if (result.threats.isEmpty()) {
        out << "(none)\n";
    } else {
        for (const ThreatEntry& threat : result.threats) {
            out << "- " << threat.filePath << "\n";
            out << "  Threat: " << threat.threatName << "\n";
            out << "  MD5: " << threat.md5Hex << "\n";
        }
    }

    out.flush();
    return out.status() == QTextStream::Ok;
}
