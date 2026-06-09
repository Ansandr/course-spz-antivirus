#pragma once

#include <QVector>
#include <QString>
#include <cstdint>

struct ProcessInfo {
    uint32_t pid           = 0;
    QString  name;
    QString  executablePath;
    bool     isSuspicious  = false;
};

/**
 * @brief Windows process list via CreateToolhelp32Snapshot.
 *
 * Uses PROCESS_QUERY_LIMITED_INFORMATION so that even restricted processes
 * can be enumerated. Paths unavailable due to access restrictions are
 * reported as "N/A" rather than causing a crash.
 */
class ProcessList {
public:
    QVector<ProcessInfo> snapshot();

private:
    static bool isSuspiciousPath(const QString& path);
};
