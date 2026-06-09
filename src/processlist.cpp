#include "processlist.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

QVector<ProcessInfo> ProcessList::snapshot() {
    QVector<ProcessInfo> result;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return result;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe)) {
        do {
            ProcessInfo info;
            info.pid = static_cast<uint32_t>(pe.th32ProcessID);
            info.name = QString::fromWCharArray(pe.szExeFile);

            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                wchar_t buf[MAX_PATH] = {};
                DWORD sz = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, buf, &sz))
                    info.executablePath = QString::fromWCharArray(buf);
                CloseHandle(hProc);
            }

            if (info.executablePath.isEmpty())
                info.executablePath = QStringLiteral("N/A");

            info.isSuspicious = isSuspiciousPath(info.executablePath);
            result.append(std::move(info));

        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return result;
}

bool ProcessList::isSuspiciousPath(const QString& path) {
    if (path == QLatin1String("N/A"))
        return false;

    const QString lower = path.toLower();
    return lower.contains(QLatin1String("\\temp\\"))
        || lower.contains(QLatin1String("\\tmp\\"))
        || lower.contains(QLatin1String("\\appdata\\local\\temp\\"))
        || lower.contains(QLatin1String("\\downloads\\"));
}
