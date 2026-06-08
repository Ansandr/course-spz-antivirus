#include <QApplication>
#include <QDir>
#include <QProcessEnvironment>

#include "logger.h"
#include "mainwindow.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("AntivirusMVP"));
    app.setOrganizationName(QStringLiteral("NULP-KI304"));
    app.setApplicationVersion(QStringLiteral("1.0.0"));

    const QString appData = QProcessEnvironment::systemEnvironment().value(QStringLiteral("APPDATA"));
    const QString appDataDir = QDir(appData).filePath(QStringLiteral("AntivirusMVP"));
    const QString logPath = QDir(appDataDir).filePath(QStringLiteral("antivirus.log"));
    if (Logger::instance()->open(logPath)) {
        Logger::instance()->info(QStringLiteral("Application started"));
    }

    MainWindow w;
    w.show();
    const int rc = app.exec();
    Logger::instance()->info(QStringLiteral("Application stopped"));
    return rc;
}
