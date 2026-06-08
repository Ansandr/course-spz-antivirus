#include <QApplication>
#include "mainwindow.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("AntivirusMVP"));
    app.setOrganizationName(QStringLiteral("NULP-KI304"));
    app.setApplicationVersion(QStringLiteral("1.0.0"));

    MainWindow w;
    w.show();
    return app.exec();
}
