#include <QApplication>
#include <QDir>
#include <QFile>
#include <QDebug>
#include <QProcessEnvironment>
#include <QTextStream>
#include <QThread>
#include <iostream>

#include "scanner.h"
#include "signaturedb.h"

#include "logger.h"
#include "mainwindow.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("AntivirusMVP"));
    app.setOrganizationName(QStringLiteral("NULP-KI307"));
    app.setApplicationVersion(QStringLiteral("1.0.0"));

    const QString appData = QProcessEnvironment::systemEnvironment().value(QStringLiteral("APPDATA"));
    const QString appDataDir = QDir(appData).filePath(QStringLiteral("AntivirusMVP"));
    const QString logPath = QDir(appDataDir).filePath(QStringLiteral("antivirus.log"));
    if (Logger::instance()->open(logPath)) {
        Logger::instance()->info(QStringLiteral("Application started"));
    }

#if !defined(NDEBUG)
    const QString tempScanDir = QDir(QDir::tempPath()).filePath(QStringLiteral("AntivirusMVP_US05"));
    QDir().mkpath(tempScanDir);

    const QString eicarPath = QDir(tempScanDir).filePath(QStringLiteral("eicar_test.txt"));
    const auto writeEicarFile = [&eicarPath]() -> bool {
        QFile eicarFile(eicarPath);
        if (eicarFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
            QTextStream out(&eicarFile);
            out << QStringLiteral("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
            eicarFile.close();
            return true;
        } else {
            qWarning() << "US-05: cannot create EICAR file:" << eicarPath;
            Logger::instance()->warning(QStringLiteral("US-05: cannot create EICAR file: ") + eicarPath);
            return false;
        }
    };
    writeEicarFile();

    const QStringList signatureCandidates = {
        QStringLiteral("signatures.db"),
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("signatures.db")),
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("..\\..\\signatures.db"))
    };

    QString signatureDbPath;
    for (const QString& candidate : signatureCandidates) {
        if (QFile::exists(candidate)) {
            signatureDbPath = candidate;
            break;
        }
    }

    SignatureDB signatureDb;
    if (!signatureDbPath.isEmpty() && signatureDb.load(signatureDbPath)) {
        Scanner scanner;
        scanner.setDirectory(tempScanDir);
        scanner.setSignatureDB(&signatureDb);

        bool threatDetected = false;

        QObject::connect(&scanner, &Scanner::logMessage,
                         [](const QString& level, const QString& message) {
                             if (level == QStringLiteral("INFO")) {
                                 Logger::instance()->info(message);
                             } else if (level == QStringLiteral("WARNING")) {
                                 Logger::instance()->warning(message);
                             } else {
                                 Logger::instance()->error(message);
                             }
                         });

        QObject::connect(&scanner, &Scanner::threatFound,
                         [&threatDetected](const QString& filePath, const QString& threatName, const QString& md5) {
                             threatDetected = true;
                             qInfo().noquote() << QStringLiteral("[US-05] THREAT: %1 in %2 (MD5: %3)")
                                                   .arg(threatName, filePath, md5);
                             std::cout << "[US-05] THREAT: "
                                       << threatName.toStdString()
                                       << " in "
                                       << filePath.toStdString()
                                       << " (MD5: "
                                       << md5.toStdString()
                                       << ")" << std::endl;
                         });

        QObject::connect(&scanner, &Scanner::finished,
                         [](int totalFiles, int threatsFound) {
                             qInfo().noquote() << QStringLiteral("[US-05] Scan finished: %1 files, %2 threats")
                                                   .arg(totalFiles)
                                                   .arg(threatsFound);
                             std::cout << "[US-05] Scan finished: "
                                       << totalFiles
                                       << " files, "
                                       << threatsFound
                                       << " threats" << std::endl;
                         });

        for (int attempt = 0; attempt < 3 && !threatDetected; ++attempt) {
            if (!QFile::exists(eicarPath)) {
                writeEicarFile();
            }
            scanner.run();
            if (!threatDetected) {
                QThread::msleep(150);
            }
        }

        if (!threatDetected) {
            Logger::instance()->warning(QStringLiteral("US-05: EICAR file was not detected"));
            std::cout << "[US-05] EICAR file was not detected" << std::endl;
        }
    } else {
        qWarning() << "US-05: cannot load signatures.db";
        Logger::instance()->warning(QStringLiteral("US-05: cannot load signatures.db"));
        std::cout << "[US-05] Cannot load signatures.db" << std::endl;
    }
#endif

    MainWindow w;
    w.show();
    const int rc = app.exec();
    Logger::instance()->info(QStringLiteral("Application stopped"));
    return rc;
}
