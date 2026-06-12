#include <QtTest/QtTest>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QTextStream>

#include "scanner.h"
#include "signaturedb.h"

class TestScanner : public QObject {
    Q_OBJECT

private slots:
    void detectsThreatInDirectory();
};

namespace {
QString findSignatureDbPath() {
    const QStringList candidates = {
        QStringLiteral("signatures.db"),
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("signatures.db")),
        QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("..\\..\\signatures.db"))
    };
    for (const QString& candidate : candidates) {
        if (QFile::exists(candidate))
            return candidate;
    }
    return {};
}
}

void TestScanner::detectsThreatInDirectory() {
    const QString signaturePath = findSignatureDbPath();
    QVERIFY2(!signaturePath.isEmpty(), "signatures.db was not found for tests");

    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());
    const QString filePath = QDir(tempDir.path()).filePath(QStringLiteral("eicar_test.txt"));
    QFile file(filePath);
    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate));
    QTextStream out(&file);
    out << QStringLiteral("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
    file.close();

    SignatureDB db;
    QVERIFY(db.load(signaturePath));

    Scanner scanner;
    scanner.setDirectory(tempDir.path());
    scanner.setSignatureDB(&db);

    bool threatDetected = false;
    QObject::connect(&scanner, &Scanner::threatFound,
                     [&threatDetected](const QString&, const QString&, const QString&) {
                         threatDetected = true;
                     });

    scanner.run();
    QVERIFY(threatDetected);
}

QTEST_MAIN(TestScanner)
#include "test_scanner.moc"
