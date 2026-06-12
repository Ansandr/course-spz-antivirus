#include <QtTest/QtTest>

#include <QCoreApplication>
#include <QDir>
#include <QFile>

#include "signaturedb.h"

class TestSignatureDB : public QObject {
    Q_OBJECT

private slots:
    void loadAndLookup();
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

void TestSignatureDB::loadAndLookup() {
    const QString path = findSignatureDbPath();
    QVERIFY2(!path.isEmpty(), "signatures.db was not found for tests");

    SignatureDB db;
    QVERIFY(db.load(path));
    QCOMPARE(db.count(), 1);
    QCOMPARE(db.lookup(QStringLiteral("44d88612fea8a8f36de82e1278abb02f")),
             QStringLiteral("EICAR-Standard-Test-File"));
    QVERIFY(db.lookup(QStringLiteral("00000000000000000000000000000000")).isEmpty());
}

QTEST_MAIN(TestSignatureDB)
#include "test_signaturedb.moc"
