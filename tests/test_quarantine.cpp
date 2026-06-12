#include <QtTest/QtTest>

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QTextStream>

#include "quarantine.h"

class TestQuarantine : public QObject {
    Q_OBJECT

private slots:
    void isolateAndRestore();
};

void TestQuarantine::isolateAndRestore() {
    QTemporaryDir tempDir;
    QVERIFY(tempDir.isValid());

    const QString quarantineDir = QDir(tempDir.path()).filePath(QStringLiteral("quarantine"));
    const QString filePath = QDir(tempDir.path()).filePath(QStringLiteral("sample.txt"));
    QFile file(filePath);
    QVERIFY(file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate));
    QTextStream out(&file);
    out << QStringLiteral("sample");
    file.close();

    Quarantine quarantine(quarantineDir);
    QVERIFY(quarantine.isolate(filePath, QStringLiteral("TestThreat")));
    QVERIFY(!QFile::exists(filePath));
    QCOMPARE(quarantine.entries().size(), 1);

    QVERIFY(quarantine.restore(0));
    QVERIFY(QFile::exists(filePath));
}

QTEST_MAIN(TestQuarantine)
#include "test_quarantine.moc"
