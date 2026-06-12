#include "signaturedb.h"

#include <QFile>
#include <QRegularExpression>
#include <QTextStream>

bool SignatureDB::load(const QString& filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
        return false;

    m_signatures.clear();

    static const QRegularExpression ws(QStringLiteral(R"(\s+)"));
    QTextStream in(&file);
    while (!in.atEnd()) {
        const QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#')))
            continue;

        const QStringList parts = line.split(ws, Qt::SkipEmptyParts);
        if (parts.size() >= 2)
            m_signatures.insert(parts.at(0).toLower(),
                                  parts.mid(1).join(QLatin1Char(' ')));
    }
    return !m_signatures.isEmpty();
}

QString SignatureDB::lookup(const QString& md5Hex) const {
    return m_signatures.value(md5Hex.toLower());
}
