#pragma once

#include <QHash>
#include <QString>

/**
 * @brief Loads and queries the MD5 signature database.
 *
 * File format (signatures.db):
 *   # comment line
 *   44d88612fea8a8f36de82e1278abb02f  EICAR-Standard-Test-File
 *
 * The first whitespace-delimited token is the lowercase MD5 hex.
 * The rest of the line is the threat name.
 */
class SignatureDB {
public:
    /**
     * @brief Load signatures from file.
     * @return true if at least one signature was loaded.
     */
    bool load(const QString& filePath);

    /**
     * @brief Look up a threat name by MD5 hex string.
     * @return Threat name, or empty QString if not found.
     */
    QString lookup(const QString& md5Hex) const;

    int count() const { return static_cast<int>(m_signatures.size()); }

private:
    QHash<QString, QString> m_signatures;   // lowercase MD5 -> threat name
};
