/*
 *  Copyright (C) 2026 Frederic Ruget <fred@atlant.is>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "TestDeviceStorage.h"

#include <QRegularExpression>
#include <QTest>

#include "core/Database.h"
#include "core/DeviceStorage.h"
#include "core/Metadata.h"
#include "crypto/Crypto.h"
#include "keys/PasswordKey.h"

QTEST_GUILESS_MAIN(TestDeviceStorage)

namespace
{
    const QString Pin = QStringLiteral("654321");
    const QString Location = QStringLiteral("yubikey:/Passwords.kdbx");

    /// An in-memory stand-in for `yb` and its YubiKey: blobs by name, the
    /// PIN on the first line of standard input (yb spec 0037), exit status
    /// 2 for "not found", 3 for "store full".
    struct FakeYb
    {
        QHash<QString, QByteArray> blobs;
        QHash<QString, int> versions;
        QStringList calls;
        int fetches = 0;
        int stores = 0;
        bool full = false;

        static bool pinOk(const QByteArray& input, QByteArray* rest)
        {
            auto newline = input.indexOf('\n');
            if (newline < 0 || input.left(newline) != Pin.toUtf8()) {
                return false;
            }
            *rest = input.mid(newline + 1);
            return true;
        }

        DeviceStorage::Result run(const QStringList& arguments, const QByteArray& input)
        {
            calls << arguments.join(' ');
            QStringList args = arguments;
            args.removeAll("--quiet");
            args.removeAll("--pin-stdin");
            DeviceStorage::Result r;
            QByteArray rest;
            if (args.value(0) == "ls") {
                QString pattern = args.last();
                QRegularExpression re(QRegularExpression::wildcardToRegularExpression(pattern));
                QStringList names;
                for (auto it = blobs.constBegin(); it != blobs.constEnd(); ++it) {
                    if (re.match(it.key()).hasMatch()) {
                        names << (args.contains("-l") ? QString("- %1 %2 %3")
                                                            .arg(versions.value(it.key()))
                                                            .arg(it.value().size())
                                                            .arg(it.key())
                                                      : it.key());
                    }
                }
                r.exitCode = names.isEmpty() ? DeviceStorage::NotFound : 0;
                r.output = names.join('\n').toUtf8();
            } else if (args.value(0) == "fetch") {
                auto name = args.last();
                if (!pinOk(input, &rest)) {
                    r.exitCode = 1;
                    r.errorText = "wrong PIN";
                } else if (!blobs.contains(name)) {
                    r.exitCode = DeviceStorage::NotFound;
                } else {
                    ++fetches;
                    r.exitCode = 0;
                    r.output = blobs.value(name);
                }
            } else if (args.value(0) == "store") {
                auto name = args.last();
                if (!pinOk(input, &rest)) {
                    r.exitCode = 1;
                    r.errorText = "wrong PIN";
                } else if (full) {
                    r.exitCode = DeviceStorage::StoreFull;
                    r.errorText = "store is full";
                } else {
                    ++stores;
                    blobs.insert(name, rest);
                    versions[name] += 1;
                    r.exitCode = 0;
                }
            }
            return r;
        }
    };

    FakeYb* fake = nullptr;

    QSharedPointer<CompositeKey> key()
    {
        auto k = QSharedPointer<CompositeKey>::create();
        k->addKey(QSharedPointer<PasswordKey>::create("master"));
        return k;
    }

    /// A new database saved to the fake YubiKey.
    void saveNewDatabase(const QString& name)
    {
        auto db = QSharedPointer<Database>::create();
        db->setKey(key());
        db->metadata()->setName(name);
        QString error;
        QVERIFY2(db->saveAs(Location, Database::Atomic, {}, &error), qPrintable(error));
    }
} // namespace

void TestDeviceStorage::initTestCase()
{
    QVERIFY(Crypto::init());
}

void TestDeviceStorage::init()
{
    delete fake;
    fake = new FakeYb;
    auto* storage = DeviceStorage::instance();
    storage->setRunner([](const QStringList& a, const QByteArray& i) { return fake->run(a, i); });
    storage->setPinPrompt([](const QString&) { return Pin; });
    storage->clearCache();
    storage->forgetPin("");
}

void TestDeviceStorage::cleanupTestCase()
{
    DeviceStorage::instance()->setRunner({});
    DeviceStorage::instance()->setPinPrompt({});
    delete fake;
    fake = nullptr;
}

void TestDeviceStorage::testLocations()
{
    QVERIFY(DeviceStorage::isDeviceLocation("yubikey:12345678/Passwords.kdbx"));
    QVERIFY(!DeviceStorage::isDeviceLocation("/home/me/Passwords.kdbx"));
    QString serial, blob;
    QVERIFY(DeviceStorage::parse("yubikey:12345678/Passwords.kdbx", &serial, &blob));
    QCOMPARE(serial, QString("12345678"));
    QCOMPARE(blob, QString("Passwords.kdbx"));
    QVERIFY(DeviceStorage::parse("yubikey:/Work.kdbx", &serial, &blob));
    QVERIFY(serial.isEmpty());
    QVERIFY(!DeviceStorage::parse("yubikey:12345678/", &serial, &blob));

    // A device location is its own canonical path (there is no file).
    Database db(Location);
    QCOMPARE(db.canonicalFilePath(), Location);
}

/// A database saved to the device and opened from it: the bytes go through
/// `yb store` and `yb fetch -p`, with the PIN on standard input.
void TestDeviceStorage::testSaveAndOpen()
{
    saveNewDatabase("on the YubiKey");
    QCOMPARE(fake->stores, 1);
    QVERIFY(fake->blobs.value("Passwords.kdbx").size() > 0);
    QVERIFY(fake->calls.last().contains("ls -l Passwords.kdbx"));

    DeviceStorage::instance()->clearCache();
    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    QCOMPARE(db->metadata()->name(), QString("on the YubiKey"));
    QCOMPARE(db->filePath(), Location);
    QCOMPARE(fake->fetches, 1);
    QVERIFY(!db->isModified());
}

/// Opening again (unlock after lock, header reads) uses the cache: the
/// device is only asked whether the vault changed, without the PIN.
void TestDeviceStorage::testOpenUsesTheCache()
{
    saveNewDatabase("cached");
    for (int i = 0; i < 3; ++i) {
        auto db = QSharedPointer<Database>::create();
        QString error;
        QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    }
    QCOMPARE(fake->fetches, 0);
}

/// A vault changed on the device (another computer) is fetched again.
void TestDeviceStorage::testChangedVaultIsFetchedAgain()
{
    saveNewDatabase("first");
    auto stored = fake->blobs.value("Passwords.kdbx");
    saveNewDatabase("second");
    // Elsewhere, the first version is stored back.
    fake->blobs.insert("Passwords.kdbx", stored);
    fake->versions["Passwords.kdbx"] += 1;

    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY2(db->open(Location, key(), &error), qPrintable(error));
    QCOMPARE(db->metadata()->name(), QString("first"));
    QCOMPARE(fake->fetches, 1);
}

/// A save the device refuses (store full) fails with a clear message, and
/// leaves the database modified, so nothing is lost.
void TestDeviceStorage::testStoreFullKeepsTheDatabaseModified()
{
    saveNewDatabase("before");
    auto db = QSharedPointer<Database>::create();
    QString error;
    QVERIFY(db->open(Location, key(), &error));
    db->metadata()->setName("after");
    fake->full = true;
    QVERIFY(!db->save(Database::Atomic, {}, &error));
    QVERIFY(error.contains("Not enough room"));
    QVERIFY(db->isModified());

    fake->full = false;
    QVERIFY2(db->save(Database::Atomic, {}, &error), qPrintable(error));
    QVERIFY(!db->isModified());
}

/// The PIN is asked when first needed, then held; forgetting it (at lock)
/// makes the next save ask again.
void TestDeviceStorage::testPinIsAskedOnceAndForgotten()
{
    int prompts = 0;
    DeviceStorage::instance()->setPinPrompt([&prompts](const QString&) {
        ++prompts;
        return Pin;
    });
    saveNewDatabase("one");
    saveNewDatabase("two");
    QCOMPARE(prompts, 1);
    DeviceStorage::instance()->forgetPin("");
    saveNewDatabase("three");
    QCOMPARE(prompts, 2);

    // A cancelled prompt fails the save, and nothing is stored.
    DeviceStorage::instance()->forgetPin("");
    DeviceStorage::instance()->setPinPrompt([](const QString&) { return QString(); });
    auto db = QSharedPointer<Database>::create();
    db->setKey(key());
    QString error;
    QVERIFY(!db->saveAs(Location, Database::Atomic, {}, &error));
    QCOMPARE(fake->stores, 3);
}

/// The vault's master password, kept on the YubiKey as `<vault>.passwd`,
/// is read without its final newline; without one, nothing is read.
void TestDeviceStorage::testStoredMasterPassword()
{
    QString password, error;
    QVERIFY(DeviceStorage::instance()->readPassword(Location, &password, &error));
    QVERIFY(password.isEmpty());

    fake->blobs.insert("Passwords.passwd", "correct horse\n");
    QVERIFY(DeviceStorage::instance()->readPassword(Location, &password, &error));
    QCOMPARE(password, QString("correct horse"));
}
