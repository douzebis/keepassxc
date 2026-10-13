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

#include "DeviceStorage.h"

#include <QCoreApplication>
#include <QProcess>
#include <QProcessEnvironment>
#include <QThread>

namespace
{
    const QString kScheme = QStringLiteral("yubikey:");
    /// Writes to a YubiKey take seconds (4 s for 22 KB, measured).
    constexpr int kTimeoutMs = 120 * 1000;

    QString tr(const char* text)
    {
        return QCoreApplication::translate("DeviceStorage", text);
    }

    /// Runs the `yb` command: `KPXC_YB` if set, `yb` from PATH otherwise.
    DeviceStorage::Result runYb(const QStringList& arguments, const QByteArray& input)
    {
        DeviceStorage::Result result;
        QProcess process;
        auto program = QProcessEnvironment::systemEnvironment().value("KPXC_YB", "yb");
        process.start(program, arguments);
        if (!process.waitForStarted()) {
            result.errorText = tr("Could not run %1: %2").arg(program, process.errorString());
            return result;
        }
        process.write(input);
        process.closeWriteChannel();
        if (!process.waitForFinished(kTimeoutMs)) {
            process.kill();
            process.waitForFinished();
            result.errorText = tr("%1 did not finish in time.").arg(program);
            return result;
        }
        result.exitCode = process.exitStatus() == QProcess::NormalExit ? process.exitCode() : -1;
        result.output = process.readAllStandardOutput();
        result.errorText = QString::fromUtf8(process.readAllStandardError()).trimmed();
        return result;
    }

    /// The vault's name without its `.kdbx` extension.
    QString stem(const QString& blob)
    {
        return blob.endsWith(".kdbx") ? blob.chopped(5) : blob;
    }
} // namespace

DeviceStorage::DeviceStorage()
    : m_runner(runYb)
{
}

DeviceStorage* DeviceStorage::instance()
{
    static DeviceStorage storage;
    return &storage;
}

bool DeviceStorage::isDeviceLocation(const QString& location)
{
    return location.startsWith(kScheme);
}

QString DeviceStorage::location(const QString& serial, const QString& blob)
{
    return kScheme + serial + "/" + blob;
}

bool DeviceStorage::parse(const QString& location, QString* serial, QString* blob)
{
    if (!isDeviceLocation(location)) {
        return false;
    }
    auto rest = location.mid(kScheme.size());
    auto slash = rest.indexOf('/');
    if (slash < 0 || slash == rest.size() - 1) {
        return false;
    }
    *serial = rest.left(slash);
    *blob = rest.mid(slash + 1);
    return true;
}

DeviceStorage::Result DeviceStorage::run(const QString& serial, const QStringList& arguments, const QByteArray& input)
{
    QStringList all{"--quiet"};
    if (!serial.isEmpty()) {
        all << "--serial" << serial;
    }
    all << arguments;
    return m_runner(all, input);
}

QString DeviceStorage::describe(const Result& result, const QString& blob)
{
    switch (result.exitCode) {
    case NotFound:
        return tr("%1 is not on the YubiKey.").arg(blob);
    case StoreFull:
        return tr("Not enough room on the YubiKey to save %1: it needs room for a second copy while "
                  "saving.\n%2")
            .arg(blob, result.errorText);
    default:
        return result.errorText.isEmpty() ? tr("yb failed (exit status %1).").arg(result.exitCode) : result.errorText;
    }
}

bool DeviceStorage::pinFor(const QString& serial, QByteArray* pin, QString* error)
{
    if (!m_pins.contains(serial)) {
        QString entered;
        if (m_pinPrompt) {
            // Saves run on a worker thread; the prompt is GUI, so it runs on
            // the GUI thread (which runs an event loop while it waits).
            auto* app = QCoreApplication::instance();
            if (app && QThread::currentThread() != app->thread()) {
                QMetaObject::invokeMethod(app, [&] { entered = m_pinPrompt(serial); }, Qt::BlockingQueuedConnection);
            } else {
                entered = m_pinPrompt(serial);
            }
        }
        if (entered.isNull()) {
            *error = tr("The YubiKey's PIN is needed.");
            return false;
        }
        setPin(serial, entered);
    }
    *pin = m_pins.value(serial);
    return true;
}

QByteArray DeviceStorage::fingerprint(const QString& serial, const QString& blob, QString* error)
{
    auto result = run(serial, {"ls", "-l", blob});
    if (result.exitCode != 0) {
        *error = describe(result, blob);
        return {};
    }
    return result.output.trimmed();
}

bool DeviceStorage::fetch(const QString& serial, const QString& blob, QByteArray* data, QString* error)
{
    QByteArray pin;
    if (!pinFor(serial, &pin, error)) {
        return false;
    }
    auto result = run(serial, {"--pin-stdin", "fetch", "-p", blob}, pin + "\n");
    if (result.exitCode != 0) {
        if (result.errorText.contains("PIN")) {
            forgetPin(serial);
        }
        *error = describe(result, blob);
        return false;
    }
    *data = result.output;
    return true;
}

bool DeviceStorage::read(const QString& location, QByteArray* data, QString* error)
{
    QString serial, blob;
    if (!parse(location, &serial, &blob)) {
        *error = tr("Not a device location: %1").arg(location);
        return false;
    }
    auto current = fingerprint(serial, blob, error);
    if (current.isEmpty()) {
        return false;
    }
    auto cached = m_cache.constFind(location);
    if (cached != m_cache.constEnd() && cached->fingerprint == current) {
        *data = cached->data;
        return true;
    }
    if (!fetch(serial, blob, data, error)) {
        return false;
    }
    m_cache.insert(location, {*data, current});
    return true;
}

bool DeviceStorage::write(const QString& location, const QByteArray& data, QString* error)
{
    QString serial, blob;
    if (!parse(location, &serial, &blob)) {
        *error = tr("Not a device location: %1").arg(location);
        return false;
    }
    QByteArray pin;
    if (!pinFor(serial, &pin, error)) {
        return false;
    }
    // The PIN on the first line, the vault after it (yb spec 0037).
    auto result = run(serial, {"--pin-stdin", "store", "--encrypted", "--no-compress", "-n", blob}, pin + "\n" + data);
    if (result.exitCode != 0) {
        if (result.errorText.contains("PIN")) {
            forgetPin(serial);
        }
        *error = describe(result, blob);
        return false;
    }
    QString ignored;
    m_cache.insert(location, {data, fingerprint(serial, blob, &ignored)});
    return true;
}

QStringList DeviceStorage::listVaults(const QString& serial, QString* error)
{
    auto result = run(serial, {"ls", "*.kdbx"});
    if (result.exitCode == NotFound) {
        return {};
    }
    if (result.exitCode != 0) {
        *error = describe(result, "*.kdbx");
        return {};
    }
    QStringList vaults;
    for (const auto& line : QString::fromUtf8(result.output).split('\n', Qt::SkipEmptyParts)) {
        // Markers (UNSIGNED, LEGACY…) follow the name after two spaces.
        vaults << line.section("  ", 0, 0).trimmed();
    }
    return vaults;
}

bool DeviceStorage::readPassword(const QString& location, QString* password, QString* error)
{
    QString serial, blob;
    if (!parse(location, &serial, &blob)) {
        *error = tr("Not a device location: %1").arg(location);
        return false;
    }
    auto passwd = stem(blob) + ".passwd";
    auto listed = run(serial, {"ls", passwd});
    if (listed.exitCode == NotFound) {
        password->clear();
        return true;
    }
    QByteArray bytes;
    if (!fetch(serial, passwd, &bytes, error)) {
        return false;
    }
    // A password typed into `yb store` may end with a newline.
    if (bytes.endsWith('\n')) {
        bytes.chop(1);
    }
    *password = QString::fromUtf8(bytes);
    bytes.fill('\0');
    return true;
}

void DeviceStorage::setPin(const QString& serial, const QString& pin)
{
    forgetPin(serial);
    m_pins.insert(serial, pin.toUtf8());
}

void DeviceStorage::forgetPin(const QString& serial)
{
    auto it = m_pins.find(serial);
    if (it != m_pins.end()) {
        it->fill('\0');
        m_pins.erase(it);
    }
}

void DeviceStorage::setRunner(Runner runner)
{
    m_runner = runner ? std::move(runner) : Runner(runYb);
}

void DeviceStorage::setPinPrompt(PinPrompt prompt)
{
    m_pinPrompt = std::move(prompt);
}

void DeviceStorage::clearCache()
{
    m_cache.clear();
}
