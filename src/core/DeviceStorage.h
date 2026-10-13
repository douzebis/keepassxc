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

#ifndef KEEPASSXC_DEVICESTORAGE_H
#define KEEPASSXC_DEVICESTORAGE_H

#include <QByteArray>
#include <QHash>
#include <QString>
#include <QStringList>

#include <functional>

/**
 * Databases stored on a device instead of a file (mock-up).
 *
 * A device database is named by a location, `yubikey:<serial>/<vault>.kdbx`
 * (`yubikey:/<vault>.kdbx` for the only YubiKey connected), used wherever
 * KeePassXC uses a file path as an identity.  Its bytes go between the
 * device and memory: no copy on disk.  The YubiKey is reached through the
 * `yb` command (https://github.com/douzebis/yb), which keeps the vault in
 * the YubiKey's PIV application, encrypted to a key that never leaves it,
 * and replaces it safely (an interrupted write keeps the previous vault).
 *
 * Reads are served from a cache of the encrypted bytes, checked against the
 * device without the PIN; writes go to the device at once (write-through).
 */
class DeviceStorage
{
public:
    /// What a run of `yb` returned.
    struct Result
    {
        int exitCode = -1;
        QByteArray output;
        QString errorText;
    };
    /// Runs `yb` with `arguments`, `input` on its standard input.
    using Runner = std::function<Result(const QStringList& arguments, const QByteArray& input)>;
    /// Asks the user for the PIN of the YubiKey `serial` (empty: the only
    /// one connected); a null string cancels.
    using PinPrompt = std::function<QString(const QString& serial)>;

    /// Exit statuses of `yb` (yb spec 0032).
    static constexpr int NotFound = 2;
    static constexpr int StoreFull = 3;

    static DeviceStorage* instance();

    static bool isDeviceLocation(const QString& location);
    static QString location(const QString& serial, const QString& blob);
    /// Splits a location into the YubiKey's serial and the blob name.
    static bool parse(const QString& location, QString* serial, QString* blob);

    /// The vault's bytes: from the cache if the device still holds them,
    /// otherwise fetched (with the PIN).
    bool read(const QString& location, QByteArray* data, QString* error);
    /// Store `data` on the device (with the PIN); updates the cache.
    bool write(const QString& location, const QByteArray& data, QString* error);

    /// The vaults (`*.kdbx` blobs) on a YubiKey; no PIN needed.
    QStringList listVaults(const QString& serial, QString* error);
    /// The vault's stored master password (`<vault>.passwd`), if any.
    bool readPassword(const QString& location, QString* password, QString* error);

    void setPin(const QString& serial, const QString& pin);
    /// Forget the PIN of a YubiKey, overwriting it in memory.
    void forgetPin(const QString& serial);

    void setRunner(Runner runner);
    void setPinPrompt(PinPrompt prompt);
    /// Drop cached bytes (tests).
    void clearCache();

private:
    DeviceStorage();

    struct CacheEntry
    {
        QByteArray data;
        /// The vault as `yb ls -l` lists it (chunks, time, size): detects a
        /// change on the device without the PIN.
        QByteArray fingerprint;
    };

    Result run(const QString& serial, const QStringList& arguments, const QByteArray& input = {});
    bool pinFor(const QString& serial, QByteArray* pin, QString* error);
    QByteArray fingerprint(const QString& serial, const QString& blob, QString* error);
    bool fetch(const QString& serial, const QString& blob, QByteArray* data, QString* error);
    static QString describe(const Result& result, const QString& blob);

    Runner m_runner;
    PinPrompt m_pinPrompt;
    QHash<QString, QByteArray> m_pins;
    QHash<QString, CacheEntry> m_cache;
};

#endif // KEEPASSXC_DEVICESTORAGE_H
