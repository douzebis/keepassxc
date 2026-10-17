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

#include "TestKeePassYB.h"

#include <QCoreApplication>
#include <QStandardPaths>
#include <QTest>

#include "core/Config.h"

QTEST_GUILESS_MAIN(TestKeePassYB)

void TestKeePassYB::initTestCase()
{
    // As main() sets it; test mode keeps the real settings untouched.
    QCoreApplication::setApplicationName("KeePassYB");
    QStandardPaths::setTestModeEnabled(true);
    qunsetenv("KPXC_CONFIG");
    qunsetenv("KPXC_CONFIG_LOCAL");
}

/// The settings are KeePassYB's own files, never KeePassXC's: both
/// applications run side by side, each with its settings.
void TestKeePassYB::testOwnConfigFiles()
{
    const auto file = config()->getFileName();
    QVERIFY2(file.contains("keepassyb", Qt::CaseInsensitive), qPrintable(file));
    QVERIFY2(!file.contains("keepassxc", Qt::CaseInsensitive), qPrintable(file));
}
