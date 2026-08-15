const extract = require('../')
const fs = require('fs-extra')
const os = require('os')
const path = require('path')
const test = require('ava')

const catsZip = path.join(__dirname, 'cats.zip')
const githubZip = path.join(__dirname, 'github.zip')
const noPermissionsZip = path.join(__dirname, 'no-permissions.zip')
const subdirZip = path.join(__dirname, 'file-in-subdir-without-subdir-entry.zip')
const symlinkDestZip = path.join(__dirname, 'symlink-dest.zip')
const symlinkZip = path.join(__dirname, 'symlink.zip')
const brokenZip = path.join(__dirname, 'broken.zip')

const relativeTarget = './cats'
const evilSymlinkName = 'evil_symlink'

async function mkdtemp (t, suffix) {
  return fs.mkdtemp(path.join(os.tmpdir(), `extract-zip-${suffix}`))
}

async function tempExtract (t, suffix, zipPath) {
  const dirPath = await mkdtemp(t, suffix)
  await extract(zipPath, { dir: dirPath })
  return dirPath
}

async function pathExists (t, pathToCheck, message) {
  const exists = await fs.pathExists(pathToCheck)
  t.true(exists, message)
}

async function pathDoesntExist (t, pathToCheck, message) {
  const exists = await fs.pathExists(pathToCheck)
  t.false(exists, message)
}

// pathDoesntExist() resolves symlinks, so it can't tell a dangling symlink from a
// missing one. This checks that nothing at all exists at the given path.
async function nothingExistsAt (t, pathToCheck, message) {
  let missing = false
  try {
    await fs.lstat(pathToCheck)
  } catch (err) {
    missing = err.code === 'ENOENT'
  }
  t.true(missing, message)
}

// CRC-32 (IEEE 802.3). Stored zip entries have to carry a real checksum.
function crc32 (buf) {
  let crc = -1
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i]
    for (let bit = 0; bit < 8; bit++) {
      crc = (crc >>> 1) ^ (0xEDB88320 & -(crc & 1))
    }
  }
  return (crc ^ -1) >>> 0
}

// Builds a minimal store-only (compression method 0) zip holding a single entry that
// is flagged as a unix symlink, with the symlink target as the entry contents. This
// is how a malicious archive smuggles an out of bound symlink past an extractor.
function symlinkZipBuffer (fileName, target) {
  const nameBuf = Buffer.from(fileName, 'utf8')
  const dataBuf = Buffer.from(target, 'utf8')
  const crc = crc32(dataBuf)
  const modTime = 24576 // 12:00:00
  const modDate = 20682 // 2020-06-10
  const unixMadeBy = 3 << 8
  const symlinkAttributes = 0o120777 * 0x10000 // shifting would overflow into a signed int

  const localHeader = Buffer.alloc(30)
  localHeader.writeUInt32LE(0x04034b50, 0) // local file header signature
  localHeader.writeUInt16LE(20, 4) // version needed to extract
  localHeader.writeUInt16LE(0, 6) // general purpose bit flag
  localHeader.writeUInt16LE(0, 8) // compression method: stored
  localHeader.writeUInt16LE(modTime, 10)
  localHeader.writeUInt16LE(modDate, 12)
  localHeader.writeUInt32LE(crc, 14)
  localHeader.writeUInt32LE(dataBuf.length, 18) // compressed size
  localHeader.writeUInt32LE(dataBuf.length, 22) // uncompressed size
  localHeader.writeUInt16LE(nameBuf.length, 26)
  localHeader.writeUInt16LE(0, 28) // extra field length

  const centralHeader = Buffer.alloc(46)
  centralHeader.writeUInt32LE(0x02014b50, 0) // central directory header signature
  centralHeader.writeUInt16LE(unixMadeBy, 4) // version made by
  centralHeader.writeUInt16LE(20, 6) // version needed to extract
  centralHeader.writeUInt16LE(0, 8) // general purpose bit flag
  centralHeader.writeUInt16LE(0, 10) // compression method: stored
  centralHeader.writeUInt16LE(modTime, 12)
  centralHeader.writeUInt16LE(modDate, 14)
  centralHeader.writeUInt32LE(crc, 16)
  centralHeader.writeUInt32LE(dataBuf.length, 20) // compressed size
  centralHeader.writeUInt32LE(dataBuf.length, 24) // uncompressed size
  centralHeader.writeUInt16LE(nameBuf.length, 28)
  centralHeader.writeUInt16LE(0, 30) // extra field length
  centralHeader.writeUInt16LE(0, 32) // file comment length
  centralHeader.writeUInt16LE(0, 34) // disk number start
  centralHeader.writeUInt16LE(0, 36) // internal file attributes
  centralHeader.writeUInt32LE(symlinkAttributes, 38) // external file attributes
  centralHeader.writeUInt32LE(0, 42) // relative offset of local header

  const localRecord = Buffer.concat([localHeader, nameBuf, dataBuf])
  const centralRecord = Buffer.concat([centralHeader, nameBuf])

  const endRecord = Buffer.alloc(22)
  endRecord.writeUInt32LE(0x06054b50, 0) // end of central directory signature
  endRecord.writeUInt16LE(0, 4) // number of this disk
  endRecord.writeUInt16LE(0, 6) // disk where central directory starts
  endRecord.writeUInt16LE(1, 8) // central directory records on this disk
  endRecord.writeUInt16LE(1, 10) // total central directory records
  endRecord.writeUInt32LE(centralRecord.length, 12) // size of central directory
  endRecord.writeUInt32LE(localRecord.length, 16) // offset of central directory
  endRecord.writeUInt16LE(0, 20) // comment length

  return Buffer.concat([localRecord, centralRecord, endRecord])
}

async function writeSymlinkZip (t, suffix, target) {
  const zipDir = await mkdtemp(t, `${suffix}-zip`)
  const zipPath = path.join(zipDir, 'malicious.zip')
  await fs.writeFile(zipPath, symlinkZipBuffer(evilSymlinkName, target))
  return zipPath
}

async function assertPermissions (t, pathToCheck, expectedMode) {
  const stats = await fs.stat(pathToCheck)
  const actualMode = (stats.mode & 0o777)
  t.is(actualMode, expectedMode)
}

test('files', async t => {
  const dirPath = await tempExtract(t, 'files', catsZip)
  await pathExists(t, path.join(dirPath, 'cats', 'gJqEYBs.jpg'), 'file created')
})

test('symlinks', async t => {
  const dirPath = await tempExtract(t, 'symlinks', catsZip)
  const symlink = path.join(dirPath, 'cats', 'orange_symlink')

  await pathExists(t, path.join(dirPath, 'cats'), 'directory created')
  await pathExists(t, symlink, `symlink created: ${symlink}`)

  const stats = await fs.lstat(symlink)
  t.truthy(stats.isSymbolicLink(), 'symlink is valid')
  const linkPath = await fs.readlink(symlink)
  t.is(linkPath, 'orange')
})

// These two run on every platform: the malicious entry has to be rejected before
// fs.symlink() is ever reached, so they never depend on being allowed to create a
// symlink (which is privileged on Windows).
test('symlink with a relative out of bound target disallowed', async t => {
  const target = '../../../../tmp/extract-zip-evil-relative'
  const zipPath = await writeSymlinkZip(t, 'relative-symlink-target', target)
  const dirPath = await mkdtemp(t, 'relative-symlink-target')

  await t.throwsAsync(extract(zipPath, { dir: dirPath }), {
    message: /Out of bound path ".*?" found while processing file evil_symlink/
  })

  await nothingExistsAt(t, path.join(dirPath, evilSymlinkName), 'symlink not created')
  await nothingExistsAt(t, path.resolve(dirPath, target), 'nothing created outside the target directory')
})

test('symlink with an absolute out of bound target disallowed', async t => {
  const target = path.resolve(os.tmpdir(), 'extract-zip-evil-absolute')
  t.true(path.isAbsolute(target), 'symlink target is absolute')

  const zipPath = await writeSymlinkZip(t, 'absolute-symlink-target', target)
  const dirPath = await mkdtemp(t, 'absolute-symlink-target')

  await t.throwsAsync(extract(zipPath, { dir: dirPath }), {
    message: /Out of bound path ".*?" found while processing file evil_symlink/
  })

  await nothingExistsAt(t, path.join(dirPath, evilSymlinkName), 'symlink not created')
  await nothingExistsAt(t, target, 'nothing created outside the target directory')
})

// Positive control: the same handcrafted zip is extracted normally when its symlink
// target stays inside the target directory, and the target is stored as-is.
test('symlink with an in bound target is stored verbatim', async t => {
  const zipPath = await writeSymlinkZip(t, 'in-bound-symlink-target', 'sibling')
  const dirPath = await mkdtemp(t, 'in-bound-symlink-target')
  await extract(zipPath, { dir: dirPath })

  const symlink = path.join(dirPath, evilSymlinkName)
  const stats = await fs.lstat(symlink)
  t.truthy(stats.isSymbolicLink(), 'symlink is valid')
  t.is(await fs.readlink(symlink), 'sibling', 'link target is not rewritten')
})

test('directories', async t => {
  const dirPath = await tempExtract(t, 'directories', catsZip)
  const dirWithContent = path.join(dirPath, 'cats', 'orange')
  const dirWithoutContent = path.join(dirPath, 'cats', 'empty')

  await pathExists(t, dirWithContent, 'directory created')

  const filesWithContent = await fs.readdir(dirWithContent)
  t.not(filesWithContent.length, 0, 'directory has files')

  await pathExists(t, dirWithoutContent, 'empty directory created')

  const filesWithoutContent = await fs.readdir(dirWithoutContent)
  t.is(filesWithoutContent.length, 0, 'empty directory has no files')
})

test('verify github zip extraction worked', async t => {
  const dirPath = await tempExtract(t, 'verify-extraction', githubZip)
  await pathExists(t, path.join(dirPath, 'extract-zip-master', 'test'), 'folder created')
  if (process.platform !== 'win32') {
    await assertPermissions(t, path.join(dirPath, 'extract-zip-master', 'test'), 0o755)
  }
})

test('opts.onEntry', async t => {
  const dirPath = await mkdtemp(t, 'onEntry')
  const actualEntries = []
  const expectedEntries = [
    'symlink/',
    'symlink/foo.txt',
    'symlink/foo_symlink.txt'
  ]
  const onEntry = function (entry) {
    actualEntries.push(entry.fileName)
  }
  await extract(symlinkZip, { dir: dirPath, onEntry })
  t.deepEqual(actualEntries, expectedEntries, 'entries should match')
})

test('relative target directory', async t => {
  await fs.remove(relativeTarget)
  await t.throwsAsync(extract(catsZip, { dir: relativeTarget }), {
    message: 'Target directory is expected to be absolute'
  })
  await pathDoesntExist(t, path.join(__dirname, relativeTarget), 'folder not created')
  await fs.remove(relativeTarget)
})

if (process.platform !== 'win32') {
  // symlink-dest.zip holds `symlink-dest/aaa -> /tmp` followed by `symlink-dest/aaa/file.txt`.
  // The out of bound symlink is now rejected on its own entry, before it is created, so the
  // entry written through it is never even reached.
  test('symlink destination disallowed', async t => {
    const dirPath = await mkdtemp(t, 'symlink-destination-disallowed')
    await pathDoesntExist(t, path.join(dirPath, 'file.txt'), "file doesn't exist at symlink target")

    await t.throwsAsync(extract(symlinkDestZip, { dir: dirPath }), {
      message: /Out of bound path ".*?" found while processing file symlink-dest\/aaa/
    })
  })

  test('no file created out of bound', async t => {
    const dirPath = await mkdtemp(t, 'out-of-bounds-file')
    await t.throwsAsync(extract(symlinkDestZip, { dir: dirPath }))

    const symlinkDestDir = path.join(dirPath, 'symlink-dest')

    await pathExists(t, symlinkDestDir, 'target folder created')
    await nothingExistsAt(t, path.join(symlinkDestDir, 'aaa'), 'out of bound symlink not created')
    await pathDoesntExist(t, path.join(symlinkDestDir, 'ccc', 'file.txt'), 'file not created in original folder')
    await pathDoesntExist(t, path.join(dirPath, 'file.txt'), 'file not created in symlink target')
  })

  // The symlink target check above means a zip can no longer plant the escaping symlink
  // itself, so this plants one by hand to keep the destination directory check covered.
  test('out of bound destination directory disallowed', async t => {
    const dirPath = await mkdtemp(t, 'out-of-bounds-dest-dir')
    const outsideDir = await mkdtemp(t, 'out-of-bounds-outside')
    await fs.symlink(outsideDir, path.join(dirPath, 'symlink-dest'))

    await t.throwsAsync(extract(symlinkDestZip, { dir: dirPath }), {
      message: /Out of bound path ".*?" found while processing file symlink-dest\/aaa/
    })

    await pathDoesntExist(t, path.join(outsideDir, 'aaa'), 'nothing extracted outside the target directory')
  })

  test('defaultDirMode', async t => {
    const dirPath = await mkdtemp(t, 'default-dir-mode')
    const defaultDirMode = 0o700
    await extract(githubZip, { dir: dirPath, defaultDirMode })
    await assertPermissions(t, path.join(dirPath, 'extract-zip-master', 'test'), defaultDirMode)
  })

  test('defaultFileMode not set', async t => {
    const dirPath = await mkdtemp(t, 'default-file-mode')
    await extract(noPermissionsZip, { dir: dirPath })
    await assertPermissions(t, path.join(dirPath, 'folder', 'file.txt'), 0o644)
  })

  test('defaultFileMode', async t => {
    const dirPath = await mkdtemp(t, 'default-file-mode')
    const defaultFileMode = 0o600
    await extract(noPermissionsZip, { dir: dirPath, defaultFileMode })
    await assertPermissions(t, path.join(dirPath, 'folder', 'file.txt'), defaultFileMode)
  })
}

test('files in subdirs where the subdir does not have its own entry is extracted', async t => {
  const dirPath = await tempExtract(t, 'subdir-file', subdirZip)
  await pathExists(t, path.join(dirPath, 'foo', 'bar'), 'file created')
})

test('extract broken zip', async t => {
  const dirPath = await mkdtemp(t, 'broken-zip')
  await t.throwsAsync(extract(brokenZip, { dir: dirPath }), {
    message: 'invalid central directory file header signature: 0x2014b00'
  })
})
