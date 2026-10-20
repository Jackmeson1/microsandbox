//! Guarded local observations and private staging, never portable capture or activation authority.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{File, Metadata},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::PassthroughFs;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Trusted caller-selected capture bounds; never accept an artifact's own limits.
#[derive(Clone, Copy)]
pub struct RuntimeScriptLimits {
    /// Maximum registered filenames to retain and pin.
    pub max_entries: usize,
    /// Maximum UTF-8 bytes in one observed script.
    pub max_script_bytes: usize,
    /// Maximum combined observed script bytes.
    pub max_total_bytes: usize,
}

/// Guest-visible runtime metadata, distinct from host access permissions and ownership.
/// This is local evidence, not a portable serialization or authorization decision.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RuntimeScriptMetadata {
    /// Guest-visible owner.
    pub uid: u32,
    /// Guest-visible group.
    pub gid: u32,
    /// Ordinary guest permission bits. Privileged bits are not representable here.
    pub mode: u16,
}

/// Pinned observations of registered files and their runtime/scripts directories.
///
/// The caller must hold the source's coherent capture/mutation guard through publication.
/// Revalidation detects observed changes but cannot replace that guard. This captures no
/// unregistered files and proves nothing about other handles in a full filesystem state.
/// It is not serializable: capture exclusions and binding substitution must precede export.
pub struct CapturedRuntimeScripts {
    runtime: Dir,
    limits: RuntimeScriptLimits,
    _scripts: Dir,
    runtime_stamp: FileStamp,
    scripts_stamp: FileStamp,
    runtime_metadata: RuntimeScriptMetadata,
    scripts_metadata: RuntimeScriptMetadata,
    files: BTreeMap<String, ScriptObservation>,
}

struct ScriptObservation {
    // Keep the captured inode alive so replacement cannot recycle its identity.
    _file: File,
    stamp: FileStamp,
    metadata: RuntimeScriptMetadata,
    content: Zeroizing<String>,
}

#[derive(PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    size: u64,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CapturedRuntimeScripts {
    /// Observe exact registered backing below an already pinned runtime directory.
    ///
    /// No source configuration text is reread. Symlinks, special files, invalid UTF-8,
    /// unsupported guest mode bits and oversized observations refuse with redacted errors.
    /// Empty registration is known empty; it is not permission to omit captured open files.
    pub fn capture(
        runtime: &File,
        registered: &BTreeSet<String>,
        limits: RuntimeScriptLimits,
    ) -> io::Result<Self> {
        if limits.max_script_bytes == usize::MAX {
            return Err(error("SCFG_LIMIT", "invalid script byte limit"));
        }
        if registered.len() > limits.max_entries {
            return Err(error("SCFG_LIMIT", "too many registered scripts"));
        }
        for name in registered {
            validate_name(name)?;
        }
        let runtime = Dir::from_std_file(runtime.try_clone().map_err(io_error)?);
        let scripts = scripts_directory(&runtime)?;
        let (runtime_stamp, runtime_metadata) = directory_observation(&runtime)?;
        let (scripts_stamp, scripts_metadata) = directory_observation(&scripts)?;
        let mut files = BTreeMap::new();
        let mut total = 0usize;
        for name in registered {
            let observation = observe_file(&scripts, name, limits.max_script_bytes)?;
            total = total
                .checked_add(observation.content.len())
                .ok_or_else(|| error("SCFG_LIMIT", "combined registered scripts are too large"))?;
            if total > limits.max_total_bytes {
                return Err(error(
                    "SCFG_LIMIT",
                    "combined registered scripts are too large",
                ));
            }
            files.insert(name.clone(), observation);
        }
        let captured = Self {
            runtime,
            limits,
            _scripts: scripts,
            runtime_stamp,
            scripts_stamp,
            runtime_metadata,
            scripts_metadata,
            files,
        };
        captured.revalidate()?;
        Ok(captured)
    }

    /// Read local observations for the capture sanitizer; content is never Debug/serialized here.
    pub fn observations(&self) -> impl Iterator<Item = (&str, &str, RuntimeScriptMetadata)> {
        self.files
            .iter()
            .map(|(name, file)| (name.as_str(), file.content.as_str(), file.metadata))
    }

    /// Recheck namespace, bytes and guest metadata while the source guard remains held.
    pub fn revalidate(&self) -> io::Result<()> {
        let scripts = scripts_directory(&self.runtime)?;
        let (runtime_stamp, runtime_metadata) = directory_observation(&self.runtime)?;
        let (scripts_stamp, scripts_metadata) = directory_observation(&scripts)?;
        // Directory size/timestamps also change for unrelated runtime heartbeat traffic.
        // Directory identity and guest permissions matter here; the coherent source guard
        // and full-state closure are responsible for other runtime files.
        if !same_inode(&runtime_stamp, &self.runtime_stamp)
            || !same_inode(&scripts_stamp, &self.scripts_stamp)
            || runtime_metadata != self.runtime_metadata
            || scripts_metadata != self.scripts_metadata
        {
            return Err(error("SCFG_RACE", "runtime script directory changed"));
        }
        for (name, original) in &self.files {
            let current = observe_file(&scripts, name, self.limits.max_script_bytes)?;
            if current.stamp != original.stamp
                || current.metadata != original.metadata
                || current.content.as_bytes() != original.content.as_bytes()
            {
                return Err(error("SCFG_RACE", "registered script backing changed"));
            }
        }
        Ok(())
    }

    /// Stage an exact local copy beneath a caller-owned private staging parent.
    ///
    /// The returned temporary runtime directory owns its files and cleans them up on drop.
    /// Nothing is installed over an existing runtime, executed, or published. The caller
    /// must complete source-generation, captured-handle and destination admission checks
    /// before adopting it. This local primitive does not implement archive restoration.
    pub fn stage_exact(&self, parent: &Path) -> io::Result<TempDir> {
        self.stage_with_check(parent, || Ok(()))
    }

    // A private completion seam lets tests inject a source race or a late failure after
    // the files exist. The public operation never runs caller-supplied code.
    pub(super) fn stage_with_check(
        &self,
        parent: &Path,
        after_files: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<TempDir> {
        self.revalidate()?;
        // TempDir retains its pathname for deferred cleanup. Pin a relative destination
        // to this call's cwd without canonicalizing symlinks or collapsing `..`.
        let parent = if parent.is_absolute() {
            parent.to_path_buf()
        } else {
            std::env::current_dir().map_err(io_error)?.join(parent)
        };
        let staged = tempfile::Builder::new()
            .prefix(".runtime-scripts-")
            .tempdir_in(&parent)
            .map_err(io_error)?;
        let runtime =
            Dir::open_ambient_dir(staged.path(), cap_std::ambient_authority()).map_err(io_error)?;
        runtime.create_dir("scripts").map_err(io_error)?;
        let scripts = scripts_directory(&runtime)?;
        for (name, source) in &self.files {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            options._cap_fs_ext_follow(cap_primitives::fs::FollowSymlinks::No);
            let mut file = scripts
                .open_with(name, &options)
                .map_err(io_error)?
                .into_std();
            file.write_all(source.content.as_bytes())
                .map_err(io_error)?;
            set_metadata(&file, source.metadata)?;
            file.sync_all().map_err(io_error)?;
        }
        set_directory_metadata(&scripts, self.scripts_metadata)?;
        set_directory_metadata(&runtime, self.runtime_metadata)?;
        after_files()?;
        // Verify the guest overlay too: matching host bytes alone would miss the 0640→0755
        // regression, and host mode cannot represent a guest's 0000 permission choice.
        for (name, expected) in &self.files {
            let actual = observe_file(&scripts, name, self.limits.max_script_bytes)?;
            if actual.content.as_bytes() != expected.content.as_bytes()
                || actual.metadata != expected.metadata
            {
                return Err(error("SCFG_INTEGRITY", "staged script backing differs"));
            }
        }
        self.revalidate()?;
        Ok(staged)
    }
}

impl FileStamp {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            links: metadata.nlink(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for CapturedRuntimeScripts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedRuntimeScripts")
            .field("count", &self.files.len())
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn observe_file(directory: &Dir, name: &str, max_bytes: usize) -> io::Result<ScriptObservation> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NONBLOCK);
    options._cap_fs_ext_follow(cap_primitives::fs::FollowSymlinks::No);
    let mut file = directory
        .open_with(name, &options)
        .map_err(io_error)?
        .into_std();
    let before = file.metadata().map_err(io_error)?;
    if !before.is_file() {
        return Err(error(
            "SCFG_BACKING",
            "registered backing is not a regular file",
        ));
    }
    let metadata = guest_metadata(&file)?;
    if before.len() > max_bytes as u64 {
        return Err(error("SCFG_LIMIT", "registered script is too large"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > max_bytes {
        return Err(error("SCFG_LIMIT", "registered script is too large"));
    }
    let content = std::str::from_utf8(&bytes)
        .map_err(|_| error("SCFG_BACKING", "registered script is not UTF-8"))?;
    let after = file.metadata().map_err(io_error)?;
    let stamp = FileStamp::from_metadata(&before);
    if stamp != FileStamp::from_metadata(&after) || metadata != guest_metadata(&file)? {
        return Err(error(
            "SCFG_RACE",
            "registered script changed during observation",
        ));
    }
    Ok(ScriptObservation {
        _file: file,
        stamp,
        metadata,
        content: Zeroizing::new(content.to_owned()),
    })
}

fn scripts_directory(runtime: &Dir) -> io::Result<Dir> {
    let root = runtime.try_clone().map_err(io_error)?.into_std_file();
    cap_primitives::fs::open_dir_nofollow(&root, Path::new("scripts"))
        .map(Dir::from_std_file)
        .map_err(io_error)
}

fn directory_observation(directory: &Dir) -> io::Result<(FileStamp, RuntimeScriptMetadata)> {
    let file = directory.try_clone().map_err(io_error)?.into_std_file();
    Ok((
        FileStamp::from_metadata(&file.metadata().map_err(io_error)?),
        guest_metadata(&file)?,
    ))
}

fn guest_metadata(file: &File) -> io::Result<RuntimeScriptMetadata> {
    let stat = PassthroughFs::runtime_backing_stat(file).map_err(io_error)?;
    #[cfg(target_os = "linux")]
    let mode = stat.st_mode & 0o7777;
    #[cfg(target_os = "macos")]
    let mode = u32::from(stat.st_mode) & 0o7777;
    if mode > 0o777 {
        return Err(error(
            "SCFG_BACKING",
            "guest script metadata contains unsupported bits",
        ));
    }
    Ok(RuntimeScriptMetadata {
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: mode as u16,
    })
}

fn set_metadata(file: &File, metadata: RuntimeScriptMetadata) -> io::Result<()> {
    PassthroughFs::set_runtime_backing_permissions(file, metadata.uid, metadata.gid, metadata.mode)
        .map_err(io_error)
}

fn set_directory_metadata(directory: &Dir, metadata: RuntimeScriptMetadata) -> io::Result<()> {
    // cap-std directory handles use O_PATH on Linux. Cloning that descriptor cannot
    // make fchmod/fsync work; open "." relative to the pinned directory instead.
    // This keeps the same inode without resolving its potentially replaced pathname.
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_DIRECTORY);
    options._cap_fs_ext_follow(cap_primitives::fs::FollowSymlinks::No);
    let file = directory
        .open_with(".", &options)
        .map_err(io_error)?
        .into_std();
    // Protect the host namespace while giving the guest its independently recorded mode.
    file.set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(io_error)?;
    set_metadata(&file, metadata)?;
    file.sync_all().map_err(io_error)
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 256
        || matches!(name, "." | "..")
        || name.contains(['\0', '/', '\\'])
    {
        return Err(error("SCFG_BACKING", "script name must be one filename"));
    }
    Ok(())
}

fn same_inode(a: &FileStamp, b: &FileStamp) -> bool {
    (a.device, a.inode) == (b.device, b.inode)
}

fn io_error(_: std::io::Error) -> io::Error {
    // Source paths and script names may contain sensitive destination/source values.
    error(
        "SCFG_BACKING",
        "cannot access regular runtime script backing",
    )
}

fn error(code: &str, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{code}: runtime.scripts: {detail}"),
    )
}
