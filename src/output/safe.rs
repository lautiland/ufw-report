use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Writes output without silently replacing different existing content.
///
/// The rendered bytes are written to a temporary file in the destination
/// directory. If the destination does not exist, it is linked into place
/// atomically. If it exists with identical bytes, the write is treated as an
/// idempotent success. If it exists with different bytes, a collision error is
/// returned and the original file is left untouched.
pub(crate) fn write_output_file<F>(path: &str, render: F) -> anyhow::Result<()>
where
    F: FnOnce(&mut fs::File) -> anyhow::Result<()>,
{
    let target = Path::new(path);
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("output");

    let temp_path = create_temp_file(parent, file_name, render)?;

    match fs::read(target) {
        Ok(existing) => {
            let new = fs::read(&temp_path)?;
            let _ = fs::remove_file(&temp_path);
            if existing == new {
                tracing::info!("Output {} is already up to date", target.display());
                Ok(())
            } else {
                anyhow::bail!(
                    "Output file '{}' already exists with different content; refusing to \
                     overwrite (collision)",
                    target.display()
                )
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // `hard_link` refuses to replace an existing path, unlike `rename`.
            match fs::hard_link(&temp_path, target) {
                Ok(()) => {
                    let _ = fs::remove_file(&temp_path);
                    Ok(())
                }
                Err(link_error) => {
                    let _ = fs::remove_file(&temp_path);
                    if link_error.kind() == io::ErrorKind::AlreadyExists {
                        anyhow::bail!(
                            "Output file '{}' was created concurrently; refusing to overwrite \
                             (collision)",
                            target.display()
                        )
                    }
                    Err(link_error.into())
                }
            }
        }
        Err(error) => {
            let _ = fs::remove_file(&temp_path);
            Err(error.into())
        }
    }
}

fn create_temp_file<F>(
    parent: &Path,
    file_name: &str,
    render: F,
) -> anyhow::Result<std::path::PathBuf>
where
    F: FnOnce(&mut fs::File) -> anyhow::Result<()>,
{
    for attempt in 0..100_u32 {
        let candidate = parent.join(format!(".{file_name}.{}.{attempt}.tmp", std::process::id()));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                let result = render(&mut file).and_then(|()| {
                    file.flush()?;
                    file.sync_all()?;
                    Ok(())
                });
                drop(file);
                if let Err(error) = result {
                    let _ = fs::remove_file(&candidate);
                    return Err(error);
                }
                return Ok(candidate);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }

    anyhow::bail!(
        "Could not create a temporary output file next to '{}'",
        parent.join(file_name).display()
    )
}
