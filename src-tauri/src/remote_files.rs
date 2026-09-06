const MAX_READ_BYTES: u64 = 2_097_152;

pub(crate) fn normalize_remote_path(username: &str, requested: &str) -> Result<String, String> {
    validate_username(username)?;
    let root = format!("/home/{username}");
    let trimmed = requested.trim();
    let path = if trimmed.is_empty() {
        root.clone()
    } else if trimmed.starts_with('/') {
        trimmed.to_owned()
    } else {
        format!("{root}/{trimmed}")
    };
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err("Yol çalışma alanının dışına çıkıyor.".into());
                }
            }
            value => parts.push(value),
        }
    }
    let normalized = format!("/{}", parts.join("/"));
    if normalized != root && !normalized.starts_with(&format!("{root}/")) {
        return Err("Sadece kullanıcı çalışma alanına erişebilirsin.".into());
    }
    Ok(normalized)
}

pub(crate) fn remote_root(username: &str) -> Result<String, String> {
    validate_username(username)?;
    Ok(format!("/home/{username}"))
}

pub(crate) fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(crate) fn guarded_root_command(username: &str) -> Result<String, String> {
    let root = remote_root(username)?;
    Ok(format!("root={}; actual_root=$(realpath -e -- \"$root\") || exit 40; [ \"$actual_root\" = \"$root\" ] || exit 41; [ -d \"$actual_root\" ] || exit 45", shell_single_quote(&root)))
}

pub(crate) fn guarded_list_command(username: &str, requested: &str) -> Result<String, String> {
    let root = remote_root(username)?;
    let target = normalize_remote_path(username, requested)?;
    Ok(format!(
        "root={}; target={}; actual_root=$(realpath -e -- \"$root\") || exit 40; [ \"$actual_root\" = \"$root\" ] || exit 41; cd -- \"$target\" || exit 42; actual=$(pwd -P) || exit 43; case \"$actual\" in \"$actual_root\"|\"$actual_root\"/*) ;; *) exit 44 ;; esac; LC_ALL=C find \"$actual\" -maxdepth 1 -mindepth 1 -printf '%y\\t%p\\t%s\\t%T@\\n' | sort -k2,2",
        shell_single_quote(&root), shell_single_quote(&target)
    ))
}

pub(crate) fn guarded_read_command(username: &str, requested: &str) -> Result<String, String> {
    let root = remote_root(username)?;
    let target = normalize_remote_path(username, requested)?;
    Ok(format!(
        "root={}; target={}; actual_root=$(realpath -e -- \"$root\") || exit 40; [ \"$actual_root\" = \"$root\" ] || exit 41; exec 3<\"$target\" || exit 42; actual=$(readlink -f /proc/self/fd/3) || exit 43; case \"$actual\" in \"$actual_root\"/*) ;; *) exit 44 ;; esac; [ -f /proc/self/fd/3 ] || exit 45; size=$(stat -Lc %s -- /proc/self/fd/3) || exit 46; [ \"$size\" -le {MAX_READ_BYTES} ] || exit 47; cat <&3",
        shell_single_quote(&root), shell_single_quote(&target)
    ))
}

pub(crate) fn guarded_mkdir_command(username: &str, parent: &str, name: &str) -> Result<String, String> {
    validate_name(name, "Geçersiz klasör adı.")?;
    parent_command(username, parent, name, "mkdir -- \"$name\"")
}

pub(crate) fn guarded_touch_command(username: &str, parent: &str, name: &str) -> Result<String, String> {
    validate_name(name, "Geçersiz dosya adı.")?;
    parent_command(username, parent, name, "if [ -e \"$name\" ] || [ -L \"$name\" ]; then actual=$(realpath -e -- \"$name\") || exit 45; case \"$actual\" in \"$actual_root\"/*) ;; *) exit 44 ;; esac; fi; touch -- \"$name\"")
}

pub(crate) fn guarded_rename_command(username: &str, old_path: &str, new_name: &str) -> Result<String, String> {
    validate_name(new_name, "Geçersiz yeni ad.")?;
    let old = normalize_remote_path(username, old_path)?;
    let (parent, old_name) = split_parent(&old)?;
    let body = format!("old_name={}; new_name={}; [ \"$old_name\" != . ] || exit 48; mv -T -- \"$old_name\" \"$new_name\"", shell_single_quote(old_name), shell_single_quote(new_name));
    parent_command(username, parent, old_name, &body)
}

pub(crate) fn guarded_delete_command(username: &str, requested: &str, is_directory: bool) -> Result<String, String> {
    let target = normalize_remote_path(username, requested)?;
    let root = remote_root(username)?;
    if target == root {
        return Err("Kullanıcı kökü silinemez.".into());
    }
    let (parent, name) = split_parent(&target)?;
    let operation = if is_directory { "rm -rf -- \"$target\"" } else { "rm -f -- \"$target\"" };
    let body = format!("target={}; {operation}", shell_single_quote(name));
    parent_command(username, parent, name, &body)
}

pub(crate) fn guarded_replace_command(username: &str, target_path: &str, staging_path: &str) -> Result<String, String> {
    let target = normalize_remote_path(username, target_path)?;
    let staging = normalize_remote_path(username, staging_path)?;
    let (parent, name) = split_parent(&target)?;
    let body = format!(
        "stage={}; stage_actual=$(realpath -e -- \"$stage\") || exit 49; case \"$stage_actual\" in \"$actual_root\"/*) ;; *) exit 44 ;; esac; [ -f \"$stage_actual\" ] || exit 45; if [ -e \"$name\" ] || [ -L \"$name\" ]; then target_actual=$(realpath -e -- \"$name\") || exit 43; case \"$target_actual\" in \"$actual_root\"/*) ;; *) exit 44 ;; esac; fi; mv -fT -- \"$stage_actual\" \"$name\"",
        shell_single_quote(&staging)
    );
    parent_command(username, parent, name, &body)
}

pub(crate) fn guarded_stage_download_command(username: &str, source_path: &str, staging_path: &str) -> Result<String, String> {
    let root = remote_root(username)?;
    let source = normalize_remote_path(username, source_path)?;
    let staging = normalize_remote_path(username, staging_path)?;
    Ok(format!(
        "root={}; source={}; stage={}; actual_root=$(realpath -e -- \"$root\") || exit 40; [ \"$actual_root\" = \"$root\" ] || exit 41; exec 3<\"$source\" || exit 42; actual=$(readlink -f /proc/self/fd/3) || exit 43; case \"$actual\" in \"$actual_root\"/*) ;; *) exit 44 ;; esac; [ -f /proc/self/fd/3 ] || exit 45; umask 077; cat <&3 > \"$stage\" || exit 46",
        shell_single_quote(&root), shell_single_quote(&source), shell_single_quote(&staging)
    ))
}

pub(crate) fn upload_target(username: &str, remote_dir: &str, local_name: &str) -> Result<String, String> {
    validate_name(local_name, "Geçersiz yerel dosya adı.")?;
    let dir = normalize_remote_path(username, remote_dir)?;
    normalize_remote_path(username, &format!("{dir}/{local_name}"))
}

fn parent_command(username: &str, requested_parent: &str, name: &str, operation: &str) -> Result<String, String> {
    let root = remote_root(username)?;
    let parent = normalize_remote_path(username, requested_parent)?;
    Ok(format!(
        "root={}; parent={}; name={}; actual_root=$(realpath -e -- \"$root\") || exit 40; [ \"$actual_root\" = \"$root\" ] || exit 41; actual_parent=$(realpath -e -- \"$parent\") || exit 42; case \"$actual_parent\" in \"$actual_root\"|\"$actual_root\"/*) ;; *) exit 44 ;; esac; cd -- \"$actual_parent\" || exit 43; {operation}",
        shell_single_quote(&root), shell_single_quote(&parent), shell_single_quote(name)
    ))
}

fn split_parent(path: &str) -> Result<(&str, &str), String> {
    match path.rsplit_once('/') {
        Some(("", name)) => Ok(("/", name)),
        Some((parent, name)) if !name.is_empty() => Ok((parent, name)),
        _ => Err("Geçersiz uzak dosya yolu.".into()),
    }
}

fn validate_name(name: &str, message: &str) -> Result<(), String> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || matches!(name, "." | "..") || name.contains('\0') {
        return Err(message.into());
    }
    Ok(())
}

fn validate_username(username: &str) -> Result<(), String> {
    if username.is_empty() || username.len() > 64 || !username.chars().all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
    }) {
        return Err("Geçersiz kullanıcı adı.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_command_checks_followed_target_inside_home() {
        // Given a lexically valid file path
        let command = guarded_read_command("armanc", "/home/armanc/docs/a.txt");

        // When the remote command is built
        let command = command.expect("valid fixture");

        // Then the followed target is checked and read through its open descriptor
        assert!(command.contains("readlink -f /proc/self/fd/3"));
        assert!(command.contains("cat <&3"));
    }

    #[test]
    fn final_link_delete_checks_parent_not_target() {
        // Given a final symlink-shaped path
        let command = guarded_delete_command("armanc", "/home/armanc/link", false);

        // When the delete command is built
        let command = command.expect("valid fixture");

        // Then the parent is resolved while rm operates on the link path
        assert!(command.contains("realpath -e -- \"$parent\""));
        assert!(command.contains("rm -f -- \"$target\""));
    }
}
