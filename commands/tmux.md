# tmux Command Reference

tmux is a terminal multiplexer. It lets one terminal hold many sessions, windows, and panes, and keeps them running after you disconnect. On remote servers it means a long job survives a dropped SSH connection, and you can reattach later from anywhere. This page covers the prefix key, the session and pane model, copy mode, scripting, and the config file.

## What it is and where it runs

tmux runs a background server that owns your sessions; the `tmux` client attaches to it. It is available on Linux and macOS through the standard package managers and is a common pick on servers where screen sessions must outlive a login. The server communicates with clients over a Unix domain socket, by default under a per-user directory such as `/tmp/tmux-<uid>/`.

Almost every tmux keystroke starts with the prefix key, `Ctrl-b` by default. You press the prefix, release it, then press the command key. Throughout this page `prefix` means that key sequence. Many users remap the prefix to `Ctrl-a` in their config.

## Core commands

### Sessions

A session is a collection of windows. Manage sessions from the shell.

```
tmux new -s work        start a named session
tmux ls                 list sessions
tmux attach -t work     attach to a session
tmux kill-session -t work   kill one session
tmux kill-server        stop the server and all sessions
```

| Key | Action |
| --- | --- |
| `prefix d` | Detach from the current session |
| `prefix s` | Interactive session list |
| `prefix $` | Rename the current session |

### Windows

A window fills the client and holds one or more panes, like a tab.

| Key | Action |
| --- | --- |
| `prefix c` | Create a new window |
| `prefix ,` | Rename the current window |
| `prefix n` / `prefix p` | Next / previous window |
| `prefix 0`..`9` | Jump to window by number |
| `prefix w` | Interactive window list |
| `prefix &` | Kill the current window |

### Panes

Panes split a window into regions.

```
prefix %     split into left and right panes
prefix "     split into top and bottom panes
```

| Key | Action |
| --- | --- |
| `prefix o` | Cycle to the next pane |
| `prefix` then arrow | Move to the pane in that direction |
| `prefix z` | Zoom the current pane to full window (toggle) |
| `prefix {` / `prefix }` | Swap pane left / right |
| `prefix x` | Kill the current pane |
| `prefix Space` | Cycle through pane layouts |

Resize by holding the prefix and pressing arrow keys, or with `prefix :resize-pane -D 5` to grow downward by five cells.

### Copy mode and scrollback

Enter copy mode with `prefix [` to scroll back through output and select text. Leave it with `q`. With default emacs-style keys, move with the arrow keys or `Ctrl-Space` to start a selection and `Alt-w` to copy. With vi-style keys (`setw -g mode-keys vi`), press `Space` to start a selection, movement keys to extend, and `Enter` to copy. Paste the most recent buffer with `prefix ]`. List buffers with `prefix :list-buffers`.

### Detach, reattach, and scripting

`prefix d` detaches and leaves everything running. `tmux attach` brings it back. For automation, `send-keys` injects keystrokes into a target pane without attaching.

```
tmux new -d -s build                        start detached
tmux send-keys -t build 'make all' Enter    run a command in it
tmux new-window -t build -n logs            add a window
tmux split-window -t build -h               split a pane
```

`tmux` reads commands from a file with `tmux source-file script.conf`, which is a common way to lay out a project workspace.

### The config file

tmux reads `~/.tmux.conf` at server start. Common entries:

```
set -g prefix C-a            remap prefix to Ctrl-a
set -g mouse on              enable mouse selection and resizing
setw -g mode-keys vi         vi keys in copy mode
set -g history-limit 10000   larger scrollback buffer
```

Reload a changed config without restarting with `prefix :source-file ~/.tmux.conf`.

## Common workflows

### Run a long job that survives disconnect

Start a detached session, launch the job, then leave.

```
tmux new -s backup
./nightly-backup.sh
prefix d
```

Reconnect later from any terminal with `tmux attach -t backup`.

### Lay out a development workspace

Open an editor beside a shell and a log tail.

```
tmux new -s dev
prefix %            split left and right
vim .               editor on the left
prefix o            move to the right pane
tail -f app.log     logs on the right
```

### Script a repeatable session

Build the layout from a file so every start is identical.

```
tmux new -d -s api
tmux send-keys -t api 'cd ~/api && ./run.sh' Enter
tmux split-window -t api -v
tmux send-keys -t api 'cd ~/api && npm test -- --watch' Enter
tmux attach -t api
```

## Flags and options worth knowing

| Flag | Effect |
| --- | --- |
| `tmux new -s name` | Name a new session |
| `tmux new -d` | Start detached (no attach) |
| `tmux attach -d -t name` | Attach and detach other clients |
| `tmux attach -r -t name` | Attach read-only |
| `tmux ls` | List sessions |
| `tmux -S /path/sock` | Use an explicit socket path |
| `tmux send-keys -t target` | Send keys to a named target |
| `tmux kill-session -t name` | Terminate one session |

## Security notes

tmux controls access to a session through the permissions on its socket file. The default per-user socket directory restricts access to its owner, so protect it: never loosen those permissions, and do not place a socket in a world-writable location with `-S`. A socket another user can write to lets that user drive your terminal, a case of CWE-732 (incorrect permission assignment for a critical resource).

Sharing a session by pointing two clients at one socket means both users see and type into the same panes. Attaching to another user's session, or inviting someone into yours, grants full control of whatever runs there. Do this only with explicit agreement, and never hand out access to a session running as root or holding privileged credentials.

A detached session keeps its scrollback, environment variables, and any running shell alive in memory. Secrets typed into a pane, or exported into its environment, remain readable to anyone who later attaches. Clear sensitive scrollback with `prefix :clear-history`, avoid putting credentials in environment variables inside shared sessions, and kill sessions you no longer need rather than leaving them attached. See `/SECURE_CODING_REFERENCE.md` for secret-handling practices.

## Resources

- The `tmux` man page, `man tmux`
- The tmux project wiki and FAQ
- "tmux 2: Productive Mouse-Free Development" by Brian P. Hogan

## Related pages

- `/commands/README.md`
- `/SECURE_CODING_REFERENCE.md`
- `/commands/vim.md`
- `/commands/ssh.md`
- `/commands/linux-commands.md`
