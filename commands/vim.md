# Vim Command Reference

Vim is a modal text editor found on nearly every Unix-like system. Its modes separate movement, text entry, and commands, so most keystrokes are editing operations rather than literal characters. This page covers the motions, edits, and file commands that cover daily work. Learn the modes first; everything else builds on them.

## What it is and where it runs

Vim (Vi IMproved) is an extended clone of the classic `vi` editor. It ships by default on most Linux distributions and macOS, and runs in any terminal over SSH, which makes it a reliable editor on remote servers. Invoke it as `vim file`, or `vi file` where `vi` is symlinked to Vim. Configuration lives in `~/.vimrc` and runtime files under `~/.vim/`.

Vim has four core modes:

| Mode | Enter from normal | Purpose |
| --- | --- | --- |
| Normal | `Esc` | Move and run operators (default mode) |
| Insert | `i`, `a`, `o` | Type text |
| Visual | `v`, `V`, `Ctrl-v` | Select text |
| Command-line | `:`, `/`, `?` | Ex commands and search |

Press `Esc` to return to normal mode from anywhere. When unsure which mode you are in, press `Esc` twice.

## Core commands

### Motion within a line

Move the cursor without leaving normal mode.

```
h  left      l  right
0  first column    $  end of line
^  first non-blank    g_ last non-blank
```

| Key | Action |
| --- | --- |
| `w` | Forward to start of next word |
| `b` | Back to start of previous word |
| `e` | Forward to end of word |
| `f{char}` | Jump to next `{char}` on the line |
| `t{char}` | Jump to just before next `{char}` |
| `;` / `,` | Repeat / reverse the last `f` or `t` |

### Motion across the file

```
j  down       k  up
gg top of file    G  bottom of file
{  previous paragraph    }  next paragraph
Ctrl-f one page down    Ctrl-b one page up
```

Prefix a line number before `G` to jump there, so `42G` goes to line 42. `:42` does the same from command-line mode.

### Entering insert mode

| Key | Action |
| --- | --- |
| `i` | Insert before cursor |
| `a` | Append after cursor |
| `o` | Open a new line below |
| `O` | Open a new line above |
| `A` | Append at end of line |
| `I` | Insert at first non-blank |

### Editing and operators

```
x    delete character under cursor
dd   delete (cut) current line
yy   yank (copy) current line
p    paste after cursor    P  paste before
cw   change word (delete + insert)
r{char}  replace one character
```

Operators combine with motions. `d$` deletes to end of line, `y}` yanks to the next paragraph, `c2w` changes two words. `u` undoes; `Ctrl-r` redoes. The `.` command repeats the last change, which pairs well with `cw` and `f` for fast repeated edits.

### Search and replace

```
/pattern   search forward
?pattern   search backward
n          next match     N  previous match
*          search word under cursor
```

Substitute with the `:s` command. `:%s/old/new/g` replaces every `old` with `new` across the whole file. Add `c` for confirm-each: `:%s/old/new/gc`. Restrict to a range with line numbers, so `:10,20s/old/new/g` touches lines 10 to 20 only.

### Files, buffers, windows, tabs

| Command | Action |
| --- | --- |
| `:w` | Write (save) the file |
| `:w file` | Write to a named file |
| `:q` | Quit |
| `:q!` | Quit, discarding changes |
| `:wq` or `:x` | Write and quit |
| `:e file` | Edit another file |
| `:bn` / `:bp` | Next / previous buffer |
| `:ls` | List open buffers |
| `:sp` / `:vsp` | Horizontal / vertical split |
| `Ctrl-w w` | Cycle between windows |
| `:tabnew` | Open a new tab |
| `gt` / `gT` | Next / previous tab |

### Registers and marks

Yanked and deleted text goes into registers. Prefix an operation with `"a` to use register `a`, so `"ayy` yanks the line into register `a` and `"ap` pastes it. The `"+` register is the system clipboard when Vim is built with clipboard support. View registers with `:registers`.

Marks save positions. `ma` sets mark `a`; `` `a `` jumps to its exact column and `'a` jumps to its line. The `` `` `` mark returns to the position before the last jump.

## Common workflows

### Edit, save, and keep working

Open a file, change a word, save without quitting, then continue.

```
vim config.yaml
/timeout        search for the word
cw 30<Esc>      change the word to 30
:w              save
```

### Replace a string across a file with confirmation

Rename a variable everywhere, reviewing each hit.

```
:%s/old_name/new_name/gc
```

Press `y` to change a match, `n` to skip, `a` to change all remaining, `q` to stop.

### Reindent a block using visual mode

Select lines, shift them right, and save.

```
V               start line-visual mode
5j              extend down five lines
>               indent the selection
:w
```

### Move text between two files

Yank in one buffer, paste in another.

```
:e source.txt
yy              yank a line
:e dest.txt
p               paste it
```

## Flags and options worth knowing

| Flag or option | Effect |
| --- | --- |
| `vim -R file` | Read-only mode |
| `vim -d a b` | Diff mode comparing two files |
| `vim +42 file` | Open at line 42 |
| `vim -u NONE` | Start with no vimrc (clean session) |
| `:set number` | Show line numbers |
| `:set hlsearch` | Highlight search matches |
| `:set paste` | Disable auto-indent for pasting |
| `:syntax on` | Enable syntax highlighting |

## Security notes

Modelines are per-file settings Vim reads from the first or last lines of a document, such as `vim: set sw=4:`. A malicious file can abuse modeline parsing to trigger unintended behavior, a class of issue tracked under CWE-94 (improper control of code generation). Disable them with `set nomodeline` in `~/.vimrc`, or keep Vim current since modeline handling has been hardened over time. Treat files from untrusted sources with care.

Editing root-owned files by running Vim as root loads that user's `~/.vimrc` and plugins, which widens the attack surface. Prefer `sudoedit file` (also reachable as `sudo -e`). It copies the file to a temporary path, opens it as your own user with your own config, and writes it back with the original ownership, so no privileged editor session runs your plugins. See `/SECURE_CODING_REFERENCE.md` for least-privilege guidance.

Swap files (`.file.swp`) and the undo history hold the content you edit, including secrets, and persist if Vim crashes. On shared or multi-user hosts this can leak data under CWE-532 (insertion of sensitive information into a log or temp file). Point swap and undo directories at a private location with `set directory=` and `set undodir=`, or disable them with `set noswapfile` when editing sensitive material, and remove stray `.swp` files afterward.

## Resources

- `vimtutor`, the interactive tutorial bundled with Vim
- The in-editor help system, reached with `:help` and `:help {topic}`
- The Vim user manual, `:help usr_toc`
- "Practical Vim" by Drew Neil

## Related pages

- `/commands/README.md`
- `/SECURE_CODING_REFERENCE.md`
- `/commands/tmux.md`
- `/commands/linux-commands.md`
- `/commands/ssh.md`
