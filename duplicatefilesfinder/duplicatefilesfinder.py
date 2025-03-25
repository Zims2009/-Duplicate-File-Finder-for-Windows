import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, font
import threading
from collections import defaultdict
import webbrowser


sort_ascending = True  # Global variable to track sorting order

def format_size(size):
    """Convert size in bytes to a human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"

def get_file_hash(file_path):
    """Compute SHA256 hash of a file."""
    try:
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None

def find_duplicate_files(directory):
    """Find duplicate files in the directory, storing sizes and paths."""
    hash_map = {}  # {hash: [(size, path), (size, path)]}
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = get_file_hash(file_path)
            if file_hash:
                file_size = os.path.getsize(file_path)
                if file_hash not in hash_map:
                    hash_map[file_hash] = []
                hash_map[file_hash].append((file_size, file_path))
    
    # Keep only duplicates
    return {h: sorted(paths, reverse=True) for h, paths in hash_map.items() if len(paths) > 1}

def display_results(duplicate_files):
    """Display the duplicate files sorted by size."""
    global sort_ascending

    result_text.delete(1.0, tk.END)

    if duplicate_files:
        result_text.insert(tk.END, "Duplicate files found (sorted by size):\n\n")

        # Sort hashes by total file size
        sorted_duplicates = sorted(
            duplicate_files.items(), 
            key=lambda item: item[1][0][0],  # Sort by first file's size
            reverse=not sort_ascending
        )

        for file_hash, files in sorted_duplicates:
            file_size = format_size(files[0][0])  # Use first file's size
            result_text.insert(tk.END, f"Hash: {file_hash} - {file_size}\n")
            for size, file_path in files:
                result_text.insert(tk.END, f"   {file_path}\n", "clickable")
            result_text.insert(tk.END, "-" * 40 + "\n")
    else:
        result_text.insert(tk.END, "No duplicate files found.\n")

def scan_duplicates_thread():
    """Scan for duplicate files and display results."""
    directory = entry_path.get().strip()
    if not os.path.exists(directory):
        messagebox.showerror("Error", "Invalid directory. Please select a valid folder.")
        return

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "Scanning for duplicates...\n")

    global duplicate_files
    duplicate_files = find_duplicate_files(directory)  # Store results globally

    display_results(duplicate_files)

    status_text.delete(1.0, tk.END)
    status_text.insert(tk.END, "Scan Complete\n")

def toggle_sorting():
    """Toggle sorting order and refresh results."""
    global sort_ascending
    sort_ascending = not sort_ascending  # Flip sorting order
    display_results(duplicate_files)
    
def browse_folder():
    folder_selected = filedialog.askdirectory()
    if folder_selected:
        entry_path.delete(0, tk.END)
        entry_path.insert(0, folder_selected)

def scan_duplicates():
    threading.Thread(target=scan_duplicates_thread, daemon=True).start()

def open_folder(event):
    """Open folder containing the selected file."""
    index = result_text.index(tk.CURRENT)
    line = result_text.get(index + " linestart", index + " lineend").strip()
    if os.path.isfile(line):
        folder = os.path.dirname(line)
        webbrowser.open(folder)

def highlight_clickable(event):
    """Change the cursor and background when hovering over clickable text."""
    index = result_text.index(tk.CURRENT)
    line = result_text.get(index + " linestart", index + " lineend").strip()
    if os.path.isfile(line):
        result_text.config(cursor="hand2")
        result_text.tag_add("highlight", index + " linestart", index + " lineend")
    else:
        result_text.config(cursor="")
        result_text.tag_remove("highlight", "1.0", tk.END)

def remove_highlight(event):
    """Remove highlight effect when mouse leaves the clickable area."""
    result_text.config(cursor="")
    result_text.tag_remove("highlight", "1.0", tk.END)

# GUI Setup
root = tk.Tk()
root.title("Duplicate File Finder")

frame = tk.Frame(root)
frame.pack(pady=10)

entry_path = tk.Entry(frame, width=50)
entry_path.pack(side=tk.LEFT, padx=5)
tk.Button(frame, text="Browse", command=browse_folder).pack(side=tk.LEFT)

tk.Button(root, text="Scan Duplicates", command=scan_duplicates_thread).pack(pady=5)

status_text = tk.Text(root, height=2, width=80)
status_text.pack(pady=5)

tk.Button(root, text="Sort by Size", command=toggle_sorting).pack(pady=5)  # Sorting button

result_text = scrolledtext.ScrolledText(root, height=10)
result_text.pack(pady=5, fill=tk.BOTH, expand=True)
result_text.bind("<Button-1>", open_folder)
result_text.bind("<Motion>", highlight_clickable)
result_text.bind("<Leave>", remove_highlight)

result_text.tag_config("clickable", foreground="blue", underline=True)
result_text.tag_config("highlight", background="lightgray")


root.mainloop()
