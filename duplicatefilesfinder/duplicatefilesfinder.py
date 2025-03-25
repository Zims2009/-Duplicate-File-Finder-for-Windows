import os
import hashlib
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, font
from collections import defaultdict
import webbrowser

def get_file_hash(file_path, hash_algo=hashlib.md5):
    """Calculate hash of a file using the specified hash algorithm (default: MD5)."""
    hash_func = hash_algo()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except (OSError, PermissionError):
        return None

def get_file_size(file_path):
    """Get file size in human-readable format."""
    try:
        size = os.path.getsize(file_path)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
    except (OSError, PermissionError):
        return "Unknown"

def find_duplicate_files(directory):
    """Find duplicate files in the given directory."""
    hash_map = defaultdict(list)
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            status_text.delete(1.0, tk.END)
            status_text.insert(tk.END, f"Scanning: {file_path}\n")
            file_hash = get_file_hash(file_path)
            if file_hash:
                hash_map[file_hash].append(file_path)
    
    duplicates = {h: paths for h, paths in hash_map.items() if len(paths) > 1}
    return duplicates

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

def scan_duplicates_thread():
    global duplicate_files
    directory = entry_path.get().strip()
    if not os.path.exists(directory):
        messagebox.showerror("Error", "Invalid directory. Please select a valid folder.")
        return
    
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "Scanning for duplicates...\n")
    
    duplicate_files = find_duplicate_files(directory)
    display_results()
    
    status_text.delete(1.0, tk.END)
    status_text.insert(tk.END, "Scan Complete\n")

def display_results(sort_by_size=False, ascending=True):
    result_text.delete(1.0, tk.END)
    if duplicate_files:
        sorted_duplicates = sorted(duplicate_files.items(), key=lambda x: os.path.getsize(x[1][0]) if os.path.exists(x[1][0]) else 0, reverse=not ascending) if sort_by_size else duplicate_files.items()
        result_text.insert(tk.END, "Duplicate files found:\n\n")
        for file_hash, paths in sorted_duplicates:
            file_size = get_file_size(paths[0])
            result_text.insert(tk.END, f"Hash: {file_hash} - {file_size}\n")
            for path in paths:
                result_text.insert(tk.END, f"  {path}\n", "clickable")
            result_text.insert(tk.END, "-" * 40 + "\n")
    else:
        result_text.insert(tk.END, "No duplicate files found.\n")

def toggle_sort():
    global sort_ascending
    sort_ascending = not sort_ascending
    display_results(sort_by_size=True, ascending=sort_ascending)

# GUI Setup
root = tk.Tk()
root.title("Duplicate File Checker")
root.geometry("600x500")

tk.Label(root, text="Select Folder:").pack(pady=5)
frame = tk.Frame(root)
frame.pack(pady=5)

entry_path = tk.Entry(frame, width=50)
entry_path.pack(side=tk.LEFT, padx=5)

btn_browse = tk.Button(frame, text="Browse", command=browse_folder)
btn_browse.pack(side=tk.LEFT)

btn_scan = tk.Button(root, text="Scan for Duplicates", command=scan_duplicates)
btn_scan.pack(pady=10)

tk.Label(root, text="Scanning Status:").pack(pady=5)
status_text = scrolledtext.ScrolledText(root, width=70, height=2)
status_text.pack(pady=5)

btn_sort = tk.Button(root, text="Sort by Size", command=toggle_sort)
btn_sort.pack(pady=5)

result_text = scrolledtext.ScrolledText(root, width=70, height=15)
result_text.pack(pady=5, fill=tk.BOTH, expand=True)
result_text.bind("<Button-1>", open_folder)
result_text.bind("<Motion>", highlight_clickable)
result_text.bind("<Leave>", remove_highlight)

result_text.tag_config("clickable", foreground="blue", underline=True)
result_text.tag_config("highlight", background="lightgray")

sort_ascending = True

root.mainloop()
