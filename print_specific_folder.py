import os

# Set of folders to include (folder names, not full paths)
include_folders = {"Comments", "Department", "Grievances", "Users"}

def print_tree(start_path, prefix=""):
    try:
        items = os.listdir(start_path)
        items.sort()
    except:
        return  # skip inaccessible folders/files

    items = [item for item in items if not item.startswith('.')]  # optional: ignore hidden files

    for index, item in enumerate(items):
        path = os.path.join(start_path, item)
        is_last = (index == len(items) - 1)
        connector = "└── " if is_last else "├── "
        print(prefix + connector + item)

        if os.path.isdir(path):
            folder_name = os.path.basename(path)
            if folder_name in include_folders or prefix == "":  # always print root
                extension = "    " if is_last else "│   "
                print_tree(path, prefix + extension)

# Replace this with your root folder
root_dir = ("D:\pycharm\Grievance_cell")

print(os.path.basename(root_dir) + "/")
print_tree(root_dir)
