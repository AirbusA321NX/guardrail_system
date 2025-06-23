import os

def print_tree(start_path, prefix=""):
    items = os.listdir(start_path)
    items.sort()
    for index, item in enumerate(items):
        path = os.path.join(start_path, item)
        is_last = (index == len(items) - 1)
        connector = "└── " if is_last else "├── "
        print(prefix + connector + item)
        if os.path.isdir(path):
            extension = "    " if is_last else "│   "
            print_tree(path, prefix + extension)

# Replace this path with your folder path
root_dir = "D:\pycharm\Grievance_cell"

print(os.path.basename(root_dir) + "/")
print_tree(root_dir)
