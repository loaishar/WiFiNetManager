import os

# Output file
OUTPUT_FILE = "replit_repo_structure_and_content.txt"

# Folders and files to include (based on your screenshot)
INCLUDED_ITEMS = {
    "app.py", "extensions.py", "generate_structure.py", "generated-icon.png",
    "main.py", "models.py", "network_scanner.py", "routes.py", "static",
    "templates"
}


# Function to write repo structure and file contents
def write_repo_structure():
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("Replit Repository Structure and File Contents:\n")
        f.write("=" * 50 + "\n\n")

        # Walk through the directory tree
        for root, dirs, files in os.walk("."):
            # Remove the .git directory from the walk
            dirs[:] = [d for d in dirs if d != ".git"]
            # Only include folders and files that match the specified items or subdirectories like 'css' and 'js'
            dirs[:] = [
                d for d in dirs if d in INCLUDED_ITEMS or d in {"css", "js"}
            ]  # Include css, js subdirectories
            files = [
                file for file in files
                if file.endswith(('.py', '.html', '.css', '.js',
                                  '.png')) and file != "list_users.py"
            ]  # Exclude list_users.py

            # Write the current directory if it's in the included items
            if os.path.basename(root) in INCLUDED_ITEMS or root == ".":
                f.write(f"Directory: {root}/\n")
                f.write("-" * 50 + "\n")

            # Write each file in the current directory
            for file in files:
                file_path = os.path.join(root, file)
                f.write(f"File: {file_path}\n")
                f.write("-" * 50 + "\n")

                try:
                    # Read the contents of the file
                    with open(file_path, "r",
                              encoding="utf-8") as content_file:
                        content = content_file.read()
                        f.write(f"Contents of {file_path}:\n")
                        f.write(content + "\n")
                except Exception as e:
                    f.write(f"Could not read file: {file_path}. Error: {e}\n")

                f.write("-" * 50 + "\n\n")


# Execute the function to document the current repo
if __name__ == "__main__":
    write_repo_structure()
    print(
        f"Repository structure and content have been written to {OUTPUT_FILE}")
