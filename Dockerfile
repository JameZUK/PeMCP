# --- Base Image ---
# Switch to the full 'bullseye' image for better system library compatibility.
# This is a more robust base than 'slim' for packages with C dependencies like oscrypto.
FROM python:3.11-bullseye

# --- Set Working Directory ---
# Set the working directory inside the container to /app.
# This is where we'll copy the script and where it will run from.
WORKDIR /app

# --- Install System Dependencies ---
# Even with the full image, it's good practice to ensure these are present.
# Some Python packages (like yara-python) need to be compiled from source,
# which requires system-level build tools. oscrypto requires libssl-dev.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    && ldconfig \
    && rm -rf /var/lib/apt/lists/*

# --- Install Python Dependencies ---
# Install all the required Python libraries using pip.
# The script dynamically checks for these, but it's best practice to
# install them explicitly in the Docker image.
# We use a single RUN command to create a more efficient image layer.
# The --no-cache-dir flag reduces the image size.
RUN pip install --no-cache-dir \
    # Core dependencies
    pefile \
    requests \
    # Digital signature and crypto
    cryptography \
    signify \
    # Analysis toolkits
    yara-python \
    flare-capa \
    flare-floss \
    stringsifter \
    vivisect \
    # MCP server functionality
    "mcp[cli]" \
    # Utilities
    "thefuzz[speedup]"

# --- Copy Script ---
# Copy your Python script from the build context into the working directory of the container.
COPY PeMCP.py .

# --- Expose Port ---
# Document that the container listens on port 8082 for the MCP server.
# This does NOT publish the port. You still need to use the -p flag on `docker run`.
EXPOSE 8082

# --- Set Entrypoint ---
# Define the command that will run when the container starts.
# Using the "exec" form of ENTRYPOINT allows you to pass command-line arguments
# to your script when you run the container.
# For example: docker run my-pemcp-analyzer --input-file some_file.exe --verbose
ENTRYPOINT ["python", "./PeMCP.py"]
