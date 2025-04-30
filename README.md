# Kind Kubernetes MCP Server

This MCP server provides tools for interacting with a local Kind Kubernetes cluster. It allows you to list pods, services, and get cluster information through the Model Context Protocol.

## Prerequisites

- Python 3.8+
- Kind Kubernetes cluster running locally: https://kind.sigs.k8s.io/docs/user/quick-start/
- `kubectl` configured to access your cluster
- pip package manager

## Creating a Kind Cluster

1. Install Kind if you haven't already:
```bash
# On macOS with Homebrew
brew install kind

# On Linux/Windows with Go
go install sigs.k8s.io/kind@latest
```

2. Create a new cluster named "test-mcp":
```bash
kind create cluster --name test-mcp
```

3. Verify the cluster is running:
```bash
kubectl cluster-info --context kind-test-mcp
```

4. You should see output similar to:
```
Kubernetes control plane is running at https://127.0.0.1:xxxxx
CoreDNS is running at https://127.0.0.1:xxxxx/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy
```

Now your Kind cluster is ready to use with this MCP server.

## Installation

1. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

This will install:
- `mcp[cli]` - The Model Context Protocol CLI with inspector tools
- `kubernetes` - The official Kubernetes Python client
- Additional dependencies for the MCP server

The MCP Inspector is included with the `mcp[cli]` package and will be available automatically.

## Usage

There are two ways to use this MCP server:

### 1. Using MCP Inspector (Development Mode)

The MCP Inspector provides a web interface for testing your tools:

1. Start the server in development mode:
```bash
mcp dev kind_server.py
```

2. Open the URL shown in the console (look for the output text: MCP Inspector is up and running at http://127.0.0.1:6274 🚀)
3. Use the web interface to:
   - View available tools
   - Test tools with different parameters
   - See the formatted output

### 2. Using Cursor IDE

To use the MCP server in Cursor:

1. Create an `mcp.json` file in your project (.cursor/mcp.json) or in the global Cursor path (https://docs.cursor.com/context/model-context-protocol):
```json
{
  "mcpServers": {
    "kind-k8s-mcp": {
      "command": "/path/to/your/venv/bin/python",
      "args": ["/path/to/your/kind_server.py"],
    }
  }
}
```

2. Cursor will automatically detect and use the MCP server
3. The tools will be available in your AI interactions

## Available Tools

The server provides the following tools:

1. `list_pods(namespace="default")`: Lists all pods in the specified namespace
   - Shows pod name, status, ready containers, and IP address
   - Default namespace is "default" if not specified

2. `list_services(namespace="default")`: Lists all services in the specified namespace
   - Shows service name, type, cluster IP, and port mappings
   - Default namespace is "default" if not specified

3. `get_cluster_info()`: Gets basic information about the Kubernetes cluster
   - Shows Kubernetes version, build date, platform
   - Lists all nodes with their status and version

## Error Handling

The server includes robust error handling for common scenarios:
- Invalid namespace names
- Cluster connectivity issues
- Authentication/authorization errors

All errors are logged with timestamps and returned as formatted strings with descriptive messages. Example error log:
```
2024-XX-XX XX:XX:XX,XXX - ERROR - Error loading kubeconfig: config file not found
```

## Development

When developing or testing new features, use the MCP Inspector (`mcp dev`) for real-time feedback and easy tool testing. The web interface makes it simple to:
- Validate tool inputs
- Check formatted outputs
- Debug issues
- Test different scenarios

### Monitoring Server Status

The server provides continuous status updates through logging:
1. **Startup Phase**:
   - Kubernetes configuration loading
   - Cluster connection verification
   - Available tools listing

2. **Runtime Phase**:
   - Tool invocations and parameters
   - Operation results and item counts
   - Error conditions and stack traces

3. **Error Handling**:
   - Detailed error messages
   - Connection issues
   - Authentication problems
   - Invalid parameter errors 