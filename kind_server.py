from kubernetes import client, config
from mcp.server.fastmcp import FastMCP
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Initialize the MCP server
mcp = FastMCP("Kind Kubernetes Tools")

logger.info("Starting Kind Kubernetes Tools MCP server...")

# Load Kubernetes configuration
try:
    config.load_kube_config()
    logger.info("Successfully loaded Kubernetes configuration")
except Exception as e:
    logger.error(f"Error loading kubeconfig: {e}")
    sys.exit(1)

# Create Kubernetes API client
try:
    v1 = client.CoreV1Api()
    version_api = client.VersionApi()
    version_info = version_api.get_code()
    logger.info(f"Connected to Kubernetes cluster version {version_info.git_version}")
    
    # Log available tools
    logger.info("Available tools:")
    logger.info("  - list_pods(namespace='default')")
    logger.info("  - list_services(namespace='default')")
    logger.info("  - get_cluster_info()")
except Exception as e:
    logger.error(f"Error connecting to Kubernetes API: {e}")
    sys.exit(1)

@mcp.tool()
def list_pods(namespace: str = "default") -> str:
    """List all pods in the specified namespace.
    
    Args:
        namespace: The Kubernetes namespace to list pods from (default: "default")
    
    Returns:
        A formatted string containing pod information
    """
    logger.info(f"Listing pods in namespace: {namespace}")
    try:
        pods = v1.list_namespaced_pod(namespace)
        pod_info = []
        for pod in pods.items:
            status = pod.status.phase
            ready_containers = sum(1 for c in pod.status.container_statuses if c.ready) if pod.status.container_statuses else 0
            total_containers = len(pod.spec.containers)
            pod_info.append(f"Pod: {pod.metadata.name}")
            pod_info.append(f"  Status: {status}")
            pod_info.append(f"  Ready: {ready_containers}/{total_containers}")
            pod_info.append(f"  IP: {pod.status.pod_ip or 'N/A'}")
            pod_info.append("")
        
        result = "\n".join(pod_info) if pod_info else "No pods found in namespace"
        logger.info(f"Found {len(pods.items)} pods in namespace {namespace}")
        return result
    except Exception as e:
        error_msg = f"Error listing pods: {str(e)}"
        logger.error(error_msg)
        return error_msg

@mcp.tool()
def list_services(namespace: str = "default") -> str:
    """List all services in the specified namespace.
    
    Args:
        namespace: The Kubernetes namespace to list services from (default: "default")
    
    Returns:
        A formatted string containing service information
    """
    logger.info(f"Listing services in namespace: {namespace}")
    try:
        services = v1.list_namespaced_service(namespace)
        svc_info = []
        for svc in services.items:
            svc_info.append(f"Service: {svc.metadata.name}")
            svc_info.append(f"  Type: {svc.spec.type}")
            if svc.spec.cluster_ip:
                svc_info.append(f"  Cluster IP: {svc.spec.cluster_ip}")
            if svc.spec.ports:
                ports = [f"{port.port}:{port.target_port}/{port.protocol}" for port in svc.spec.ports]
                svc_info.append(f"  Ports: {', '.join(ports)}")
            svc_info.append("")
        
        result = "\n".join(svc_info) if svc_info else "No services found in namespace"
        logger.info(f"Found {len(services.items)} services in namespace {namespace}")
        return result
    except Exception as e:
        error_msg = f"Error listing services: {str(e)}"
        logger.error(error_msg)
        return error_msg

@mcp.tool()
def get_cluster_info() -> str:
    """Get basic information about the Kubernetes cluster.
    
    Returns:
        A string containing cluster information
    """
    logger.info("Getting cluster information")
    try:
        version = version_api.get_code()
        nodes = v1.list_node()
        
        info = [
            f"Kubernetes Version: {version.git_version}",
            f"Build Date: {version.build_date}",
            f"Platform: {version.platform}",
            "",
            "Nodes:",
        ]
        
        for node in nodes.items:
            ready_status = next((c.status for c in node.status.conditions if c.type == "Ready"), "Unknown")
            info.extend([
                f"  Name: {node.metadata.name}",
                f"  Status: {ready_status}",
                f"  Kubelet Version: {node.status.node_info.kubelet_version}",
                ""
            ])
        
        result = "\n".join(info)
        logger.info(f"Found {len(nodes.items)} nodes in the cluster")
        return result
    except Exception as e:
        error_msg = f"Error getting cluster info: {str(e)}"
        logger.error(error_msg)
        return error_msg

if __name__ == "__main__":
    mcp.run() 