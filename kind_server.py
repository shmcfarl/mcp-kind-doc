"""
Kind Kubernetes MCP Server

A Model Context Protocol (MCP) server that provides Kubernetes cluster management
capabilities through a set of tools for listing and inspecting various Kubernetes
resources including pods, services, deployments, configmaps, secrets, and namespaces.

Features:
- Input validation for all parameters
- Enhanced error handling with specific exception types
- Configuration management via environment variables
- Support for label selectors and filtering
- Comprehensive logging and monitoring
- Multiple Kubernetes resource types support

Environment Variables:
- KUBECONFIG: Path to kubeconfig file (optional)
- LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- KUBE_CONTEXT: Kubernetes context to use (optional)

Author: Shannon McFarland
Version: 2.0.0
"""

from kubernetes import client, config
from mcp.server.fastmcp import FastMCP
import logging
import sys
import os
import re
from typing import Optional, List, Dict, Any

# =============================================================================
# CONFIGURATION MANAGEMENT
# =============================================================================

class Config:
    """
    Configuration management class for the MCP server.
    
    Handles environment variable configuration and provides centralized
    access to server settings including logging levels and Kubernetes
    connection parameters.
    """
    
    def __init__(self):
        """Initialize configuration from environment variables."""
        self.kubeconfig_path = os.getenv('KUBECONFIG')
        self.log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
        self.kube_context = os.getenv('KUBE_CONTEXT')
        
    def get_log_level(self) -> int:
        """
        Get the logging level as an integer constant.
        
        Returns:
            int: Logging level constant (e.g., logging.DEBUG, logging.INFO)
        """
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        return level_map.get(self.log_level, logging.INFO)

# =============================================================================
# INPUT VALIDATION
# =============================================================================

class InputValidator:
    """
    Input validation utilities for Kubernetes resource parameters.
    
    Provides validation methods for namespace names and label selectors
    according to Kubernetes naming conventions and best practices.
    """
    
    @staticmethod
    def validate_namespace(namespace: str) -> tuple[bool, str]:
        """
        Validate namespace name according to Kubernetes naming conventions.
        
        Kubernetes namespace naming rules:
        - Must be a non-empty string
        - Maximum 63 characters
        - Must be lowercase alphanumeric with hyphens
        - Cannot start or end with hyphen
        - Cannot contain consecutive hyphens
        - Special case: "*" is allowed for wildcard (all namespaces)
        
        Args:
            namespace (str): The namespace name to validate
            
        Returns:
            tuple[bool, str]: (is_valid, error_message)
                - is_valid: True if namespace is valid, False otherwise
                - error_message: Empty string if valid, error description if invalid
        """
        if not namespace or not isinstance(namespace, str):
            return False, "Namespace must be a non-empty string"
        
        # Allow wildcard for all namespaces
        if namespace == "*":
            return True, ""
        
        # Check length limit (Kubernetes DNS subdomain limit)
        if len(namespace) > 63:
            return False, "Namespace name must be 63 characters or less"
        
        # Check format: lowercase alphanumeric with hyphens, no consecutive hyphens
        if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$', namespace):
            return False, "Namespace name must be lowercase alphanumeric with hyphens"
        
        return True, ""
    
    @staticmethod
    def validate_label_selector(selector: str) -> tuple[bool, str]:
        """
        Validate label selector format.
        
        Performs basic validation on label selector strings to ensure
        they meet Kubernetes requirements for label selection.
        
        Args:
            selector (str): The label selector string to validate
            
        Returns:
            tuple[bool, str]: (is_valid, error_message)
                - is_valid: True if selector is valid, False otherwise
                - error_message: Empty string if valid, error description if invalid
        """
        if not selector or not isinstance(selector, str):
            return False, "Label selector must be a non-empty string"
        
        # Check length limit (reasonable limit for label selectors)
        if len(selector) > 1000:
            return False, "Label selector must be 1000 characters or less"
        
        return True, ""

def get_all_namespaces(v1: client.CoreV1Api) -> List[str]:
    """
    Get a list of all namespace names in the cluster.
    
    Args:
        v1: Kubernetes CoreV1Api client
        
    Returns:
        List[str]: List of namespace names
    """
    try:
        namespaces = v1.list_namespace()
        return [ns.metadata.name for ns in namespaces.items]
    except Exception as e:
        logger.error(f"Error getting namespaces: {e}")
        return []

# =============================================================================
# ERROR HANDLING
# =============================================================================

class KubernetesError(Exception):
    """
    Base exception class for all Kubernetes-related errors.
    
    This serves as the parent class for all custom Kubernetes exceptions
    in the MCP server, allowing for specific error handling and logging.
    """
    pass

class NamespaceNotFoundError(KubernetesError):
    """
    Raised when a requested namespace does not exist.
    
    This exception is raised when attempting to access resources in a
    namespace that cannot be found in the cluster.
    """
    pass

class AccessDeniedError(KubernetesError):
    """
    Raised when access to a Kubernetes resource is denied.
    
    This typically occurs when the current user lacks the necessary
    RBAC permissions to perform the requested operation.
    """
    pass

class InvalidInputError(KubernetesError):
    """
    Raised when input validation fails.
    
    This exception is raised when user input does not meet the
    required format or validation criteria.
    """
    pass

def handle_kubernetes_exception(e: Exception, operation: str) -> str:
    """
    Handle Kubernetes API exceptions and return user-friendly error messages.
    
    Converts technical Kubernetes API exceptions into human-readable error
    messages that provide clear guidance on what went wrong and how to fix it.
    
    Args:
        e (Exception): The exception that was raised
        operation (str): Description of the operation that failed
        
    Returns:
        str: User-friendly error message with actionable guidance
    """
    if isinstance(e, client.ApiException):
        # Handle specific HTTP status codes with appropriate messages
        if e.status == 403:
            return f"Access denied: {operation} - check your RBAC permissions"
        elif e.status == 404:
            return f"Resource not found: {operation}"
        elif e.status == 422:
            return f"Invalid input: {operation} - {e.reason}"
        elif e.status == 500:
            return f"Kubernetes server error: {operation}"
        else:
            return f"Kubernetes API error ({e.status}): {operation} - {e.reason}"
    else:
        return f"Unexpected error during {operation}: {str(e)}"

# =============================================================================
# SERVER INITIALIZATION
# =============================================================================

# Initialize configuration from environment variables
config_obj = Config()

# Configure logging with structured format
logging.basicConfig(
    level=config_obj.get_log_level(),
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# Initialize the MCP server with descriptive name
mcp = FastMCP("Kind Kubernetes Tools")

logger.info("Starting Kind Kubernetes Tools MCP server...")

# Load Kubernetes configuration with error handling
try:
    # Load kubeconfig from specified path or default location
    if config_obj.kubeconfig_path:
        config.load_kube_config(config_file=config_obj.kubeconfig_path)
        logger.info(f"Loaded Kubernetes configuration from {config_obj.kubeconfig_path}")
    else:
        config.load_kube_config()
        logger.info("Loaded Kubernetes configuration from default location")
    
    # Switch to specified context if provided
    if config_obj.kube_context:
        config.load_kube_config(context=config_obj.kube_context)
        logger.info(f"Using Kubernetes context: {config_obj.kube_context}")
        
except Exception as e:
    logger.error(f"Error loading kubeconfig: {e}")
    sys.exit(1)

# Create Kubernetes API clients and verify connection
try:
    # Initialize core Kubernetes API clients
    v1 = client.CoreV1Api()  # For pods, services, configmaps, secrets, namespaces
    version_api = client.VersionApi()  # For cluster version information
    
    # Test connection by getting cluster version
    version_info = version_api.get_code()
    logger.info(f"Connected to Kubernetes cluster version {version_info.git_version}")
    
    # Log available MCP tools for debugging and documentation
    logger.info("Available MCP tools:")
    logger.info("  - list_pods(namespace='default', label_selector=None)")
    logger.info("  - list_services(namespace='default', label_selector=None)")
    logger.info("  - list_deployments(namespace='default', label_selector=None)")
    logger.info("  - list_configmaps(namespace='default', label_selector=None)")
    logger.info("  - list_secrets(namespace='default', label_selector=None)")
    logger.info("  - list_namespaces(label_selector=None)")
    logger.info("  - get_cluster_info()")
    
except Exception as e:
    logger.error(f"Error connecting to Kubernetes API: {e}")
    sys.exit(1)

# =============================================================================
# MCP TOOLS - KUBERNETES RESOURCE MANAGEMENT
# =============================================================================

@mcp.tool()
def list_pods(namespace: str = "default", label_selector: Optional[str] = None) -> str:
    """
    List all pods in the specified namespace with optional label filtering.
    
    This tool provides comprehensive information about pods including their status,
    readiness, IP addresses, node assignments, and labels. It supports filtering
    by label selectors to help users find specific pods.
    
    Args:
        namespace (str): The Kubernetes namespace to list pods from. 
                        Must follow Kubernetes naming conventions (default: "default").
                        Use "*" to list pods from all namespaces.
        label_selector (Optional[str]): Label selector to filter pods. 
                                      Format: "key=value" or "key in (value1,value2)"
                                      Example: "app=nginx" or "tier in (frontend,backend)"
    
    Returns:
        str: Formatted string containing detailed pod information including:
             - Pod name and status
             - Container readiness (ready/total)
             - Pod IP address and node assignment
             - Creation timestamp and labels
             - Error message if operation fails
    
    Raises:
        InvalidInputError: If namespace or label_selector validation fails
        AccessDeniedError: If user lacks permissions to list pods
        NamespaceNotFoundError: If the specified namespace doesn't exist
    """
    # Validate input parameters according to Kubernetes conventions
    is_valid, error_msg = InputValidator.validate_namespace(namespace)
    if not is_valid:
        logger.error(f"Invalid namespace: {error_msg}")
        return f"Error: {error_msg}"
    
    if label_selector:
        is_valid, error_msg = InputValidator.validate_label_selector(label_selector)
        if not is_valid:
            logger.error(f"Invalid label selector: {error_msg}")
            return f"Error: {error_msg}"
    
    # Log the operation for debugging and audit purposes
    logger.info(f"Listing pods in namespace: {namespace}" + (f" with selector: {label_selector}" if label_selector else ""))
    
    try:
        pod_info = []
        total_pods = 0
        
        # Handle wildcard namespace (all namespaces)
        if namespace == "*":
            # Get all namespaces and query each one
            all_namespaces = get_all_namespaces(v1)
            if not all_namespaces:
                return "Error: Could not retrieve namespace list"
            
            for ns in all_namespaces:
                pods = v1.list_namespaced_pod(ns, label_selector=label_selector)
                if pods.items:
                    pod_info.append(f"=== Namespace: {ns} ===")
                    for pod in pods.items:
                        status = pod.status.phase
                        ready_containers = sum(1 for c in pod.status.container_statuses if c.ready) if pod.status.container_statuses else 0
                        total_containers = len(pod.spec.containers)
                        
                        pod_info.append(f"Pod: {pod.metadata.name}")
                        pod_info.append(f"  Status: {status}")
                        pod_info.append(f"  Ready: {ready_containers}/{total_containers}")
                        pod_info.append(f"  IP: {pod.status.pod_ip or 'N/A'}")
                        pod_info.append(f"  Node: {pod.spec.node_name or 'N/A'}")
                        pod_info.append(f"  Age: {pod.metadata.creation_timestamp}")
                        
                        if pod.metadata.labels:
                            labels = [f"{k}={v}" for k, v in pod.metadata.labels.items()]
                            pod_info.append(f"  Labels: {', '.join(labels)}")
                        
                        pod_info.append("")
                    total_pods += len(pods.items)
        else:
            # Query specific namespace
            pods = v1.list_namespaced_pod(namespace, label_selector=label_selector)
            
            # Process each pod and extract relevant information
            for pod in pods.items:
                status = pod.status.phase
                # Calculate container readiness status
                ready_containers = sum(1 for c in pod.status.container_statuses if c.ready) if pod.status.container_statuses else 0
                total_containers = len(pod.spec.containers)
                
                # Build detailed pod information
                pod_info.append(f"Pod: {pod.metadata.name}")
                pod_info.append(f"  Status: {status}")
                pod_info.append(f"  Ready: {ready_containers}/{total_containers}")
                pod_info.append(f"  IP: {pod.status.pod_ip or 'N/A'}")
                pod_info.append(f"  Node: {pod.spec.node_name or 'N/A'}")
                pod_info.append(f"  Age: {pod.metadata.creation_timestamp}")
                
                # Include labels for better resource identification
                if pod.metadata.labels:
                    labels = [f"{k}={v}" for k, v in pod.metadata.labels.items()]
                    pod_info.append(f"  Labels: {', '.join(labels)}")
                
                pod_info.append("")  # Add spacing between pods
            total_pods = len(pods.items)
        
        # Format and return results
        if namespace == "*":
            result = "\n".join(pod_info) if pod_info else "No pods found in any namespace"
            logger.info(f"Found {total_pods} pods across all namespaces")
        else:
            result = "\n".join(pod_info) if pod_info else f"No pods found in namespace '{namespace}'"
            logger.info(f"Found {total_pods} pods in namespace {namespace}")
        return result
        
    except client.ApiException as e:
        # Handle Kubernetes API-specific errors with user-friendly messages
        error_msg = handle_kubernetes_exception(e, f"listing pods in namespace '{namespace}'")
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        # Handle unexpected errors
        error_msg = f"Unexpected error listing pods: {str(e)}"
        logger.error(error_msg)
        return error_msg

@mcp.tool()
def list_services(namespace: str = "default", label_selector: Optional[str] = None) -> str:
    """
    List all services in the specified namespace with optional label filtering.
    
    This tool provides comprehensive information about Kubernetes services including
    their type, cluster IP, ports, external IPs, and labels. Services are essential
    for network access to pods and applications.
    
    Args:
        namespace (str): The Kubernetes namespace to list services from.
                        Must follow Kubernetes naming conventions (default: "default").
                        Use "*" to list services from all namespaces.
        label_selector (Optional[str]): Label selector to filter services.
                                      Format: "key=value" or "key in (value1,value2)"
                                      Example: "app=nginx" or "type=LoadBalancer"
    
    Returns:
        str: Formatted string containing detailed service information including:
             - Service name and type (ClusterIP, NodePort, LoadBalancer, ExternalName)
             - Cluster IP address
             - Port mappings (port:target_port/protocol)
             - External IPs for LoadBalancer services
             - Creation timestamp and labels
             - Error message if operation fails
    
    Raises:
        InvalidInputError: If namespace or label_selector validation fails
        AccessDeniedError: If user lacks permissions to list services
        NamespaceNotFoundError: If the specified namespace doesn't exist
    """
    # Validate input parameters according to Kubernetes conventions
    is_valid, error_msg = InputValidator.validate_namespace(namespace)
    if not is_valid:
        logger.error(f"Invalid namespace: {error_msg}")
        return f"Error: {error_msg}"
    
    if label_selector:
        is_valid, error_msg = InputValidator.validate_label_selector(label_selector)
        if not is_valid:
            logger.error(f"Invalid label selector: {error_msg}")
            return f"Error: {error_msg}"
    
    # Log the operation for debugging and audit purposes
    logger.info(f"Listing services in namespace: {namespace}" + (f" with selector: {label_selector}" if label_selector else ""))
    
    try:
        svc_info = []
        total_services = 0
        
        # Handle wildcard namespace (all namespaces)
        if namespace == "*":
            # Get all namespaces and query each one
            all_namespaces = get_all_namespaces(v1)
            if not all_namespaces:
                return "Error: Could not retrieve namespace list"
            
            for ns in all_namespaces:
                services = v1.list_namespaced_service(ns, label_selector=label_selector)
                if services.items:
                    svc_info.append(f"=== Namespace: {ns} ===")
                    for svc in services.items:
                        svc_info.append(f"Service: {svc.metadata.name}")
                        svc_info.append(f"  Type: {svc.spec.type}")
                        
                        if svc.spec.cluster_ip:
                            svc_info.append(f"  Cluster IP: {svc.spec.cluster_ip}")
                        
                        if svc.spec.ports:
                            ports = [f"{port.port}:{port.target_port}/{port.protocol}" for port in svc.spec.ports]
                            svc_info.append(f"  Ports: {', '.join(ports)}")
                        
                        if svc.status.load_balancer and svc.status.load_balancer.ingress:
                            external_ips = [ingress.ip or ingress.hostname for ingress in svc.status.load_balancer.ingress]
                            svc_info.append(f"  External IPs: {', '.join(external_ips)}")
                        
                        if svc.metadata.labels:
                            labels = [f"{k}={v}" for k, v in svc.metadata.labels.items()]
                            svc_info.append(f"  Labels: {', '.join(labels)}")
                        
                        svc_info.append("")
                    total_services += len(services.items)
        else:
            # Query specific namespace
            services = v1.list_namespaced_service(namespace, label_selector=label_selector)
            
            # Process each service and extract relevant information
            for svc in services.items:
                svc_info.append(f"Service: {svc.metadata.name}")
                svc_info.append(f"  Type: {svc.spec.type}")
                
                # Include cluster IP for internal services
                if svc.spec.cluster_ip:
                    svc_info.append(f"  Cluster IP: {svc.spec.cluster_ip}")
                
                # Display port mappings
                if svc.spec.ports:
                    ports = [f"{port.port}:{port.target_port}/{port.protocol}" for port in svc.spec.ports]
                    svc_info.append(f"  Ports: {', '.join(ports)}")
                
                # Include external IPs for LoadBalancer services
                if svc.status.load_balancer and svc.status.load_balancer.ingress:
                    external_ips = [ingress.ip or ingress.hostname for ingress in svc.status.load_balancer.ingress]
                    svc_info.append(f"  External IPs: {', '.join(external_ips)}")
                
                # Include labels for better resource identification
                if svc.metadata.labels:
                    labels = [f"{k}={v}" for k, v in svc.metadata.labels.items()]
                    svc_info.append(f"  Labels: {', '.join(labels)}")
                
                svc_info.append("")  # Add spacing between services
            total_services = len(services.items)
        
        # Format and return results
        if namespace == "*":
            result = "\n".join(svc_info) if svc_info else "No services found in any namespace"
            logger.info(f"Found {total_services} services across all namespaces")
        else:
            result = "\n".join(svc_info) if svc_info else f"No services found in namespace '{namespace}'"
            logger.info(f"Found {total_services} services in namespace {namespace}")
        return result
        
    except client.ApiException as e:
        # Handle Kubernetes API-specific errors with user-friendly messages
        error_msg = handle_kubernetes_exception(e, f"listing services in namespace '{namespace}'")
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        # Handle unexpected errors
        error_msg = f"Unexpected error listing services: {str(e)}"
        logger.error(error_msg)
        return error_msg

@mcp.tool()
def get_cluster_info() -> str:
    """
    Get comprehensive information about the Kubernetes cluster.
    
    This tool provides detailed cluster information including version details,
    node information, and system specifications. It's useful for cluster
    health monitoring and troubleshooting.
    
    Returns:
        str: Formatted string containing cluster information including:
             - Kubernetes version and build information
             - Platform and Go version details
             - Node information (name, status, versions)
             - Container runtime and OS details
             - Error message if operation fails
    
    Raises:
        AccessDeniedError: If user lacks permissions to access cluster info
        KubernetesError: If cluster connection or API access fails
    """
    # Log the operation for debugging and audit purposes
    logger.info("Getting cluster information")
    
    try:
        # Get cluster version and build information
        version = version_api.get_code()
        nodes = v1.list_node()
        
        # Build comprehensive cluster information
        info = [
            f"Kubernetes Version: {version.git_version}",
            f"Build Date: {version.build_date}",
            f"Platform: {version.platform}",
            f"Go Version: {version.go_version}",
            "",
            "Nodes:",
        ]
        
        # Process each node and extract detailed information
        for node in nodes.items:
            # Find the Ready condition status
            ready_status = next((c.status for c in node.status.conditions if c.type == "Ready"), "Unknown")
            node_info = node.status.node_info
            
            # Add comprehensive node details
            info.extend([
                f"  Name: {node.metadata.name}",
                f"  Status: {ready_status}",
                f"  Kubelet Version: {node_info.kubelet_version}",
                f"  Container Runtime: {node_info.container_runtime_version}",
                f"  OS: {node_info.operating_system}",
                f"  Architecture: {node_info.architecture}",
                ""
            ])
        
        # Format and return results
        result = "\n".join(info)
        logger.info(f"Found {len(nodes.items)} nodes in the cluster")
        return result
        
    except client.ApiException as e:
        # Handle Kubernetes API-specific errors with user-friendly messages
        error_msg = handle_kubernetes_exception(e, "getting cluster information")
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        # Handle unexpected errors
        error_msg = f"Unexpected error getting cluster info: {str(e)}"
        logger.error(error_msg)
        return error_msg

# =============================================================================
# ADDITIONAL KUBERNETES RESOURCE TYPES
# =============================================================================

@mcp.tool()
def list_deployments(namespace: str = "default", label_selector: Optional[str] = None) -> str:
    """
    List all deployments in the specified namespace with optional label filtering.
    
    Deployments are higher-level abstractions that manage ReplicaSets and provide
    declarative updates to pods. This tool shows deployment status, replica counts,
    and rollout information.
    
    Args:
        namespace (str): The Kubernetes namespace to list deployments from.
                        Must follow Kubernetes naming conventions (default: "default").
                        Use "*" to list deployments from all namespaces.
        label_selector (Optional[str]): Label selector to filter deployments.
                                      Format: "key=value" or "key in (value1,value2)"
                                      Example: "app=nginx" or "tier=frontend"
    
    Returns:
        str: Formatted string containing detailed deployment information including:
             - Deployment name and replica status (ready/desired)
             - Available and updated replica counts
             - Creation timestamp and labels
             - Error message if operation fails
    
    Raises:
        InvalidInputError: If namespace or label_selector validation fails
        AccessDeniedError: If user lacks permissions to list deployments
        NamespaceNotFoundError: If the specified namespace doesn't exist
    """
    # Validate input parameters according to Kubernetes conventions
    is_valid, error_msg = InputValidator.validate_namespace(namespace)
    if not is_valid:
        logger.error(f"Invalid namespace: {error_msg}")
        return f"Error: {error_msg}"
    
    if label_selector:
        is_valid, error_msg = InputValidator.validate_label_selector(label_selector)
        if not is_valid:
            logger.error(f"Invalid label selector: {error_msg}")
            return f"Error: {error_msg}"
    
    # Log the operation for debugging and audit purposes
    logger.info(f"Listing deployments in namespace: {namespace}" + (f" with selector: {label_selector}" if label_selector else ""))
    
    try:
        # Initialize Apps API client for deployment operations
        apps_v1 = client.AppsV1Api()
        deploy_info = []
        total_deployments = 0
        
        # Handle wildcard namespace (all namespaces)
        if namespace == "*":
            # Get all namespaces and query each one
            all_namespaces = get_all_namespaces(v1)
            if not all_namespaces:
                return "Error: Could not retrieve namespace list"
            
            for ns in all_namespaces:
                deployments = apps_v1.list_namespaced_deployment(ns, label_selector=label_selector)
                if deployments.items:
                    deploy_info.append(f"=== Namespace: {ns} ===")
                    for deploy in deployments.items:
                        status = deploy.status
                        deploy_info.append(f"Deployment: {deploy.metadata.name}")
                        deploy_info.append(f"  Ready: {status.ready_replicas or 0}/{deploy.spec.replicas}")
                        deploy_info.append(f"  Available: {status.available_replicas or 0}")
                        deploy_info.append(f"  Updated: {status.updated_replicas or 0}")
                        deploy_info.append(f"  Age: {deploy.metadata.creation_timestamp}")
                        
                        if deploy.metadata.labels:
                            labels = [f"{k}={v}" for k, v in deploy.metadata.labels.items()]
                            deploy_info.append(f"  Labels: {', '.join(labels)}")
                        
                        deploy_info.append("")
                    total_deployments += len(deployments.items)
        else:
            # Query specific namespace
            deployments = apps_v1.list_namespaced_deployment(namespace, label_selector=label_selector)
            
            # Process each deployment and extract relevant information
            for deploy in deployments.items:
                status = deploy.status
                deploy_info.append(f"Deployment: {deploy.metadata.name}")
                deploy_info.append(f"  Ready: {status.ready_replicas or 0}/{deploy.spec.replicas}")
                deploy_info.append(f"  Available: {status.available_replicas or 0}")
                deploy_info.append(f"  Updated: {status.updated_replicas or 0}")
                deploy_info.append(f"  Age: {deploy.metadata.creation_timestamp}")
                
                # Include labels for better resource identification
                if deploy.metadata.labels:
                    labels = [f"{k}={v}" for k, v in deploy.metadata.labels.items()]
                    deploy_info.append(f"  Labels: {', '.join(labels)}")
                
                deploy_info.append("")  # Add spacing between deployments
            total_deployments = len(deployments.items)
        
        # Format and return results
        if namespace == "*":
            result = "\n".join(deploy_info) if deploy_info else "No deployments found in any namespace"
            logger.info(f"Found {total_deployments} deployments across all namespaces")
        else:
            result = "\n".join(deploy_info) if deploy_info else f"No deployments found in namespace '{namespace}'"
            logger.info(f"Found {total_deployments} deployments in namespace {namespace}")
        return result
        
    except client.ApiException as e:
        # Handle Kubernetes API-specific errors with user-friendly messages
        error_msg = handle_kubernetes_exception(e, f"listing deployments in namespace '{namespace}'")
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        # Handle unexpected errors
        error_msg = f"Unexpected error listing deployments: {str(e)}"
        logger.error(error_msg)
        return error_msg

@mcp.tool()
def list_configmaps(namespace: str = "default", label_selector: Optional[str] = None) -> str:
    """
    List all configmaps in the specified namespace with optional label filtering.
    
    ConfigMaps are used to store non-confidential data in key-value pairs.
    They can be consumed by pods as environment variables, command-line arguments,
    or configuration files in a volume.
    
    Args:
        namespace (str): The Kubernetes namespace to list configmaps from.
                        Must follow Kubernetes naming conventions (default: "default").
                        Use "*" to list configmaps from all namespaces.
        label_selector (Optional[str]): Label selector to filter configmaps.
                                      Format: "key=value" or "key in (value1,value2)"
                                      Example: "app=nginx" or "type=config"
    
    Returns:
        str: Formatted string containing detailed configmap information including:
             - ConfigMap name and data entry counts
             - Binary data entry counts
             - Creation timestamp and labels
             - Error message if operation fails
    
    Raises:
        InvalidInputError: If namespace or label_selector validation fails
        AccessDeniedError: If user lacks permissions to list configmaps
        NamespaceNotFoundError: If the specified namespace doesn't exist
    """
    # Validate input parameters according to Kubernetes conventions
    is_valid, error_msg = InputValidator.validate_namespace(namespace)
    if not is_valid:
        logger.error(f"Invalid namespace: {error_msg}")
        return f"Error: {error_msg}"
    
    if label_selector:
        is_valid, error_msg = InputValidator.validate_label_selector(label_selector)
        if not is_valid:
            logger.error(f"Invalid label selector: {error_msg}")
            return f"Error: {error_msg}"
    
    # Log the operation for debugging and audit purposes
    logger.info(f"Listing configmaps in namespace: {namespace}" + (f" with selector: {label_selector}" if label_selector else ""))
    
    try:
        # Query Kubernetes API for configmaps in the specified namespace
        configmaps = v1.list_namespaced_config_map(namespace, label_selector=label_selector)
        cm_info = []
        
        # Process each configmap and extract relevant information
        for cm in configmaps.items:
            cm_info.append(f"ConfigMap: {cm.metadata.name}")
            cm_info.append(f"  Data: {len(cm.data) if cm.data else 0} entries")
            cm_info.append(f"  Binary Data: {len(cm.binary_data) if cm.binary_data else 0} entries")
            cm_info.append(f"  Age: {cm.metadata.creation_timestamp}")
            
            # Include labels for better resource identification
            if cm.metadata.labels:
                labels = [f"{k}={v}" for k, v in cm.metadata.labels.items()]
                cm_info.append(f"  Labels: {', '.join(labels)}")
            
            cm_info.append("")  # Add spacing between configmaps
        
        # Format and return results
        result = "\n".join(cm_info) if cm_info else f"No configmaps found in namespace '{namespace}'"
        logger.info(f"Found {len(configmaps.items)} configmaps in namespace {namespace}")
        return result
        
    except client.ApiException as e:
        # Handle Kubernetes API-specific errors with user-friendly messages
        error_msg = handle_kubernetes_exception(e, f"listing configmaps in namespace '{namespace}'")
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        # Handle unexpected errors
        error_msg = f"Unexpected error listing configmaps: {str(e)}"
        logger.error(error_msg)
        return error_msg

@mcp.tool()
def list_secrets(namespace: str = "default", label_selector: Optional[str] = None) -> str:
    """
    List all secrets in the specified namespace with optional label filtering.
    
    Secrets are used to store sensitive information such as passwords, OAuth tokens,
    and SSH keys. They are base64 encoded and can be consumed by pods as environment
    variables or mounted as files in a volume.
    
    Args:
        namespace (str): The Kubernetes namespace to list secrets from.
                        Must follow Kubernetes naming conventions (default: "default").
                        Use "*" to list secrets from all namespaces.
        label_selector (Optional[str]): Label selector to filter secrets.
                                      Format: "key=value" or "key in (value1,value2)"
                                      Example: "type=Opaque" or "app=database"
    
    Returns:
        str: Formatted string containing detailed secret information including:
             - Secret name and type (Opaque, kubernetes.io/service-account-token, etc.)
             - Data entry counts (without exposing actual values)
             - Creation timestamp and labels
             - Error message if operation fails
    
    Raises:
        InvalidInputError: If namespace or label_selector validation fails
        AccessDeniedError: If user lacks permissions to list secrets
        NamespaceNotFoundError: If the specified namespace doesn't exist
    """
    # Validate input parameters according to Kubernetes conventions
    is_valid, error_msg = InputValidator.validate_namespace(namespace)
    if not is_valid:
        logger.error(f"Invalid namespace: {error_msg}")
        return f"Error: {error_msg}"
    
    if label_selector:
        is_valid, error_msg = InputValidator.validate_label_selector(label_selector)
        if not is_valid:
            logger.error(f"Invalid label selector: {error_msg}")
            return f"Error: {error_msg}"
    
    # Log the operation for debugging and audit purposes
    logger.info(f"Listing secrets in namespace: {namespace}" + (f" with selector: {label_selector}" if label_selector else ""))
    
    try:
        # Query Kubernetes API for secrets in the specified namespace
        secrets = v1.list_namespaced_secret(namespace, label_selector=label_selector)
        secret_info = []
        
        # Process each secret and extract relevant information
        for secret in secrets.items:
            secret_info.append(f"Secret: {secret.metadata.name}")
            secret_info.append(f"  Type: {secret.type}")
            secret_info.append(f"  Data: {len(secret.data) if secret.data else 0} entries")
            secret_info.append(f"  Age: {secret.metadata.creation_timestamp}")
            
            # Include labels for better resource identification
            if secret.metadata.labels:
                labels = [f"{k}={v}" for k, v in secret.metadata.labels.items()]
                secret_info.append(f"  Labels: {', '.join(labels)}")
            
            secret_info.append("")  # Add spacing between secrets
        
        # Format and return results
        result = "\n".join(secret_info) if secret_info else f"No secrets found in namespace '{namespace}'"
        logger.info(f"Found {len(secrets.items)} secrets in namespace {namespace}")
        return result
        
    except client.ApiException as e:
        # Handle Kubernetes API-specific errors with user-friendly messages
        error_msg = handle_kubernetes_exception(e, f"listing secrets in namespace '{namespace}'")
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        # Handle unexpected errors
        error_msg = f"Unexpected error listing secrets: {str(e)}"
        logger.error(error_msg)
        return error_msg

@mcp.tool()
def list_namespaces(label_selector: Optional[str] = None) -> str:
    """
    List all namespaces in the cluster with optional label filtering.
    
    Namespaces provide a way to divide cluster resources between multiple users,
    teams, or projects. They are the primary mechanism for resource isolation
    and access control in Kubernetes.
    
    Args:
        label_selector (Optional[str]): Label selector to filter namespaces.
                                      Format: "key=value" or "key in (value1,value2)"
                                      Example: "name=default" or "environment=production"
    
    Returns:
        str: Formatted string containing detailed namespace information including:
             - Namespace name and status (Active, Terminating)
             - Creation timestamp and labels
             - Error message if operation fails
    
    Raises:
        InvalidInputError: If label_selector validation fails
        AccessDeniedError: If user lacks permissions to list namespaces
        KubernetesError: If cluster connection or API access fails
    """
    # Validate label selector if provided
    if label_selector:
        is_valid, error_msg = InputValidator.validate_label_selector(label_selector)
        if not is_valid:
            logger.error(f"Invalid label selector: {error_msg}")
            return f"Error: {error_msg}"
    
    # Log the operation for debugging and audit purposes
    logger.info("Listing namespaces" + (f" with selector: {label_selector}" if label_selector else ""))
    
    try:
        # Query Kubernetes API for all namespaces in the cluster
        namespaces = v1.list_namespace(label_selector=label_selector)
        ns_info = []
        
        # Process each namespace and extract relevant information
        for ns in namespaces.items:
            status = ns.status.phase
            ns_info.append(f"Namespace: {ns.metadata.name}")
            ns_info.append(f"  Status: {status}")
            ns_info.append(f"  Age: {ns.metadata.creation_timestamp}")
            
            # Include labels for better resource identification
            if ns.metadata.labels:
                labels = [f"{k}={v}" for k, v in ns.metadata.labels.items()]
                ns_info.append(f"  Labels: {', '.join(labels)}")
            
            ns_info.append("")  # Add spacing between namespaces
        
        # Format and return results
        result = "\n".join(ns_info) if ns_info else "No namespaces found"
        logger.info(f"Found {len(namespaces.items)} namespaces")
        return result
        
    except client.ApiException as e:
        # Handle Kubernetes API-specific errors with user-friendly messages
        error_msg = handle_kubernetes_exception(e, "listing namespaces")
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        # Handle unexpected errors
        error_msg = f"Unexpected error listing namespaces: {str(e)}"
        logger.error(error_msg)
        return error_msg

# =============================================================================
# MAIN EXECUTION
# =============================================================================

if __name__ == "__main__":
    """
    Main entry point for the MCP server.
    
    Starts the FastMCP server which will handle incoming tool requests
    and route them to the appropriate Kubernetes resource management functions.
    """
    mcp.run() 