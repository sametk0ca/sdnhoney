/**
 * Network Topology Visualization using D3.js
 * For SDN Honeypot Dashboard
 */

document.addEventListener('DOMContentLoaded', function() {
    // Get the container dimensions for the visualization
    const container = document.getElementById('topology-container');
    const width = container.clientWidth;
    const height = container.clientHeight;
    
    // Create manual refresh button
    const refreshButton = document.createElement('button');
    refreshButton.id = 'topology-refresh-btn';
    refreshButton.innerHTML = '↻ Refresh Topology';
    refreshButton.className = 'topology-refresh-btn';
    container.parentNode.insertBefore(refreshButton, container);
    
    // Create the SVG element
    const svg = d3.select('#topology-container')
        .append('svg')
        .attr('width', width)
        .attr('height', height);
    
    // Initialize force simulation
    const simulation = d3.forceSimulation()
        .force('link', d3.forceLink().id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-300))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(30));
    
    // Create zoom behavior
    const zoom = d3.zoom()
        .scaleExtent([0.5, 3])
        .on('zoom', (event) => {
            g.attr('transform', event.transform);
        });
    
    // Apply zoom to SVG
    svg.call(zoom);
    
    // Create a group for all visualization elements (for zooming)
    const g = svg.append('g');
    
    // Group elements for links and nodes
    const linkGroup = g.append('g').attr('class', 'links');
    const nodeGroup = g.append('g').attr('class', 'nodes');
    
    // Add status indicator
    const statusText = svg.append('text')
        .attr('id', 'topology-status')
        .attr('x', 20)
        .attr('y', 30)
        .attr('class', 'topology-status')
        .text('Topology initialized');
    
    // Flag to track if this is the first load
    let isFirstLoad = true;
    
    // Initialize empty data
    let nodes = [];
    let links = [];
    
    // Function to update the topology visualization
    function updateTopology(data) {
        // Only clear visualization if it's the first load or manually refreshed
        if (isFirstLoad) {
            linkGroup.selectAll('*').remove();
            nodeGroup.selectAll('*').remove();
            
            statusText.text('Topology loading...');
            
            if (!data || !data.topology) {
                // If no topology data, show placeholder
                statusText.text('No topology data available');
                return;
            }
            
            // Process topology data
            nodes = data.topology.nodes || [];
            links = data.topology.links || [];
            
            // Create links
            const link = linkGroup.selectAll('.link')
                .data(links)
                .enter()
                .append('line')
                .attr('class', d => d.active ? 'link active' : 'link');
            
            // Create nodes
            const node = nodeGroup.selectAll('.node')
                .data(nodes)
                .enter()
                .append('g')
                .attr('class', 'node')
                .call(d3.drag()
                    .on('start', dragStarted)
                    .on('drag', dragged)
                    .on('end', dragEnded));
            
            // Add circles for nodes
            node.append('circle')
                .attr('r', d => {
                    // Use different sizes based on node type
                    if (d.type === 'switch') return 18;
                    if (d.type === 'honeypot') return 15;
                    if (d.type === 'external') return 15;
                    return 14; // Regular hosts
                })
                .attr('class', d => d.type);
            
            // Add secondary circles for hosts to create a double-circle effect
            node.filter(d => d.type !== 'switch')
                .append('circle')
                .attr('r', d => {
                    if (d.type === 'honeypot') return 10;
                    if (d.type === 'external') return 10;
                    return 9; // Regular hosts
                })
                .attr('class', d => `${d.type}-inner`);
            
            // Add 'X' sign inside switches
            node.filter(d => d.type === 'switch')
                .append('text')
                .attr('text-anchor', 'middle')
                .attr('dominant-baseline', 'middle')
                .attr('class', 'switch-x')
                .attr('dy', '.1em')
                .text('✕');
            
            // Add labels for nodes
            node.append('text')
                .attr('dx', d => {
                    // Position labels based on node type
                    if (d.type === 'switch') return 22;
                    return 18;
                })
                .attr('dy', '.35em')
                .attr('class', d => `node-label ${d.type}-label`)
                .text(d => d.id);
                
            // Add small indicators for special nodes
            node.filter(d => d.type === 'honeypot')
                .append('text')
                .attr('class', 'node-indicator honeypot-indicator')
                .attr('text-anchor', 'middle')
                .attr('dominant-baseline', 'middle')
                .attr('dy', '.1em')
                .text('H');
                
            node.filter(d => d.type === 'external')
                .append('text')
                .attr('class', 'node-indicator external-indicator')
                .attr('text-anchor', 'middle')
                .attr('dominant-baseline', 'middle')
                .attr('dy', '.1em')
                .text('E');
            
            // Add tooltips showing node details on hover
            node.append('title')
                .text(d => {
                    let details = `ID: ${d.id}\nType: ${d.type}`;
                    
                    if (d.type === 'switch') {
                        if (d.dpid) details += `\nDPID: ${d.dpid}`;
                    } 
                    else {
                        // More detailed info for hosts
                        if (d.ip) details += `\nIP: ${d.ip}`;
                        if (d.mac) details += `\nMAC: ${d.mac}`;
                        
                        // Add special notes based on node type
                        if (d.type === 'honeypot') {
                            details += `\n--- HONEYPOT HOST ---`;
                        } else if (d.type === 'external') {
                            details += `\n--- EXTERNAL NODE ---`;
                        }
                    }
                    
                    return details;
                });
            
            // Update simulation with new data
            simulation
                .nodes(nodes)
                .on('tick', ticked);
            
            simulation.force('link')
                .links(links);
            
            // Restart simulation
            simulation.alpha(1).restart();
            
            // Function to update positions on each simulation tick
            function ticked() {
                link
                    .attr('x1', d => d.source.x)
                    .attr('y1', d => d.source.y)
                    .attr('x2', d => d.target.x)
                    .attr('y2', d => d.target.y);
                
                node.attr('transform', d => `translate(${d.x},${d.y})`);
            }
            
            // After first successful load, update status and flag
            isFirstLoad = false;
            statusText.text('Topology loaded - Manual refresh only');
        }
        
        // Drag functions
        function dragStarted(event, d) {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }
        
        function dragged(event, d) {
            d.fx = event.x;
            d.fy = event.y;
        }
        
        function dragEnded(event, d) {
            if (!event.active) simulation.alphaTarget(0);
            // Keep the nodes fixed where the user dragged them
            // by NOT resetting fx/fy to null
            // Uncomment the next lines to make them "spring back":
            // d.fx = null;
            // d.fy = null;
        }
    }
    
    // Function to convert API data to topology visualization format
    function processTopologyData(data) {
        // Placeholder for converted data
        const topology = {
            nodes: [],
            links: []
        };
        
        // Process switches
        if (data.switches && data.switches.length) {
            data.switches.forEach((dpid, index) => {
                topology.nodes.push({
                    id: `s${index + 1}`,
                    type: 'switch',
                    dpid: dpid
                });
            });
        }
        
        // Process hosts
        if (data.hosts && Object.keys(data.hosts).length) {
            for (const [hostName, hostData] of Object.entries(data.hosts)) {
                // Determine node type
                let nodeType = 'host';
                if (hostName === 'h8') nodeType = 'honeypot';
                if (hostName.startsWith('external')) nodeType = 'external';
                
                topology.nodes.push({
                    id: hostName,
                    type: nodeType,
                    ip: hostData.ip || 'unknown',
                    mac: hostData.mac || 'unknown'
                });
            }
        }
        
        // Process links from MAC table
        if (data.mac_table && Object.keys(data.mac_table).length) {
            // In the MAC table format, DPID is the key and values are mac:port mappings
            for (const [dpid, portMap] of Object.entries(data.mac_table)) {
                // Find the switch ID from the DPID
                const switchIndex = data.switches.indexOf(dpid);
                if (switchIndex < 0) continue;
                
                const switchId = `s${switchIndex + 1}`;
                
                // For each MAC address in this switch's port map
                for (const [mac, port] of Object.entries(portMap)) {
                    // Find the host with this MAC
                    let targetNode = null;
                    
                    // Since MAC addresses might not be in hosts data directly
                    // We use port numbers based on topology to create links
                    // This is a simplification - in a real system, you'd get full link data from the controller
                    
                    // For now, we'll use host index to infer connections
                    // This is a placeholder - in practice, the controller should provide proper link data
                    const targetId = `h${port}`;
                    
                    topology.links.push({
                        source: switchId,
                        target: targetId,
                        port: port,
                        active: (Math.random() > 0.7) // Random activity for demo
                    });
                }
            }
        }
        
        // Add fixed topology connections between switches
        // This is hardcoded based on the known topology from large_topo.py
        
        // Core to aggregation links (s1-s2, s1-s3)
        topology.links.push({ source: 's1', target: 's2' });
        topology.links.push({ source: 's1', target: 's3' });
        
        // Aggregation to edge links (s2-s4, s2-s5, s3-s6, s3-s7)
        topology.links.push({ source: 's2', target: 's4' });
        topology.links.push({ source: 's2', target: 's5' });
        topology.links.push({ source: 's3', target: 's6' });
        topology.links.push({ source: 's3', target: 's7' });
        
        // Host connections based on the known topology
        topology.links.push({ source: 's4', target: 'h1' });
        topology.links.push({ source: 's4', target: 'h2' });
        topology.links.push({ source: 's5', target: 'h3' });
        topology.links.push({ source: 's5', target: 'h4' });
        topology.links.push({ source: 's6', target: 'h5' });
        topology.links.push({ source: 's6', target: 'h6' });
        topology.links.push({ source: 's7', target: 'h7' });
        topology.links.push({ source: 's7', target: 'h8' }); // Honeypot host
        topology.links.push({ source: 's1', target: 'external1' });
        topology.links.push({ source: 's1', target: 'external2' });
        
        return topology;
    }
    
    // Function to fetch and update topology data
    function updateTopologyData() {
        // Show "refreshing" status when manually refreshed
        if (!isFirstLoad) {
            statusText.text('Refreshing topology...');
        }
        
        fetch('/data?_=' + new Date().getTime())
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                // Add the topology data to the response
                data.topology = processTopologyData(data);
                
                // Update the visualization
                updateTopology(data);
                
                // Show timestamp for last refresh if not first load
                if (!isFirstLoad) {
                    const now = new Date();
                    statusText.text(`Topology refreshed at ${now.toLocaleTimeString()}`);
                }
            })
            .catch(error => {
                console.error('Error fetching topology data:', error);
                // Show error in status text
                statusText.text(`Error: ${error.message}`);
            });
    }
    
    // Initial update
    updateTopologyData();
    
    // Manual refresh button event listener
    refreshButton.addEventListener('click', function() {
        isFirstLoad = true;  // Force a full refresh
        updateTopologyData();
    });
    
    // No automatic interval refresh for topology
    // The rest of the dashboard will still refresh every 5 seconds
}); 