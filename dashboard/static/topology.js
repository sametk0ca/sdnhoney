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
    
    // Create fix layout toggle button
    const fixLayoutButton = document.createElement('button');
    fixLayoutButton.id = 'topology-fix-layout-btn';
    fixLayoutButton.innerHTML = '🔒 Fix Layout';
    fixLayoutButton.className = 'topology-button';
    fixLayoutButton.style.marginLeft = '10px';
    container.parentNode.insertBefore(fixLayoutButton, container);
    
    // Track layout fixed state
    let layoutFixed = true;
    
    // Create the SVG element
    const svg = d3.select('#topology-container')
        .append('svg')
        .attr('width', width)
        .attr('height', height);
    
    // Initialize force simulation
    const simulation = d3.forceSimulation()
        .force('link', d3.forceLink().id(d => d.id).distance(100))
        .force('charge', d3.forceManyBody().strength(-600))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collision', d3.forceCollide().radius(40));
    
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
    
    // Initialize empty data
    let nodes = [];
    let links = [];
    
    // Function to update the topology visualization
    function updateTopology(data) {
        // Clear previous visualization
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
            .attr('class', d => d.active ? 'link active' : 'link')
            .attr('stroke-width', 2); // Increase link visibility
        
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
        
        // Apply the layout based on current state
        if (layoutFixed) {
            applyFixedLayout(nodes);
        }
        
        // Update simulation with new data
        simulation
            .nodes(nodes)
            .on('tick', ticked);
        
        simulation.force('link')
            .links(links);
        
        // Restart simulation with high alpha to ensure good positioning
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
        
        const now = new Date();
        statusText.text(`Topology refreshed at ${now.toLocaleTimeString()}`);
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
        // Keep the node fixed at the position where it was dragged
        // This ensures nodes stay connected but can be manually arranged
    }
    
    // Function to convert API data to topology visualization format
    function processTopologyData(data) {
        // Placeholder for converted data
        const topology = {
            nodes: [],
            links: []
        };
        
        // Process switches - create all switch nodes
        if (data.switches && data.switches.length) {
            data.switches.forEach((dpid, index) => {
                topology.nodes.push({
                    id: `s${index + 1}`,
                    type: 'switch',
                    dpid: dpid
                });
            });
        }
        
        // Process hosts - create all host nodes
        if (data.hosts && Object.keys(data.hosts).length) {
            for (const [hostName, hostData] of Object.entries(data.hosts)) {
                // Determine node type
                let nodeType = 'host';
                if (hostName === 'h15') nodeType = 'honeypot'; // Updated for new honeypot host (h15)
                if (hostName.startsWith('external')) nodeType = 'external';
                
                // Determine MAC address based on host name
                let mac = hostData.mac || 'unknown';
                
                // Map specific MAC addresses based on host name
                if (hostName.startsWith('external')) {
                    // external1-4: 01-04
                    const externalNum = parseInt(hostName.substring(8));
                    if (externalNum >= 1 && externalNum <= 4) {
                        const hexNum = externalNum.toString(16).padStart(2, '0');
                        mac = `00:00:00:00:00:${hexNum}`;
                    }
                } else if (hostName.startsWith('h')) {
                    const hostNum = parseInt(hostName.substring(1));
                    if (hostNum >= 1 && hostNum <= 5) {
                        // host1-5: 05-09
                        const hexNum = (hostNum + 4).toString(16).padStart(2, '0');
                        mac = `00:00:00:00:00:${hexNum}`;
                    } else if (hostNum >= 6 && hostNum <= 11) {
                        // host6-11: 0a-0f
                        const hexNum = (hostNum + 4).toString(16).padStart(2, '0');
                        mac = `00:00:00:00:00:${hexNum}`;
                    } else if (hostNum >= 12 && hostNum <= 15) {
                        // host12-15: 10-13
                        const hexNum = (hostNum - 2).toString(16).padStart(2, '0');
                        mac = `00:00:00:00:00:${hexNum}`;
                    }
                }
                
                topology.nodes.push({
                    id: hostName,
                    type: nodeType,
                    ip: hostData.ip || 'unknown',
                    mac: mac
                });
            }
        }
        
        // Create a map of the predefined links in the topology
        const topologyLinks = [
            // Core to core links
            { source: 's1', target: 's2' },
            
            // Core to Aggregation links
            { source: 's1', target: 's3' }, 
            { source: 's1', target: 's4' },
            { source: 's2', target: 's5' }, 
            { source: 's2', target: 's6' },
            
            // Aggregation to Edge links
            { source: 's3', target: 's7' }, 
            { source: 's3', target: 's8' },
            { source: 's4', target: 's9' }, 
            { source: 's4', target: 's10' },
            { source: 's5', target: 's11' }, 
            { source: 's5', target: 's12' },
            { source: 's6', target: 's13' }, 
            { source: 's6', target: 's14' },
            
            // Edge to Host links (based on topology.py)
            { source: 's7', target: 'h1' }, 
            { source: 's7', target: 'h2' },
            { source: 's8', target: 'h3' }, 
            { source: 's8', target: 'h4' },
            { source: 's9', target: 'h5' }, 
            { source: 's9', target: 'h6' },
            { source: 's10', target: 'h7' }, 
            { source: 's10', target: 'h8' },
            { source: 's11', target: 'h9' }, 
            { source: 's11', target: 'h10' },
            { source: 's12', target: 'h11' }, 
            { source: 's12', target: 'h12' },
            { source: 's13', target: 'h13' }, 
            { source: 's13', target: 'h14' },
            { source: 's14', target: 'h15' }, // Honeypot host
            
            // External hosts to core switches
            { source: 's1', target: 'external1' },
            { source: 's1', target: 'external2' },
            { source: 's2', target: 'external3' },
            { source: 's2', target: 'external4' }
        ];
        
        // Add all links from the predefined topology
        for (const link of topologyLinks) {
            // Check if both source and target nodes exist before adding the link
            const sourceExists = topology.nodes.some(node => node.id === link.source);
            const targetExists = topology.nodes.some(node => node.id === link.target);
            
            if (sourceExists && targetExists) {
                topology.links.push({
                    source: link.source,
                    target: link.target,
                    active: true
                });
            }
        }
        
        return topology;
    }
    
    // Function to fetch and update topology data
    function updateTopologyData() {
        statusText.text('Refreshing topology...');
        
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
        updateTopologyData();
    });
    
    // Fix layout button event listener
    fixLayoutButton.addEventListener('click', function() {
        layoutFixed = !layoutFixed;
        
        if (layoutFixed) {
            fixLayoutButton.innerHTML = '🔒 Fix Layout';
            applyFixedLayout(nodes);
        } else {
            fixLayoutButton.innerHTML = '🔓 Free Layout';
            releaseFixedLayout(nodes);
        }
        
        // Restart simulation to apply changes
        simulation.alpha(1).restart();
    });
    
    // Initialize node positions based on their hierarchical level in the network
    function applyFixedLayout(nodes) {
        nodes.forEach(node => {
            // Set initial positions based on node type/ID to help with visualization
            if (node.id.startsWith('s')) {
                const switchNum = parseInt(node.id.substring(1));
                
                // Core switches (s1-s2)
                if (switchNum <= 2) {
                    node.fx = width * (0.3 + (switchNum - 1) * 0.4); // Horizontally spread
                    node.fy = height * 0.2; // Top of the visualization
                } 
                // Aggregation switches (s3-s6)
                else if (switchNum <= 6) {
                    const column = (switchNum - 3) % 4;
                    node.fx = width * (0.2 + column * 0.2);
                    node.fy = height * 0.4;
                } 
                // Edge switches (s7-s14)
                else {
                    const column = (switchNum - 7) % 8;
                    node.fx = width * (0.1 + column * 0.1);
                    node.fy = height * 0.6;
                }
            }
            
            // Position hosts below their connected switches
            else if (node.id.startsWith('h')) {
                const hostNum = parseInt(node.id.substring(1));
                const column = (hostNum - 1) % 14;
                node.fx = width * (0.1 + column * 0.06);
                node.fy = height * 0.8;
            }
            
            // Position external hosts at the top
            else if (node.id.startsWith('external')) {
                const externalNum = parseInt(node.id.substring(8));
                node.fx = width * (0.2 + (externalNum - 1) * 0.2);
                node.fy = height * 0.05;
            }
        });
    }
    
    // Release fixed positions and allow dynamic layout
    function releaseFixedLayout(nodes) {
        nodes.forEach(node => {
            // Keep x and y but release fixed positions
            node.x = node.fx || node.x;
            node.y = node.fy || node.y;
            node.fx = null;
            node.fy = null;
        });
    }
}); 