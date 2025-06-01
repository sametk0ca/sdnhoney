// SDN Honeypot Dashboard JavaScript
class SDNDashboard {
    constructor() {
        this.topology = null;
        this.chart = null;
        this.updateInterval = 5000; // 5 seconds
        this.logCounter = 0;
        
        this.init();
    }
    
    init() {
        this.setupTopology();
        this.setupChart();
        this.startRealTimeUpdates();
        this.addLog('Dashboard initialized successfully');
    }
    
    // Network Topology Visualization
    setupTopology() {
        const container = d3.select('#topology-svg');
        const containerNode = document.getElementById('topology-container');
        const width = containerNode.clientWidth;
        const height = containerNode.clientHeight;
        
        container.attr('width', width).attr('height', height);
        
        // Fetch topology data and render
        fetch('/api/topology')
            .then(response => response.json())
            .then(data => {
                this.topology = data;
                this.renderTopology(data, width, height);
            })
            .catch(error => {
                console.error('Error fetching topology:', error);
                this.addLog('Error loading topology data');
            });
    }
    
    renderTopology(data, width, height) {
        const svg = d3.select('#topology-svg');
        svg.selectAll('*').remove(); // Clear previous content
        
        // Create groups for links and nodes
        const linkGroup = svg.append('g').attr('class', 'links');
        const nodeGroup = svg.append('g').attr('class', 'nodes');
        
        // Combine all nodes (switches + hosts)
        const allNodes = [...data.switches, ...data.hosts];
        
        // Draw links
        const links = linkGroup.selectAll('.link')
            .data(data.links)
            .enter()
            .append('line')
            .attr('class', 'link')
            .attr('x1', d => {
                const source = allNodes.find(n => n.id === d.source);
                return source ? source.x : 0;
            })
            .attr('y1', d => {
                const source = allNodes.find(n => n.id === d.source);
                return source ? source.y : 0;
            })
            .attr('x2', d => {
                const target = allNodes.find(n => n.id === d.target);
                return target ? target.x : 0;
            })
            .attr('y2', d => {
                const target = allNodes.find(n => n.id === d.target);
                return target ? target.y : 0;
            });
        
        // Draw nodes
        const nodes = nodeGroup.selectAll('.node')
            .data(allNodes)
            .enter()
            .append('g')
            .attr('class', 'node')
            .attr('transform', d => `translate(${d.x}, ${d.y})`);
        
        // Add node circles
        nodes.append('circle')
            .attr('r', d => d.id.startsWith('s') ? 20 : 15)
            .attr('class', d => {
                if (d.id.startsWith('s')) return 'node-switch';
                if (d.type === 'normal') return 'node-host node-normal';
                if (d.type === 'triage_honeypot' || d.type === 'deep_honeypot') return 'node-host node-honeypot';
                return 'node-host node-client';
            });
        
        // Add node labels
        nodes.append('text')
            .attr('class', 'node-text')
            .attr('dy', '0.35em')
            .text(d => d.id);
        
        // Add tooltips
        nodes.append('title')
            .text(d => {
                if (d.id.startsWith('s')) {
                    return `${d.name}\nSwitch ID: ${d.id}`;
                } else {
                    return `${d.name}\nIP: ${d.ip}\nPort: ${d.port || 'N/A'}\nType: ${d.type}`;
                }
            });
    }
    
    // Traffic Chart Setup
    setupChart() {
        const ctx = document.getElementById('traffic-chart').getContext('2d');
        
        this.chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Active IPs',
                        data: [],
                        borderColor: '#00ff88',
                        backgroundColor: 'rgba(0, 255, 136, 0.1)',
                        tension: 0.4
                    },
                    {
                        label: 'Suspicious IPs',
                        data: [],
                        borderColor: '#ffa500',
                        backgroundColor: 'rgba(255, 165, 0, 0.1)',
                        tension: 0.4
                    },
                    {
                        label: 'Malicious IPs',
                        data: [],
                        borderColor: '#ff4757',
                        backgroundColor: 'rgba(255, 71, 87, 0.1)',
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#ffffff' },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    },
                    y: {
                        ticks: { color: '#ffffff' },
                        grid: { color: 'rgba(255, 255, 255, 0.1)' }
                    }
                },
                interaction: {
                    intersect: false
                }
            }
        });
    }
    
    // Real-time Updates
    startRealTimeUpdates() {
        setInterval(() => {
            this.updateStats();
            this.updateHostStatus();
            this.updateAlerts();
            this.updateFlows();
            this.updateTrafficHistory();
        }, this.updateInterval);
        
        // Initial load
        this.updateStats();
        this.updateHostStatus();
    }
    
    updateStats() {
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                // Update statistics
                document.getElementById('active-ips').textContent = data.active_ips || 0;
                document.getElementById('suspicious-ips').textContent = data.suspicious_ips ? data.suspicious_ips.length : 0;
                document.getElementById('malicious-ips').textContent = data.malicious_ips ? data.malicious_ips.length : 0;
                document.getElementById('flow-count').textContent = data.flow_count || 0;
                
                // Update controller status
                const controllerStatus = document.getElementById('controller-status');
                controllerStatus.textContent = 'Online';
                controllerStatus.style.color = '#00ff88';
                
                // Update last update time
                document.getElementById('last-update').textContent = data.last_update || new Date().toLocaleTimeString();
                
                this.addLog(`Stats updated: ${data.active_ips} active IPs, ${data.suspicious_ips ? data.suspicious_ips.length : 0} suspicious`);
            })
            .catch(error => {
                console.error('Error updating stats:', error);
                const controllerStatus = document.getElementById('controller-status');
                controllerStatus.textContent = 'Offline';
                controllerStatus.style.color = '#ff4757';
                this.addLog('Controller connection failed');
            });
    }
    
    updateHostStatus() {
        fetch('/api/host_status')
            .then(response => response.json())
            .then(data => {
                const container = document.getElementById('host-status-grid');
                container.innerHTML = '';
                
                Object.entries(data).forEach(([hostId, status]) => {
                    const hostDiv = document.createElement('div');
                    hostDiv.className = `host-item ${status}`;
                    hostDiv.textContent = `${hostId.toUpperCase()}: ${status.toUpperCase()}`;
                    container.appendChild(hostDiv);
                });
            })
            .catch(error => console.error('Error updating host status:', error));
    }
    
    updateAlerts() {
        fetch('/api/honeypot_alerts')
            .then(response => response.json())
            .then(data => {
                const container = document.getElementById('alerts-container');
                
                if (data.length === 0) {
                    container.innerHTML = '<div class="no-alerts">No recent alerts</div>';
                    return;
                }
                
                container.innerHTML = '';
                data.slice(-10).reverse().forEach(alert => {
                    const alertDiv = document.createElement('div');
                    alertDiv.className = 'alert-item';
                    alertDiv.innerHTML = `
                        <div class="alert-time">${alert.timestamp || 'Unknown time'}</div>
                        <div>IP: <span class="alert-ip">${alert.source_ip || 'Unknown'}</span></div>
                        <div>Classification: ${alert.classification || 'Unknown'}</div>
                        <div>Risk Score: ${alert.risk_score || 'N/A'}</div>
                    `;
                    container.appendChild(alertDiv);
                });
            })
            .catch(error => console.error('Error updating alerts:', error));
    }
    
    updateFlows() {
        fetch('/api/traffic_flows')
            .then(response => response.json())
            .then(data => {
                const container = document.getElementById('flows-container');
                
                if (data.length === 0) {
                    container.innerHTML = '<div class="no-flows">No active flows detected</div>';
                    return;
                }
                
                container.innerHTML = '';
                data.forEach(flow => {
                    const flowDiv = document.createElement('div');
                    flowDiv.className = `flow-item ${flow.classification}`;
                    flowDiv.innerHTML = `
                        <div><strong>${flow.source_ip}</strong> → <strong>${flow.target}</strong></div>
                        <div>Classification: ${flow.classification}</div>
                        <div>Packets: ${flow.packets}</div>
                    `;
                    container.appendChild(flowDiv);
                });
                
                // Update topology to show active flows
                this.highlightActiveFlows(data);
            })
            .catch(error => console.error('Error updating flows:', error));
    }
    
    updateTrafficHistory() {
        fetch('/api/traffic_history')
            .then(response => response.json())
            .then(data => {
                if (data.length === 0) return;
                
                const labels = data.map(d => d.timestamp);
                const activeIPs = data.map(d => d.active_ips);
                const suspiciousIPs = data.map(d => d.suspicious_ips);
                const maliciousIPs = data.map(d => d.malicious_ips);
                
                // Update chart data
                this.chart.data.labels = labels.slice(-20); // Last 20 points
                this.chart.data.datasets[0].data = activeIPs.slice(-20);
                this.chart.data.datasets[1].data = suspiciousIPs.slice(-20);
                this.chart.data.datasets[2].data = maliciousIPs.slice(-20);
                
                this.chart.update('none'); // Update without animation for real-time feel
            })
            .catch(error => console.error('Error updating traffic history:', error));
    }
    
    highlightActiveFlows(flows) {
        if (!this.topology) return;
        
        const svg = d3.select('#topology-svg');
        
        // Reset all links
        svg.selectAll('.link')
            .classed('active', false);
        
        // Highlight active flows
        flows.forEach(flow => {
            // Find links that represent this flow
            svg.selectAll('.link')
                .filter(d => {
                    const sourceNode = [...this.topology.switches, ...this.topology.hosts]
                        .find(n => n.id === flow.target);
                    return sourceNode && d.target === flow.target;
                })
                .classed('active', true);
        });
    }
    
    addLog(message) {
        const container = document.getElementById('logs-container');
        const logDiv = document.createElement('div');
        logDiv.className = 'log-entry';
        logDiv.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        
        container.appendChild(logDiv);
        
        // Keep only last 50 log entries
        const entries = container.querySelectorAll('.log-entry');
        if (entries.length > 50) {
            container.removeChild(entries[0]);
        }
        
        // Auto-scroll to bottom
        container.scrollTop = container.scrollHeight;
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new SDNDashboard();
});

// Handle window resize for topology
window.addEventListener('resize', () => {
    if (window.dashboard) {
        setTimeout(() => {
            window.dashboard.setupTopology();
        }, 250);
    }
}); 