document.addEventListener('DOMContentLoaded', function() {
    const controllerStatusElem = document.getElementById('controller-status');
    const switchListElem = document.getElementById('switch-list');
    const macTableElem = document.getElementById('mac-table');
    const controllerLogElem = document.getElementById('controller-log');
    const mlLogElem = document.getElementById('ml-model-log');
    const host8HoneypotLogElem = document.getElementById('host8-honeypot-log');
    const errorMessageElem = document.getElementById('error-message');
    const tooltipElem = document.getElementById('host-tooltip'); // Keep tooltip element for topology
    
    // Add refresh indicator to the page
    const refreshIndicator = document.createElement('div');
    refreshIndicator.id = 'refresh-indicator';
    refreshIndicator.textContent = 'Last updated: Never';
    document.querySelector('.dashboard-container').prepend(refreshIndicator);

    // Add system status banner
    const statusBanner = document.createElement('div');
    statusBanner.id = 'status-banner';
    statusBanner.style.display = 'none';
    document.querySelector('.dashboard-container').prepend(statusBanner);

    // Track controller state
    let controllerShutdown = false;
    let consecutiveErrors = 0;
    const MAX_CONSECUTIVE_ERRORS = 2; // After this many errors, consider the controller down


    function fetchData() {
        // Show refreshing indicator
        refreshIndicator.textContent = 'Refreshing...';
        refreshIndicator.classList.add('refreshing');
        
        // Add cache-busting parameter
        const cacheBuster = new Date().getTime();
        
        fetch(`/data?_=${cacheBuster}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                // Update refresh indicator
                const now = new Date();
                refreshIndicator.textContent = `Last updated: ${now.toLocaleTimeString()}`;
                refreshIndicator.classList.remove('refreshing');
                refreshIndicator.classList.remove('error');
                
                // Clear previous error
                errorMessageElem.textContent = '';
                errorMessageElem.style.display = 'none';
                
                // Reset error counter on successful fetch
                consecutiveErrors = 0;
                
                // Check for shutdown in logs
                let shutdownDetected = false;
                if (data.logs && data.logs.length > 0) {
                    const recentLogs = data.logs.slice(-10); // Check last 10 log entries
                    shutdownDetected = recentLogs.some(log => 
                        log.includes('Keyboard Interrupt') || 
                        log.includes('Closing RYU application') ||
                        log.includes('shutting down') ||
                        log.includes('shutdown')
                    );
                    
                    // If shutdown detected in logs, mark controller as shutdown
                   
                }

                if (data.error) {
                    errorMessageElem.textContent = data.error;
                    errorMessageElem.style.display = 'block';
                    
                    // Show shutdown status if detected
                    
                }

                // Handle when controller explicitly reports its status
                if (data.status) {
                    controllerStatusElem.textContent = data.status;
                    if (data.status === 'Shutdown' || data.status.toLowerCase().includes('down')) {
                        
                    } else if (!controllerShutdown) {
                        // Only reset class if not in shutdown state
                        controllerStatusElem.className = '';
                        statusBanner.style.display = 'none';
                    }
                } else if (!controllerShutdown) {
                    controllerStatusElem.textContent = 'Unknown';
                }

                // Update Switch List
                switchListElem.innerHTML = ''; // Clear existing list
                if (data.switches && data.switches.length > 0) {
                    data.switches.forEach(dpid => {
                        const li = document.createElement('li');
                        li.textContent = `DPID: ${dpid}`;
                        switchListElem.appendChild(li);
                    });
                } else if (controllerShutdown) {
                    switchListElem.innerHTML = '<li class="shutdown-status">No switches available - Controller is down</li>';
                } else {
                    switchListElem.innerHTML = '<li>No switches connected</li>';
                }

                // Update MAC Table
                if (data.mac_table && Object.keys(data.mac_table).length > 0) {
                    macTableElem.textContent = JSON.stringify(data.mac_table, null, 2);
                } else if (controllerShutdown) {
                    macTableElem.textContent = 'MAC table data unavailable - Controller is down';
                    macTableElem.className = 'shutdown-status';
                } else {
                    macTableElem.textContent = '{}';
                    macTableElem.className = '';
                }

                // Update Controller Log
                if (data.logs && data.logs.length > 0) {
                    controllerLogElem.textContent = data.logs.join('\n');
                    controllerLogElem.scrollTop = controllerLogElem.scrollHeight;
                } else if (controllerShutdown) {
                    // Preserve existing logs if controller is down
                    if (!controllerLogElem.textContent) {
                        controllerLogElem.textContent = 'Controller logs unavailable.';
                    }
                }

                // Update ML Model Log
                if (data.ml_logs && data.ml_logs.length > 0) {
                    mlLogElem.textContent = data.ml_logs.join('\n');
                    mlLogElem.scrollTop = mlLogElem.scrollHeight;
                } else if (controllerShutdown) {
                    // Preserve existing logs if controller is down
                    if (!mlLogElem.textContent) {
                        mlLogElem.textContent = 'ML logs unavailable.';
                    }
                }

                // Update Host8 Honeypot Log
                if (host8HoneypotLogElem) {
                    if (data.host8_honeypot_logs && data.host8_honeypot_logs.length > 0) {
                        host8HoneypotLogElem.textContent = data.host8_honeypot_logs.join('\n');
                        host8HoneypotLogElem.scrollTop = host8HoneypotLogElem.scrollHeight;
                    } else if (controllerShutdown) {
                         // Preserve existing logs if controller is down and we have some
                         if (!host8HoneypotLogElem.textContent) {
                             host8HoneypotLogElem.textContent = 'Host8 Honeypot logs unavailable (controller down).';
                         } 
                    } else {
                        // Handle case where logs might be empty even if controller is up
                        host8HoneypotLogElem.textContent = 'No Host8 Honeypot log entries found.';
                    }
                }
            })
            .catch(error => {
                console.error('Error fetching data:', error);
                consecutiveErrors++;
                
                // Update refresh indicator to show error
                refreshIndicator.textContent = `Error updating`;
                refreshIndicator.classList.remove('refreshing');
                refreshIndicator.classList.add('error');
                
                // After multiple consecutive errors, assume controller is down
                if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
                    
                    errorMessageElem.textContent = `Controller appears to be down: ${error.message}`;
                } else {
                    errorMessageElem.textContent = `Failed to fetch data: ${error.message}`;
                }
                errorMessageElem.style.display = 'block';
                
                // Keep existing data on the page to avoid flickering
                // Only update status elements to show error
                if (controllerShutdown) {
                    if (!switchListElem.innerHTML.includes('down')) {
                        switchListElem.innerHTML = '<li class="shutdown-status">No switches available - Controller is down</li>';
                    }
                    
                    if (!macTableElem.textContent.includes('down')) {
                        macTableElem.textContent = 'MAC table data unavailable - Controller is down';
                        macTableElem.className = 'shutdown-status';
                    }
                }

                // Update Host8 Honeypot log display on error
                if (host8HoneypotLogElem) {
                    if (!host8HoneypotLogElem.textContent.includes('*** ERROR')) {
                         // Append error only if not already showing one to avoid repetition
                         host8HoneypotLogElem.textContent += `\n*** Error fetching Host8 logs: ${error.message} ***`;
                         host8HoneypotLogElem.scrollTop = host8HoneypotLogElem.scrollHeight;
                    }
                }
            });
    }

    // Fetch data initially and then every 5 seconds
    fetchData();
    setInterval(fetchData, 5000);
}); 