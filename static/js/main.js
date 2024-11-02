// Define fetchWithAuth function
function fetchWithAuth(url, options = {}) {
    options.credentials = 'include';  // Include cookies in the request
    return fetch(url, options);
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM Content Loaded');
    
    const scanButton = document.getElementById('scan-button');
    if (scanButton) {
        scanButton.addEventListener('click', function() {
            const button = this;
            const originalText = button.innerHTML;
            
            // Show loading state
            button.disabled = true;
            button.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Scanning...';
            
            console.log('Starting network scan...');
            
            fetchWithAuth('/api/scan', { 
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                console.log('Scan response:', data);
                
                if (!data.devices) {
                    throw new Error('Invalid response format');
                }
                
                // Update device list
                const deviceList = document.getElementById('device-list');
                if (!deviceList) {
                    throw new Error('Device list element not found');
                }
                
                if (data.devices.length === 0) {
                    deviceList.innerHTML = '<tr><td colspan="6">No devices found on the network. Please check your network connection.</td></tr>';
                } else {
                    deviceList.innerHTML = '';
                    data.devices.forEach(device => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${device.name || 'Unknown'}</td>
                            <td>${device.ip_address}</td>
                            <td>${device.mac_address}</td>
                            <td>
                                <span class="badge bg-${device.status ? 'success' : 'danger'}">
                                    ${device.status ? 'Online' : 'Offline'}
                                </span>
                            </td>
                            <td>${device.last_seen ? new Date(device.last_seen).toLocaleString() : 'Never'}</td>
                            <td>
                                <button class="btn btn-${device.blocked ? 'success' : 'danger'} btn-sm toggle-device" 
                                        data-device-id="${device.id}">
                                    ${device.blocked ? 'Unblock' : 'Block'}
                                </button>
                            </td>
                        `;
                        deviceList.appendChild(row);
                    });
                }
            })
            .catch(error => {
                console.error('Scan error:', error);
                const deviceList = document.getElementById('device-list');
                if (deviceList) {
                    deviceList.innerHTML = '<tr><td colspan="6">Error scanning for devices. Please try again.</td></tr>';
                }
            })
            .finally(() => {
                // Reset button state
                button.disabled = false;
                button.innerHTML = originalText;
            });
        });
    }

    // Handle device updates via WebSocket
    const socket = io();
    socket.on('devices_update', function(devices) {
        refreshDeviceList(devices);
    });

    // Handle device toggling
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('toggle-device')) {
            const deviceId = e.target.dataset.deviceId;
            e.target.disabled = true;
            
            fetchWithAuth(`/api/devices/${deviceId}/toggle`, { 
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                if (!data.success) {
                    throw new Error('Failed to toggle device');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error toggling device. Please try again.');
            })
            .finally(() => {
                e.target.disabled = false;
            });
        }
    });

    function refreshDeviceList(devices) {
        const deviceList = document.getElementById('device-list');
        if (!deviceList) {
            console.error('Device list element not found');
            return;
        }
        
        if (!devices || devices.length === 0) {
            deviceList.innerHTML = '<tr><td colspan="6">No devices found. Try scanning for new devices.</td></tr>';
        } else {
            deviceList.innerHTML = '';
            devices.forEach(device => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${device.name || 'Unknown'}</td>
                    <td>${device.ip_address}</td>
                    <td>${device.mac_address}</td>
                    <td>
                        <span class="badge bg-${device.status ? 'success' : 'danger'}">
                            ${device.status ? 'Online' : 'Offline'}
                        </span>
                    </td>
                    <td>${device.last_seen ? new Date(device.last_seen).toLocaleString() : 'Never'}</td>
                    <td>
                        <button class="btn btn-${device.blocked ? 'success' : 'danger'} btn-sm toggle-device" 
                                data-device-id="${device.id}">
                            ${device.blocked ? 'Unblock' : 'Block'}
                        </button>
                    </td>
                `;
                deviceList.appendChild(row);
            });
        }
    }
});
